from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Iterable
from xml.etree.ElementTree import fromstring, iterparse
from zipfile import ZipFile

from engine.pipeline import DB_PATH
from engine.preprocess import (
    init_preprocess_tables,
    load_alias_mapping,
    normalize_manual_label,
    register_feature_field,
    save_feature_record,
    utc_now,
)


def col_to_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha())
    index = 0
    for ch in letters:
        index = index * 26 + ord(ch.upper()) - 64
    return index


def read_shared_strings(zip_file: ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zip_file.namelist():
        return []
    root = fromstring(zip_file.read("xl/sharedStrings.xml"))
    return [
        "".join(node.text or "" for node in item.iter() if node.tag.rsplit("}", 1)[-1] == "t")
        for item in root
    ]


def cell_text(cell, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.iter() if node.tag.rsplit("}", 1)[-1] == "t")
    value = ""
    for node in cell:
        if node.tag.rsplit("}", 1)[-1] == "v":
            value = node.text or ""
            break
    if cell_type == "s" and value:
        return shared_strings[int(value)]
    return value


def sheet_names(path: Path) -> list[str]:
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with ZipFile(path) as zip_file:
        root = fromstring(zip_file.read("xl/workbook.xml"))
    sheets = root.find(ns + "sheets")
    if sheets is None:
        return []
    return [sheet.attrib.get("name", "") for sheet in sheets]


def worksheet_paths(path: Path) -> list[str]:
    with ZipFile(path) as zip_file:
        return [
            name
            for name in zip_file.namelist()
            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
        ]


def iter_xlsx_rows(path: Path, sheet_xml: str) -> Iterable[list[str]]:
    with ZipFile(path) as zip_file:
        shared_strings = read_shared_strings(zip_file)
        with zip_file.open(sheet_xml) as worksheet:
            for _, elem in iterparse(worksheet, events=("end",)):
                if elem.tag.rsplit("}", 1)[-1] != "row":
                    continue
                values_by_index: dict[int, str] = {}
                max_index = 0
                for cell in elem:
                    if cell.tag.rsplit("}", 1)[-1] != "c":
                        continue
                    index = col_to_index(cell.attrib.get("r", ""))
                    max_index = max(max_index, index)
                    values_by_index[index] = cell_text(cell, shared_strings)
                if max_index:
                    yield [values_by_index.get(index, "") for index in range(1, max_index + 1)]
                elem.clear()


def row_to_dict(headers: list[str], row: list[str]) -> dict[str, str]:
    result = {}
    for index, header in enumerate(headers):
        if not header:
            continue
        value = row[index] if index < len(row) else ""
        result[header] = value
    return result


def import_app_judgment_workbook(path: Path, limit: int | None = None) -> dict[str, int]:
    """Import Wuhan-interface APP judgement field workbook.

    Sheet 1/2 are source/API facts. Sheet 3 summarizes network IOCs by MD5.
    Sheet 4 contains one row per URL/domain/IP. All feature rows are registered
    and persisted through `save_feature_record`.
    """
    init_preprocess_tables()
    names = sheet_names(path)
    sheets = worksheet_paths(path)
    counts: dict[str, int] = {}
    mapping = load_alias_mapping()
    conn = sqlite3.connect(DB_PATH)
    for sheet_name, sheet_xml in zip(names, sheets):
        if sheet_name in {"错误日志", "字段说明"}:
            continue
        rows = iter_xlsx_rows(path, sheet_xml)
        try:
            headers = next(rows)
        except StopIteration:
            counts[sheet_name] = 0
            continue
        for header in headers:
            if header:
                register_feature_field(header, mapping.get(header, header), f"app_judgment:{sheet_name}")
        count = 0
        for row in rows:
            raw = row_to_dict(headers, row)
            if not raw.get("md5"):
                continue
            raw["feature_sheet"] = sheet_name
            save_feature_record(
                raw,
                source=f"app_judgment:{sheet_name}",
                payload_format="json",
                connection=conn,
                register_fields=False,
                write_bloom=False,
            )
            count += 1
            if count % 1000 == 0:
                conn.commit()
            if limit and count >= limit:
                break
        conn.commit()
        counts[sheet_name] = count
    conn.close()
    return counts


def import_conflict_annotation_workbook(path: Path, limit: int | None = None) -> dict[str, int]:
    """Import conflict/manual-label workbook as high-priority feature records."""
    init_preprocess_tables()
    names = sheet_names(path)
    sheets = worksheet_paths(path)
    counts: dict[str, int] = {}
    mapping = load_alias_mapping()
    conn = sqlite3.connect(DB_PATH)
    for sheet_name, sheet_xml in zip(names, sheets):
        if "统计" in sheet_name:
            continue
        rows = iter_xlsx_rows(path, sheet_xml)
        try:
            headers = next(rows)
        except StopIteration:
            counts[sheet_name] = 0
            continue
        for header in headers:
            if header:
                register_feature_field(header, mapping.get(header, header), f"conflict_annotation:{sheet_name}")
        count = 0
        for row in rows:
            raw = row_to_dict(headers, row)
            md5 = raw.get("MD5") or raw.get("md5")
            if not md5:
                continue
            raw["feature_sheet"] = sheet_name
            raw["conflict_type"] = raw.get("冲突类型", sheet_name)
            save_feature_record(
                raw,
                source=f"conflict_annotation:{sheet_name}",
                payload_format="json",
                connection=conn,
                register_fields=False,
                write_bloom=False,
            )
            if "人工审核结果" in raw:
                conn.execute(
                    """
                    INSERT INTO manual_labels
                    (md5, label, source_file, conflict_type, raw_json, imported_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(md5) DO UPDATE SET
                        label=excluded.label,
                        source_file=excluded.source_file,
                        conflict_type=excluded.conflict_type,
                        raw_json=excluded.raw_json,
                        imported_at=excluded.imported_at
                    """,
                    (
                        str(md5).upper().strip(),
                        normalize_manual_label(raw.get("人工审核结果", "")),
                        path.name,
                        str(raw.get("冲突类型", sheet_name)),
                        json.dumps(raw, ensure_ascii=False),
                        utc_now(),
                    ),
                )
            count += 1
            if count % 1000 == 0:
                conn.commit()
            if limit and count >= limit:
                break
        conn.commit()
        counts[sheet_name] = count
    conn.close()
    return counts


def find_default_files() -> tuple[Path | None, Path | None]:
    root = Path(__file__).resolve().parents[2]
    app_file = None
    conflict_file = None
    for path in root.rglob("*.xlsx"):
        if path.name.startswith("~$"):
            continue
        if "APP研判字段" in path.name:
            app_file = path
        if "冲突样本分析_人工标注_分身规则更新" in path.name:
            conflict_file = path
    return app_file, conflict_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-file", default="")
    parser.add_argument("--conflict-file", default="")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--only", choices=["all", "app", "conflict"], default="all")
    args = parser.parse_args()

    default_app, default_conflict = find_default_files()
    app_file = Path(args.app_file) if args.app_file else default_app
    conflict_file = Path(args.conflict_file) if args.conflict_file else default_conflict
    result: dict[str, object] = {}
    if args.only in {"all", "app"} and app_file:
        result["app_judgment"] = {
            "path": str(app_file),
            "sheets": import_app_judgment_workbook(app_file, limit=args.limit),
        }
    if args.only in {"all", "conflict"} and conflict_file:
        result["conflict_annotation"] = {
            "path": str(conflict_file),
            "sheets": import_conflict_annotation_workbook(conflict_file, limit=args.limit),
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
