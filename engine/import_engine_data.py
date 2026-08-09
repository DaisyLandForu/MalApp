from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Iterable
from xml.etree.ElementTree import fromstring, iterparse
from zipfile import ZipFile

from engine.pipeline import DATA_DIR, DB_PATH, init_db


ENGINE_COLUMNS = {
    "MD5": "md5",
    "pngName": "package_name",
    "appType": "app_type",
    "size": "size",
    "fakeApp": "fake_app",
    "steady": "steady",
    "\u75c5\u6bd2\u540d\u79f0": "virus_name",
    "\u7c7b\u578b": "detect_type",
    "score": "score",
    "\u5371\u5bb3\u7c7b\u578b": "risk_type",
    "platform": "platform",
    "\u75c5\u6bd2\u63cf\u8ff0": "virus_description",
    "controlUrl": "control_url",
    "downloadUrl": "download_url",
    "description": "description",
    "findtime": "find_time",
    "controlMailbox": "control_mailbox",
    "controlPhone": "control_phone",
    "\u5e94\u7528\u540d\u79f0": "app_name",
    "\u5e94\u7528\u7248\u672c\u53f7": "app_version",
    "\u89c4\u5219\u6765\u6e90": "rule_source",
    "\u8fd0\u8425\u5546": "operator",
    "\u53cd\u8bc8\u6807\u7b7e": "anti_fraud_label",
    "\u6837\u672csha1": "sha1",
    "\u6837\u672csha256": "sha256",
    "APP\u7248\u672c\u72b6\u6001\uff1a1\u3001\u6b63\u7248\uff0c2\u3001\u76d7\u7248\uff0c3\u3001\u53cd\u8bc8\u6807\u7b7e\u65e0\u503c": "app_version_status",
    "\u662f\u5426\u6d89\u8bc8\u5e94\u7528\uff1a1\u3001\u662f\uff0c2\u3001\u5426": "fraud_app_flag",
    "\u6d89\u8bc8\u5e94\u7528\u5927\u7c7b": "fraud_category_big",
    "\u6d89\u8bc8\u5e94\u7528\u5c0f\u7c7b": "fraud_category_small",
    "\u6d89\u8bc8\u5e94\u7528\u5bb6\u65cf": "fraud_family",
    "\u662f\u5426\u4eff\u5192": "impersonation_flag",
    "\u6b63\u7248\u5e94\u7528\u7684pkg": "official_pkg",
    "\u6b63\u7248\u5e94\u7528\u540d\u79f0": "official_app_name",
    "\u4eff\u5192\u4e00\u7ea7\u5206\u7c7b": "impersonation_l1",
    "\u4eff\u5192\u4e8c\u7ea7\u5206\u7c7b": "impersonation_l2",
    "\u4eff\u5192\u4e09\u7ea7\u5206\u7c7b": "impersonation_l3",
    "\u8bc1\u4e66\u62e5\u6709\u8005": "cert_owner",
    "\u8bc1\u4e66\u5f00\u53d1\u8005": "cert_developer",
    "\u6765\u6e90\u5730\u533a": "source_region",
    "\u6240\u5c5e\u5e94\u7528\u5546\u5e97": "app_store",
    "\u5f00\u53d1\u8005\u540d\u79f0": "developer_name",
    "\u6837\u672cSDK\u540d\u79f0\u5217\u8868": "sdk_list",
    "\u5b89\u88c5\u5305\u6587\u4ef6\u7c7b\u578b": "package_type",
    "\u8bc1\u4e66\u6307\u7eb9MD5": "cert_md5",
    "\u5e94\u7528\u7b7e\u540d\u8bc1\u4e66sha1": "cert_sha1",
    "\u5e94\u7528\u7b7e\u540d\u8bc1\u4e66sha256": "cert_sha256",
    "\u9ed1\u5ba2\u7ec4\u7ec7\u540d\u79f0": "hacker_group",
    "\u6076\u610f\u6837\u672cSM3\u503c": "sm3",
}


TABLE_COLUMNS = [
    "engine",
    "md5",
    "sha1",
    "sha256",
    "package_name",
    "app_name",
    "app_type",
    "size",
    "fake_app",
    "steady",
    "virus_name",
    "detect_type",
    "score",
    "risk_type",
    "platform",
    "virus_description",
    "description",
    "control_url",
    "download_url",
    "control_mailbox",
    "control_phone",
    "app_version",
    "rule_source",
    "operator",
    "anti_fraud_label",
    "app_version_status",
    "fraud_app_flag",
    "fraud_category_big",
    "fraud_category_small",
    "fraud_family",
    "impersonation_flag",
    "official_pkg",
    "official_app_name",
    "impersonation_l1",
    "impersonation_l2",
    "impersonation_l3",
    "cert_owner",
    "cert_developer",
    "source_region",
    "app_store",
    "developer_name",
    "sdk_list",
    "package_type",
    "cert_md5",
    "cert_sha1",
    "cert_sha256",
    "hacker_group",
    "sm3",
    "find_time",
    "raw_json",
]


def init_engine_tables() -> None:
    """Create the SQLite table that stores imported 360/cm rows."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        columns_sql = ", ".join(f"{col} TEXT" for col in TABLE_COLUMNS)
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS engine_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                {columns_sql},
                UNIQUE(engine, md5)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_engine_md5 ON engine_detections(md5)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_engine_score ON engine_detections(engine, score)")


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
    values = []
    for item in root:
        values.append("".join(node.text or "" for node in item.iter() if node.tag.rsplit("}", 1)[-1] == "t"))
    return values


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


def iter_xlsx_rows(path: Path) -> Iterable[list[str]]:
    """Stream rows from xlsx without loading the full workbook into memory.

    `cm.xlsx` stores most text values as inlineStr. openpyxl's normal read mode
    did not expose those values reliably in this environment, so this parser
    reads the worksheet XML directly and handles inline strings explicitly.
    """
    with ZipFile(path) as zip_file:
        shared_strings = read_shared_strings(zip_file)
        with zip_file.open("xl/worksheets/sheet1.xml") as worksheet:
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


def to_record(engine: str, headers: list[str], row: list[str]) -> dict[str, str]:
    """Map one original spreadsheet row into the internal engine schema."""
    raw = {headers[index]: row[index] if index < len(row) else "" for index in range(len(headers))}
    normalized = {ENGINE_COLUMNS[key]: value for key, value in raw.items() if key in ENGINE_COLUMNS}
    record = {col: "" for col in TABLE_COLUMNS}
    record.update(normalized)
    record["engine"] = engine
    record["md5"] = record["md5"].upper().strip()
    record["raw_json"] = json.dumps(raw, ensure_ascii=False)
    return record


def import_xlsx(engine: str, path: Path, *, limit: int | None = None) -> dict[str, int]:
    """Import one engine spreadsheet into SQLite.

    Existing rows are updated by `(engine, md5)`, so re-running the import is
    safe and refreshes the data.
    """
    init_engine_tables()
    rows = iter_xlsx_rows(path)
    headers = next(rows)
    imported = 0
    skipped = 0
    placeholders = ", ".join("?" for _ in TABLE_COLUMNS)
    columns = ", ".join(TABLE_COLUMNS)
    update_sql = ", ".join(f"{col}=excluded.{col}" for col in TABLE_COLUMNS if col not in {"engine", "md5"})
    sql = f"""
        INSERT INTO engine_detections ({columns})
        VALUES ({placeholders})
        ON CONFLICT(engine, md5) DO UPDATE SET {update_sql}
    """
    with sqlite3.connect(DB_PATH) as conn:
        batch = []
        for row in rows:
            record = to_record(engine, headers, row)
            if not record["md5"]:
                skipped += 1
                continue
            batch.append([record[col] for col in TABLE_COLUMNS])
            imported += 1
            if len(batch) >= 1000:
                conn.executemany(sql, batch)
                batch.clear()
            if limit and imported >= limit:
                break
        if batch:
            conn.executemany(sql, batch)
    return {"imported": imported, "skipped": skipped}


def find_default_file(name: str) -> Path:
    root = Path(__file__).resolve().parents[2]
    matches = [path for path in root.rglob(name) if not path.name.startswith("~$")]
    if not matches:
        raise FileNotFoundError(name)
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--engine", choices=["360", "cm", "all"], default="all")
    args = parser.parse_args()

    jobs = []
    if args.engine in {"360", "all"}:
        jobs.append(("360", find_default_file("360.xlsx")))
    if args.engine in {"cm", "all"}:
        jobs.append(("cm", find_default_file("cm.xlsx")))

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for engine, path in jobs:
        result = import_xlsx(engine, path, limit=args.limit)
        print(json.dumps({"engine": engine, "path": str(path), **result}, ensure_ascii=False))


if __name__ == "__main__":
    main()
