from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote
from urllib.request import Request, urlopen
from xml.etree.ElementTree import fromstring, iterparse
from zipfile import ZipFile

from engine.pipeline import DB_PATH, init_db


DEFAULT_FIELDS = (
    "md5,platfrom,appName,pkgName,fileType,companyInfos,signature,metaStr,"
    "appType,fakeApp,steady,permissions,plugins,ltUrls,appTypeFromStatic,"
    "fraudTypeInfo,fraudName,unifyCheckPart"
)

BASIC_INFO_URL = "http://10.0.16.31:20091/apkinfo/type/{md5}?fieldsParam={fields}"
URL_INFO_URL = "http://10.0.16.31:30086/apkInfoUrl/findUrl?md5={md5}"


def init_app_tables() -> None:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_md5_labels (
                md5 TEXT PRIMARY KEY,
                source_sheet TEXT NOT NULL,
                label TEXT NOT NULL,
                app_name TEXT,
                fraud_type TEXT,
                fraud_subtype TEXT,
                raw_json TEXT NOT NULL,
                imported_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_app_md5_label ON app_md5_labels(label)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_md5_api_cache (
                md5 TEXT PRIMARY KEY,
                basic_info_json TEXT,
                url_info_json TEXT,
                status TEXT NOT NULL,
                error TEXT,
                fetched_at TEXT NOT NULL
            )
            """
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


def sheet_names(path: Path) -> list[str]:
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with ZipFile(path) as zip_file:
        root = fromstring(zip_file.read("xl/workbook.xml"))
    sheets = root.find(ns + "sheets")
    if sheets is None:
        return []
    return [sheet.attrib.get("name", "") for sheet in sheets]


def row_to_dict(headers: list[str], row: list[str]) -> dict[str, str]:
    return {headers[index]: row[index] if index < len(row) else "" for index in range(len(headers))}


def import_sheet(path: Path, sheet_xml: str, source_sheet: str, label: str, limit: int | None = None) -> int:
    rows = iter_xlsx_rows(path, sheet_xml)
    headers = next(rows)
    imported = 0
    now = utc_now()
    sql = """
        INSERT INTO app_md5_labels
        (md5, source_sheet, label, app_name, fraud_type, fraud_subtype, raw_json, imported_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(md5) DO UPDATE SET
            source_sheet=excluded.source_sheet,
            label=excluded.label,
            app_name=excluded.app_name,
            fraud_type=excluded.fraud_type,
            fraud_subtype=excluded.fraud_subtype,
            raw_json=excluded.raw_json,
            imported_at=excluded.imported_at
    """
    with sqlite3.connect(DB_PATH) as conn:
        batch = []
        for row in rows:
            raw = row_to_dict(headers, row)
            md5 = str(raw.get("md5", "")).upper().strip()
            if not md5:
                continue
            batch.append(
                (
                    md5,
                    source_sheet,
                    label,
                    raw.get("appName", ""),
                    raw.get("fraudGaType", ""),
                    raw.get("fraudGaSubType", ""),
                    json.dumps(raw, ensure_ascii=False),
                    now,
                )
            )
            imported += 1
            if len(batch) >= 1000:
                conn.executemany(sql, batch)
                batch.clear()
            if limit and imported >= limit:
                break
        if batch:
            conn.executemany(sql, batch)
    return imported


def import_app_md5(path: Path, limit: int | None = None) -> dict[str, Any]:
    init_app_tables()
    names = sheet_names(path)
    jobs = [
        ("xl/worksheets/sheet1.xml", names[0] if len(names) >= 1 else "malicious_fraud", "malicious"),
        ("xl/worksheets/sheet2.xml", names[1] if len(names) >= 2 else "benign", "benign"),
    ]
    result = {}
    for sheet_xml, source_sheet, label in jobs:
        result[source_sheet] = import_sheet(path, sheet_xml, source_sheet, label, limit=limit)
    result["total"] = sum(result.values())
    return result


def fetch_json(url: str, timeout: float) -> Any:
    request = Request(url, headers={"User-Agent": "malapp-mvp/0.1"})
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw_text": body}


def fetch_app_api(md5: str, fields: str = DEFAULT_FIELDS, timeout: float = 8.0) -> dict[str, Any]:
    md5 = md5.upper().strip()
    basic_url = BASIC_INFO_URL.format(md5=quote(md5), fields=quote(fields, safe=","))
    url_info_url = URL_INFO_URL.format(md5=quote(md5))
    return {
        "basic_info": fetch_json(basic_url, timeout),
        "url_info": fetch_json(url_info_url, timeout),
    }


def md5s_for_enrichment(limit: int, label: str | None = None, missing_only: bool = True) -> list[str]:
    conditions = []
    params: list[Any] = []
    if label:
        conditions.append("l.label = ?")
        params.append(label)
    if missing_only:
        conditions.append("c.md5 IS NULL")
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    sql = f"""
        SELECT l.md5
        FROM app_md5_labels l
        LEFT JOIN app_md5_api_cache c ON l.md5 = c.md5
        {where}
        ORDER BY l.md5
        LIMIT ?
    """
    params.append(limit)
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [row[0] for row in rows]


def enrich_md5s(
    md5s: list[str],
    *,
    fields: str = DEFAULT_FIELDS,
    timeout: float = 8.0,
    sleep_seconds: float = 0.05,
) -> dict[str, int]:
    init_app_tables()
    ok = failed = 0
    with sqlite3.connect(DB_PATH) as conn:
        for md5 in md5s:
            try:
                payload = fetch_app_api(md5, fields=fields, timeout=timeout)
                conn.execute(
                    """
                    INSERT INTO app_md5_api_cache
                    (md5, basic_info_json, url_info_json, status, error, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(md5) DO UPDATE SET
                        basic_info_json=excluded.basic_info_json,
                        url_info_json=excluded.url_info_json,
                        status=excluded.status,
                        error=excluded.error,
                        fetched_at=excluded.fetched_at
                    """,
                    (
                        md5,
                        json.dumps(payload["basic_info"], ensure_ascii=False),
                        json.dumps(payload["url_info"], ensure_ascii=False),
                        "ok",
                        "",
                        utc_now(),
                    ),
                )
                ok += 1
            except Exception as exc:
                conn.execute(
                    """
                    INSERT INTO app_md5_api_cache
                    (md5, basic_info_json, url_info_json, status, error, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(md5) DO UPDATE SET
                        status=excluded.status,
                        error=excluded.error,
                        fetched_at=excluded.fetched_at
                    """,
                    (md5, "", "", "failed", str(exc), utc_now()),
                )
                failed += 1
            if sleep_seconds:
                time.sleep(sleep_seconds)
    return {"ok": ok, "failed": failed}


def stats() -> dict[str, Any]:
    init_app_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        by_label = [
            dict(row)
            for row in conn.execute(
                "SELECT label, COUNT(*) AS count FROM app_md5_labels GROUP BY label ORDER BY label"
            ).fetchall()
        ]
        total = conn.execute("SELECT COUNT(*) FROM app_md5_labels").fetchone()[0]
        cache = [
            dict(row)
            for row in conn.execute(
                "SELECT status, COUNT(*) AS count FROM app_md5_api_cache GROUP BY status ORDER BY status"
            ).fetchall()
        ]
        overlap = conn.execute(
            """
            SELECT COUNT(DISTINCT l.md5)
            FROM app_md5_labels l
            JOIN engine_detections e ON l.md5 = e.md5
            """
        ).fetchone()[0]
    return {"total": total, "by_label": by_label, "engine_overlap": overlap, "api_cache": cache}


def find_default_file() -> Path:
    root = Path(__file__).resolve().parents[2]
    matches = [path for path in root.rglob("APP_md5.xlsx") if not path.name.startswith("~$")]
    if not matches:
        raise FileNotFoundError("APP_md5.xlsx")
    return matches[0]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default="")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--import-only", action="store_true")
    parser.add_argument("--enrich", action="store_true")
    parser.add_argument("--enrich-limit", type=int, default=10)
    parser.add_argument("--label", choices=["malicious", "benign"], default=None)
    parser.add_argument("--include-cached", action="store_true")
    parser.add_argument("--fields", default=DEFAULT_FIELDS)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--sleep", type=float, default=0.05)
    args = parser.parse_args()

    path = Path(args.path) if args.path else find_default_file()
    result: dict[str, Any] = {"path": str(path)}
    if args.import_only or not args.enrich:
        result["import"] = import_app_md5(path, limit=args.limit)
    if args.enrich:
        md5s = md5s_for_enrichment(args.enrich_limit, label=args.label, missing_only=not args.include_cached)
        result["enrich"] = enrich_md5s(md5s, fields=args.fields, timeout=args.timeout, sleep_seconds=args.sleep)
    result["stats"] = stats()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
