from __future__ import annotations

import json
import sqlite3
from typing import Any

from engine.pipeline import DB_PATH


def engine_table_exists(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'engine_detections'"
    ).fetchone() is not None


def engine_stats() -> dict[str, Any]:
    """Return imported 360/cm row counts and MD5 overlap statistics."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if not engine_table_exists(conn):
            return {"by_engine": [], "overlap_md5": 0, "total_md5": 0}
        by_engine = [
            dict(row)
            for row in conn.execute(
                "SELECT engine, COUNT(*) AS count FROM engine_detections GROUP BY engine ORDER BY engine"
            ).fetchall()
        ]
        overlap = conn.execute(
            """
            SELECT COUNT(*) AS count FROM (
                SELECT md5 FROM engine_detections
                GROUP BY md5
                HAVING COUNT(DISTINCT engine) >= 2
            )
            """
        ).fetchone()["count"]
        total_md5 = conn.execute("SELECT COUNT(DISTINCT md5) AS count FROM engine_detections").fetchone()["count"]
    return {"by_engine": by_engine, "overlap_md5": overlap, "total_md5": total_md5}


def get_engine_records(md5: str) -> list[dict[str, Any]]:
    """Fetch all engine rows for one MD5."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if not engine_table_exists(conn):
            return []
        rows = conn.execute(
            "SELECT * FROM engine_detections WHERE md5 = ? ORDER BY engine",
            (md5.upper().strip(),),
        ).fetchall()
    return [dict(row) for row in rows]


def search_engine_records(limit: int = 50, conflict_only: bool = False) -> list[dict[str, Any]]:
    """List imported samples.

    When `conflict_only` is true, only MD5s that appear in two engines are
    returned. These are the most useful samples for Engine C arbitration.
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if not engine_table_exists(conn):
            return []
        if conflict_only:
            rows = conn.execute(
                """
                SELECT md5,
                       GROUP_CONCAT(engine || ':' || score, ', ') AS engine_scores,
                       COUNT(DISTINCT engine) AS engine_count,
                       MAX(COALESCE(app_name, '')) AS app_name,
                       MAX(COALESCE(package_name, '')) AS package_name
                FROM engine_detections
                GROUP BY md5
                HAVING engine_count >= 2
                ORDER BY md5
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT md5,
                       GROUP_CONCAT(engine || ':' || score, ', ') AS engine_scores,
                       COUNT(DISTINCT engine) AS engine_count,
                       MAX(COALESCE(app_name, '')) AS app_name,
                       MAX(COALESCE(package_name, '')) AS package_name
                FROM engine_detections
                GROUP BY md5
                ORDER BY md5
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def score_to_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 50.0


def score_to_engine_label(score: float) -> str:
    if score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "benign"


def yes_like(value: Any) -> bool:
    return str(value).strip() in {"是", "1", "true", "True", "yes", "Y"}


def build_sample_from_engine_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge 360/cm rows into the sample JSON consumed by `judge()`.

    In this MVP:
    - 360 is treated as Engine A.
    - cm is treated as Engine B.
    - Engine C is produced by four agents + model debate + WEC.
    """
    if not records:
        raise ValueError("no engine records found")

    by_engine = {record["engine"]: record for record in records}
    first = records[0]
    record_360 = by_engine.get("360")
    record_cm = by_engine.get("cm")
    score_360 = score_to_number(record_360["score"]) if record_360 else 50.0
    score_cm = score_to_number(record_cm["score"]) if record_cm else 50.0

    merged: dict[str, Any] = {
        "sample_id": first["md5"],
        "md5": first["md5"],
        "sha1": first.get("sha1") or "",
        "sha256": first.get("sha256") or "",
        "engine_a_label": score_to_engine_label(score_360),
        "engine_a_score": score_360,
        "engine_b_label": score_to_engine_label(score_cm),
        "engine_b_score": score_cm,
        "app_name": "",
        "package_name": "",
        "app_type": "",
        "platform": "",
        "signature_status": "",
        "permissions": [],
        "control_url": "",
        "download_url": "",
        "control_mailbox": "",
        "control_phone": "",
        "fake_app": False,
        "brand_similarity": "",
        "virus_name": "",
        "fraud_family": "",
        "packer": False,
        "sdk_list": "",
        "engine_records": [],
    }

    text_fields = [
        "app_name",
        "package_name",
        "app_type",
        "platform",
        "control_url",
        "download_url",
        "control_mailbox",
        "control_phone",
        "virus_name",
        "fraud_family",
        "sdk_list",
    ]
    for field in text_fields:
        for record in records:
            value = record.get(field)
            if value:
                merged[field] = value
                break

    for record in records:
        if yes_like(record.get("fake_app")) or yes_like(record.get("impersonation_flag")):
            merged["fake_app"] = True
        if record.get("steady") and str(record.get("steady")) not in {"未加固", "未知", ""}:
            merged["packer"] = True
        if record.get("cert_md5") or record.get("cert_sha1") or record.get("cert_sha256"):
            merged["signature_status"] = "normal"
        if record.get("description"):
            merged.setdefault("engine_descriptions", []).append(record["description"])

        merged["engine_records"].append(
            {
                "engine": record["engine"],
                "score": record.get("score"),
                "detect_type": record.get("detect_type"),
                "description": record.get("description"),
                "find_time": record.get("find_time"),
            }
        )

    if merged["sdk_list"]:
        merged["permissions"] = [item.strip() for item in str(merged["sdk_list"]).split(",") if item.strip()][:20]

    return merged


def build_sample_by_md5(md5: str) -> dict[str, Any]:
    return build_sample_from_engine_records(get_engine_records(md5))
