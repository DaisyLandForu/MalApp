from __future__ import annotations

import json
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from malapp.application.judgement import DATA_DIR, DB_PATH, init_db
from malapp.data_import.preprocess import (
    create_import_batch,
    finalize_import_batch,
    init_preprocess_tables,
    save_feature_record,
)
from malapp.observability.metrics import observability_metrics

STARTED_AT = time.monotonic()
_CACHE_LOCK = Lock()
_CACHE_VALUE: dict[str, Any] | None = None
_CACHE_TIME = 0.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _count(conn: sqlite3.Connection, table: str) -> int:
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is None:
        return 0
    return int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def _directory_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except OSError:
                pass
    return total


def dashboard_overview(cache_seconds: float = 5.0) -> dict[str, Any]:
    global _CACHE_TIME, _CACHE_VALUE
    now = time.monotonic()
    with _CACHE_LOCK:
        if _CACHE_VALUE is not None and now - _CACHE_TIME < cache_seconds:
            return _CACHE_VALUE

    init_db()
    init_preprocess_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        engine_records = _count(conn, "engine_detections")
        task_rows = _rows(
            conn,
            "SELECT status AS name, COUNT(*) AS count FROM sample_tasks GROUP BY status ORDER BY count DESC",
        )
        task_status_counts = {str(row["name"]): int(row["count"]) for row in task_rows}
        task_total = sum(task_status_counts.values())
        task_status_order = ["pending", "processing", "completed", "failed"]
        task_status = [
            {"name": status, "count": task_status_counts.get(status, 0)}
            for status in task_status_order
        ]
        task_status.extend(
            {"name": status, "count": count}
            for status, count in task_status_counts.items()
            if status not in task_status_order
        )
        judgement_reports = _count(conn, "judgements")
        counts = {
            "engine_records": engine_records,
            "unique_engine_samples": int(
                conn.execute("SELECT COUNT(DISTINCT md5) FROM engine_detections").fetchone()[0]
            ) if engine_records else 0,
            "feature_records": _count(conn, "sample_features"),
            "queued_samples": task_total,
            # This card describes persisted judgement reports, not the
            # transient task queue.  Queue state can be reset while reports
            # are intentionally retained, so using `task_completed` makes
            # the dashboard disagree with the validation/report views.
            "saved_reports": judgement_reports,
            "judgement_reports": judgement_reports,
            "cached_reports": _count(conn, "report_cache"),
            "manual_labels": _count(conn, "manual_labels"),
        }
        verdicts = _rows(
            conn,
            "SELECT verdict AS name, COUNT(*) AS count FROM judgements GROUP BY verdict ORDER BY count DESC",
        )
        risks = _rows(
            conn,
            "SELECT risk_level AS name, COUNT(*) AS count FROM judgements GROUP BY risk_level ORDER BY count DESC",
        )
        sources = _rows(
            conn,
            """
            SELECT source AS name, COUNT(*) AS count
            FROM sample_features
            GROUP BY source
            ORDER BY count DESC
            LIMIT 8
            """,
        )
        trend = _rows(
            conn,
            """
            SELECT substr(created_at, 1, 10) AS day,
                   COUNT(*) AS count,
                   ROUND(AVG(final_score), 4) AS average_score
            FROM judgements
            GROUP BY substr(created_at, 1, 10)
            ORDER BY day DESC
            LIMIT 14
            """,
        )
        trend.reverse()
        recent_rows = conn.execute(
            """
            SELECT id, sample_id, verdict, final_score, risk_level, created_at, payload_json
            FROM judgements
            ORDER BY created_at DESC
            LIMIT 8
            """
        ).fetchall()

    recent_reports = []
    latest_payload: dict[str, Any] = {}
    for index, row in enumerate(recent_rows):
        payload: dict[str, Any] = {}
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            pass
        if index == 0:
            latest_payload = payload
        sample = payload.get("sample", {})
        recent_reports.append(
            {
                "report_id": row["id"],
                "sample_id": row["sample_id"],
                "app_name": sample.get("app_name") or sample.get("package_name") or row["sample_id"],
                "verdict": row["verdict"],
                "final_score": row["final_score"],
                "risk_level": row["risk_level"],
                "created_at": row["created_at"],
            }
        )

    runtime = latest_payload.get("preprocess", {}).get("agent_runtime", {})
    agents = runtime.get("agents", [])
    if isinstance(agents, dict):
        agents = [{"name": name, **details} for name, details in agents.items()]
    if not agents:
        agents = [
            {"name": "static_analysis", "status": "ready"},
            {"name": "threat_intel", "status": "ready"},
            {"name": "impersonation", "status": "ready"},
            {"name": "business_label", "status": "ready"},
        ]
    debate = latest_payload.get("debate", {})
    providers = debate.get("providers", {})
    metrics = debate.get("metrics", {})

    result = {
        "generated_at": utc_now(),
        "uptime_seconds": round(time.monotonic() - STARTED_AT),
        "counts": counts,
        "task_status": task_status,
        "verdicts": verdicts,
        "risks": risks,
        "feature_sources": sources,
        "trend": trend,
        "recent_reports": recent_reports,
        "agents": agents,
        "models": {
            "providers": providers,
            "token_usage": metrics.get("token_usage", {}),
            "latency_ms": metrics.get("latency_ms", {}),
        },
        "observability": observability_metrics(limit=1000),
        "storage": {
            "database_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
            "data_directory_bytes": _directory_size(DATA_DIR),
            "database_path": str(DB_PATH),
        },
    }
    with _CACHE_LOCK:
        _CACHE_VALUE = result
        _CACHE_TIME = now
    return result


def import_feature_records(
    items: list[Any],
    *,
    source: str = "manual_upload",
    payload_format: str = "json",
    batch_id: str = "",
) -> dict[str, Any]:
    if not items:
        raise ValueError("items must contain at least one record")
    batch_id = batch_id or create_import_batch(source)
    imported = 0
    failed = 0
    duplicates = 0
    errors: list[dict[str, Any]] = []
    hashes: Counter[str] = Counter()
    for index, item in enumerate(items):
        try:
            result = save_feature_record(
                item,
                source=source,
                payload_format=payload_format,
                batch_id=batch_id,
            )
            imported += 1
            content_hash = str(result.get("content_hash", ""))
            if content_hash:
                hashes[content_hash] += 1
                if hashes[content_hash] > 1:
                    duplicates += 1
        except Exception as exc:
            failed += 1
            if len(errors) < 20:
                errors.append({"index": index, "error": str(exc)})
    global _CACHE_VALUE
    with _CACHE_LOCK:
        _CACHE_VALUE = None
    batch_count = finalize_import_batch(batch_id)
    return {
        "total": len(items),
        "imported": imported,
        "failed": failed,
        "duplicates_in_batch": duplicates,
        "source": source,
        "batch_id": batch_id,
        "batch_count": batch_count,
        "errors": errors,
    }
