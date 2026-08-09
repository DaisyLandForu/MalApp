from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
DB_PATH = DATA_DIR / "mvp.db"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, float(value)))


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_reward_tables() -> None:
    conn = connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reward_records (
                reward_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                sample_id TEXT,
                md5 TEXT,
                reward REAL NOT NULL,
                components_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reward_records_report ON reward_records(report_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reward_records_md5 ON reward_records(md5)")
        conn.commit()
    finally:
        conn.close()


def _avg(values: list[float], default: float = 0.0) -> float:
    return float(mean(values)) if values else default


def _report_error_text(report: dict[str, Any]) -> str:
    execution = report.get("execution") or {}
    debate = report.get("debate") or {}
    return " ".join(
        str(x)
        for x in [
            execution.get("error"),
            execution.get("agent_trace_error"),
            execution.get("reward_error"),
            debate.get("error"),
            debate.get("runtime_error"),
        ]
        if x
    ).lower()


def latest_review(report_id: str) -> dict[str, Any] | None:
    conn = connect()
    try:
        row = conn.execute(
            """
            SELECT payload_json FROM human_reviews
            WHERE report_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (report_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


def build_reward(report: dict[str, Any], human_review: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence_blocks = report.get("evidence_blocks") or []
    decision = report.get("decision") or {}
    debate = report.get("debate") or {}
    final_score = clamp(float(decision.get("final_score") or 0.0))
    final_conf = clamp(float(decision.get("confidence") or decision.get("final_confidence") or 0.0))

    evidence_scores = [clamp(float(block.get("score") or 0.0)) for block in evidence_blocks]
    evidence_conf = [clamp(float(block.get("confidence") or 0.0)) for block in evidence_blocks]
    evidence_items = sum(len(block.get("evidence_items") or block.get("evidence") or []) for block in evidence_blocks)
    missing_fields = sum(len(block.get("missing_fields") or []) for block in evidence_blocks)

    schema_completeness = _avg(
        [
            1.0 if report.get("sample") else 0.0,
            1.0 if len(evidence_blocks) >= 4 else len(evidence_blocks) / 4,
            1.0 if debate.get("model_a") else 0.0,
            1.0 if debate.get("model_b") else 0.0,
            1.0 if debate.get("arbiter") else 0.0,
            1.0 if decision else 0.0,
        ]
    )
    evidence_coverage = clamp((evidence_items / 12.0) * 0.7 + _avg(evidence_conf) * 0.3 - min(missing_fields, 20) * 0.015)
    debate_validity = _avg(
        [
            1.0 if debate.get("model_a") else 0.0,
            1.0 if debate.get("model_b") else 0.0,
            1.0 if debate.get("cross_examination") else 0.0,
            1.0 if debate.get("arbiter") else 0.0,
        ]
    )
    error_text = _report_error_text(report)
    model_health = 0.0 if ("failed" in error_text or "timeout" in error_text or "schema" in error_text) else 1.0
    confidence_quality = clamp(0.5 * final_conf + 0.3 * abs(final_score - 0.5) * 2 + 0.2 * _avg(evidence_scores))

    human_alignment = None
    if human_review and human_review.get("is_correct") is not None:
        human_alignment = 1.0 if int(human_review.get("is_correct") or 0) == 1 else -1.0

    if human_alignment is None:
        reward = (
            schema_completeness * 0.25
            + evidence_coverage * 0.25
            + debate_validity * 0.20
            + model_health * 0.15
            + confidence_quality * 0.15
        )
    else:
        reward = (
            (human_alignment + 1.0) / 2.0 * 0.55
            + schema_completeness * 0.12
            + evidence_coverage * 0.13
            + debate_validity * 0.10
            + model_health * 0.05
            + confidence_quality * 0.05
        )

    components = {
        "schema_completeness": round(schema_completeness, 4),
        "evidence_coverage": round(evidence_coverage, 4),
        "debate_validity": round(debate_validity, 4),
        "model_health": round(model_health, 4),
        "confidence_quality": round(confidence_quality, 4),
        "human_alignment": human_alignment,
        "evidence_item_count": evidence_items,
        "missing_field_count": missing_fields,
        "final_score": final_score,
        "final_confidence": final_conf,
        "requires_human_review": bool(
            human_alignment is None
            and (final_conf < 0.55 or 0.35 <= final_score <= 0.65 or model_health < 1.0 or missing_fields >= 8)
        ),
    }
    return {
        "reward_id": f"reward-{uuid.uuid4().hex[:16]}",
        "report_id": report.get("report_id"),
        "sample_id": (report.get("sample") or {}).get("sample_id"),
        "md5": (report.get("sample") or {}).get("md5"),
        "reward": round(clamp(reward), 4),
        "components": components,
        "created_at": now_iso(),
    }


def save_reward_for_report(report: dict[str, Any], human_review: dict[str, Any] | None = None) -> dict[str, Any]:
    init_reward_tables()
    if human_review is None:
        human_review = latest_review(str(report.get("report_id") or ""))
    record = build_reward(report, human_review)
    conn = connect()
    try:
        conn.execute(
            """
            INSERT INTO reward_records
            (reward_id, report_id, sample_id, md5, reward, components_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["reward_id"],
                record.get("report_id") or "",
                record.get("sample_id"),
                record.get("md5"),
                record["reward"],
                json.dumps(record["components"], ensure_ascii=False),
                record["created_at"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return record


def get_reward(report_id: str) -> dict[str, Any] | None:
    init_reward_tables()
    conn = connect()
    try:
        row = conn.execute(
            """
            SELECT reward_id, report_id, sample_id, md5, reward, components_json, created_at
            FROM reward_records
            WHERE report_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (report_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "reward_id": row[0],
            "report_id": row[1],
            "sample_id": row[2],
            "md5": row[3],
            "reward": row[4],
            "components": json.loads(row[5]),
            "created_at": row[6],
        }
    finally:
        conn.close()


def list_rewards(limit: int = 200) -> list[dict[str, Any]]:
    init_reward_tables()
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT reward_id, report_id, sample_id, md5, reward, components_json, created_at
            FROM reward_records
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 2000)),),
        ).fetchall()
        return [
            {
                "reward_id": row[0],
                "report_id": row[1],
                "sample_id": row[2],
                "md5": row[3],
                "reward": row[4],
                "components": json.loads(row[5]),
                "created_at": row[6],
            }
            for row in rows
        ]
    finally:
        conn.close()
