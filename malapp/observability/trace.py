from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malapp.observability.context import sanitized

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
DB_PATH = DATA_DIR / "mvp.db"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_trace_tables() -> None:
    conn = connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_traces (
                trace_id TEXT PRIMARY KEY,
                run_id TEXT,
                report_id TEXT NOT NULL,
                sample_id TEXT,
                md5 TEXT,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_traces_report ON agent_traces(report_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_traces_md5 ON agent_traces(md5)")
        trace_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(agent_traces)").fetchall()
        }
        if "run_id" not in trace_columns:
            conn.execute("ALTER TABLE agent_traces ADD COLUMN run_id TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_traces_run ON agent_traces(run_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS human_reviews (
                review_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                sample_id TEXT,
                md5 TEXT,
                human_label TEXT NOT NULL,
                is_correct INTEGER,
                notes TEXT,
                reviewer TEXT,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_human_reviews_report ON human_reviews(report_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_human_reviews_md5 ON human_reviews(md5)")
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(human_reviews)").fetchall()
        }
        review_columns = {
            "error_types_json": "TEXT",
            "evidence_supported": "INTEGER",
            "json_valid": "INTEGER",
            "concise": "INTEGER",
            "punctuation_valid": "INTEGER",
            "hallucination": "INTEGER",
            "corrected_output": "TEXT",
            "review_status": "TEXT",
            "second_reviewer": "TEXT",
            "adjudication_notes": "TEXT",
        }
        for column, column_type in review_columns.items():
            if column not in existing_columns:
                conn.execute(
                    f"ALTER TABLE human_reviews ADD COLUMN {column} {column_type}"
                )
        conn.commit()
    finally:
        conn.close()


def _json_loads(value: str | bytes | None) -> Any:
    if not value:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(value)


def get_report(report_id: str) -> dict[str, Any] | None:
    if not report_id:
        return None
    init_trace_tables()
    conn = connect()
    try:
        row = conn.execute("SELECT payload_json FROM judgements WHERE id = ?", (report_id,)).fetchone()
        return _json_loads(row[0]) if row else None
    finally:
        conn.close()


def build_agent_trace(report: dict[str, Any]) -> dict[str, Any]:
    sample = report.get("sample") or {}
    preprocess = report.get("preprocess") or {}
    debate = report.get("debate") or {}
    decision = report.get("decision") or {}
    execution = report.get("execution") or {}
    evidence_layers = report.get("evidence_layers") or {}
    run_id = str(report.get("run_id") or execution.get("run_id") or "")
    trace_id = f"trace-{run_id.removeprefix('run-')}" if run_id else f"trace-{report.get('report_id')}"
    runtime_snapshot = report.get("runtime_snapshot") or {}
    if not runtime_snapshot:
        try:
            from malapp.governance.runtime import save_runtime_snapshot

            runtime_snapshot = save_runtime_snapshot()
        except Exception as exc:
            runtime_snapshot = {"error": str(exc)}
    trace = {
        "trace_id": trace_id,
        "run_id": run_id,
        "report_id": report.get("report_id"),
        "created_at": now_iso(),
        "sample": {
            "sample_id": sample.get("sample_id"),
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
            "sha256": sample.get("sha256"),
            "app_name": sample.get("app_name"),
            "package_name": sample.get("package_name"),
        },
        "input_snapshot": {
            "preprocess": preprocess,
            "raw_evidence": evidence_layers.get("raw_evidence"),
            "rag_context": evidence_layers.get("rag_context"),
        },
        "agent_runtime": preprocess.get("agent_runtime") or {},
        "investigation": (preprocess.get("agent_runtime") or {}).get("investigation") or {},
        "pipeline": execution.get("pipeline") or {},
        "degradation": report.get("degradation") or {},
        "agent_outputs": report.get("evidence_blocks") or [],
        "llm_explanation": evidence_layers.get("llm_explanation"),
        "debate": {
            "run_id": debate.get("run_id"),
            "providers": debate.get("providers"),
            "execution_mode": debate.get("execution_mode"),
            "model_a": debate.get("model_a"),
            "model_b": debate.get("model_b"),
            "cross_examination": debate.get("cross_examination"),
            "stages": debate.get("stages"),
            "arbiter": debate.get("arbiter"),
            "timings": debate.get("timings") or debate.get("metrics"),
            "model_calls": debate.get("model_calls") or [],
        },
        "decision": decision,
        "decision_provenance": report.get("decision_provenance") or {},
        "execution": execution,
        "evaluation_metadata": report.get("evaluation_metadata") or {},
        "runtime_snapshot": runtime_snapshot,
    }
    return sanitized(trace)


def save_agent_trace(report: dict[str, Any]) -> dict[str, Any]:
    init_trace_tables()
    trace = build_agent_trace(report)
    sample = trace.get("sample") or {}
    conn = connect()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO agent_traces
            (trace_id, run_id, report_id, sample_id, md5, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trace["trace_id"],
                trace.get("run_id"),
                trace.get("report_id") or "",
                sample.get("sample_id"),
                sample.get("md5"),
                trace["created_at"],
                json.dumps(trace, ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return trace


def get_trace(report_id: str = "", trace_id: str = "", run_id: str = "") -> dict[str, Any] | None:
    init_trace_tables()
    conn = connect()
    try:
        if trace_id:
            row = conn.execute("SELECT payload_json FROM agent_traces WHERE trace_id = ?", (trace_id,)).fetchone()
        elif run_id:
            row = conn.execute("SELECT payload_json FROM agent_traces WHERE run_id = ?", (run_id,)).fetchone()
        else:
            row = conn.execute(
                "SELECT payload_json FROM agent_traces WHERE report_id = ? ORDER BY created_at DESC LIMIT 1",
                (report_id,),
            ).fetchone()
        return _json_loads(row[0]) if row else None
    finally:
        conn.close()


def list_traces(limit: int = 100) -> list[dict[str, Any]]:
    init_trace_tables()
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT payload_json FROM agent_traces
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 1000)),),
        ).fetchall()
        return [_json_loads(row[0]) for row in rows]
    finally:
        conn.close()


def _infer_correct(report: dict[str, Any] | None, human_label: str, is_correct: Any) -> int | None:
    if is_correct is not None:
        return 1 if bool(is_correct) else 0
    if not report:
        return None
    verdict = ((report.get("decision") or {}).get("verdict") or "").strip()
    if not verdict:
        return None
    return 1 if verdict == human_label else 0


def save_human_review(
    report_id: str,
    human_label: str,
    notes: str = "",
    reviewer: str = "",
    is_correct: Any = None,
    error_types: Any = None,
    evidence_supported: Any = None,
    json_valid: Any = None,
    concise: Any = None,
    punctuation_valid: Any = None,
    hallucination: Any = None,
    corrected_output: str = "",
    review_status: str = "reviewed",
    second_reviewer: str = "",
    adjudication_notes: str = "",
) -> dict[str, Any]:
    if human_label not in {"malicious", "suspicious", "benign"}:
        raise ValueError("human_label must be malicious, suspicious or benign")
    report = get_report(report_id)
    sample = (report or {}).get("sample") or {}
    from malapp.evaluation.framework import normalize_error_types

    normalized_error_types = normalize_error_types(error_types)

    def optional_bool(value: Any) -> bool | None:
        if value is None or value == "":
            return None
        return bool(value)

    if review_status not in {"pending", "reviewed", "adjudicated", "rejected"}:
        raise ValueError("review_status must be pending, reviewed, adjudicated or rejected")
    review = {
        "review_id": f"review-{uuid.uuid4().hex[:16]}",
        "report_id": report_id,
        "sample_id": sample.get("sample_id"),
        "md5": sample.get("md5"),
        "human_label": human_label,
        "is_correct": _infer_correct(report, human_label, is_correct),
        "notes": notes or "",
        "reviewer": reviewer or "",
        "error_types": normalized_error_types,
        "evidence_supported": optional_bool(evidence_supported),
        "json_valid": optional_bool(json_valid),
        "concise": optional_bool(concise),
        "punctuation_valid": optional_bool(punctuation_valid),
        "hallucination": optional_bool(hallucination),
        "corrected_output": corrected_output or "",
        "review_status": review_status,
        "second_reviewer": second_reviewer or "",
        "adjudication_notes": adjudication_notes or "",
        "created_at": now_iso(),
    }
    init_trace_tables()
    conn = connect()
    try:
        conn.execute(
            """
            INSERT INTO human_reviews
            (review_id, report_id, sample_id, md5, human_label, is_correct, notes, reviewer, created_at, payload_json,
             error_types_json, evidence_supported, json_valid, concise, punctuation_valid, hallucination,
             corrected_output, review_status, second_reviewer, adjudication_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review["review_id"],
                review["report_id"],
                review.get("sample_id"),
                review.get("md5"),
                review["human_label"],
                review["is_correct"],
                review["notes"],
                review["reviewer"],
                review["created_at"],
                json.dumps(review, ensure_ascii=False),
                json.dumps(review["error_types"], ensure_ascii=False),
                None if review["evidence_supported"] is None else int(review["evidence_supported"]),
                None if review["json_valid"] is None else int(review["json_valid"]),
                None if review["concise"] is None else int(review["concise"]),
                None if review["punctuation_valid"] is None else int(review["punctuation_valid"]),
                None if review["hallucination"] is None else int(review["hallucination"]),
                review["corrected_output"],
                review["review_status"],
                review["second_reviewer"],
                review["adjudication_notes"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    if report:
        try:
            from malapp.observability.rewards import save_reward_for_report

            review["reward"] = save_reward_for_report(report, review)
        except Exception as exc:  # keep review saving independent from reward scoring
            review["reward_error"] = str(exc)
    return review


def list_human_reviews(limit: int = 200) -> list[dict[str, Any]]:
    init_trace_tables()
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT payload_json FROM human_reviews
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 2000)),),
        ).fetchall()
        return [_json_loads(row[0]) for row in rows]
    finally:
        conn.close()
