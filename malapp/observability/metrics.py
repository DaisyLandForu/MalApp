"""Durable, low-cardinality operational metrics for judgement runs."""

from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timezone
from typing import Any

from malapp.observability.trace import connect, init_trace_tables


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_metrics_tables() -> None:
    init_trace_tables()
    conn = connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observability_runs (
                run_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                evidence_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                retry_count INTEGER NOT NULL,
                timeout_count INTEGER NOT NULL,
                failure_count INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observability_agent_runs (
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                evidence_count INTEGER NOT NULL,
                confidence REAL NOT NULL,
                retry_count INTEGER NOT NULL,
                timed_out INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                PRIMARY KEY (run_id, agent_name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS observability_model_calls (
                call_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                provider_slot TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                retry_count INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_observability_runs_created ON observability_runs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_observability_agents_name ON observability_agent_runs(agent_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_observability_model_run ON observability_model_calls(run_id)")
        conn.commit()
    finally:
        conn.close()


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _evidence_count(block: dict[str, Any]) -> int:
    items = block.get("evidence_items")
    if isinstance(items, list) and items:
        return len(items)
    evidence = block.get("evidence")
    return len(evidence) if isinstance(evidence, list) else 0


def _run_latency(pipeline: dict[str, Any]) -> float:
    started = _number(pipeline.get("started_at"))
    completed = _number(pipeline.get("completed_at"))
    if started and completed >= started:
        return round((completed - started) * 1000, 3)
    return round(sum(_number(stage.get("latency_ms")) for stage in pipeline.get("stages", [])), 3)


def record_run_metrics(report: dict[str, Any]) -> dict[str, Any]:
    """Persist one idempotent metric row per run, agent, and model call."""
    run_id = str(report.get("run_id") or (report.get("execution") or {}).get("run_id") or "").strip()
    if not run_id:
        raise ValueError("run_id is required to record observability metrics")
    report_id = str(report.get("report_id") or "")
    execution = report.get("execution") or {}
    pipeline = execution.get("pipeline") or {}
    runtime = (report.get("preprocess") or {}).get("agent_runtime") or {}
    agents = runtime.get("agents") if isinstance(runtime.get("agents"), dict) else {}
    evidence_blocks = [item for item in report.get("evidence_blocks", []) if isinstance(item, dict)]
    evidence_by_agent: dict[str, int] = {}
    for block in evidence_blocks:
        agent_name = str(block.get("agent") or "")
        evidence_by_agent[agent_name] = evidence_by_agent.get(agent_name, 0) + _evidence_count(block)
    agent_rows: list[dict[str, Any]] = []
    for name, state in agents.items():
        state = state if isinstance(state, dict) else {}
        status = str(state.get("status") or "unknown")
        failure_type = str(state.get("failure_type") or "")
        agent_rows.append(
            {
                "run_id": run_id,
                "agent_name": str(name),
                "status": status,
                "latency_ms": _number(state.get("last_latency_ms")),
                "evidence_count": int(evidence_by_agent.get(str(name), 0)),
                "confidence": _number(state.get("confidence")),
                "retry_count": max(0, int(_number(state.get("restart_count")))),
                "timed_out": int(status == "timeout" or failure_type == "timeout"),
                "failed": int(status in {"failed", "timeout"}),
            }
        )

    model_calls = [
        item for item in (report.get("debate") or {}).get("model_calls", []) if isinstance(item, dict)
    ]
    model_retry_count = sum(max(0, int(_number(item.get("retry_count")))) for item in model_calls)
    agent_retry_count = sum(item["retry_count"] for item in agent_rows)
    stage_failures = sum(1 for stage in pipeline.get("stages", []) if stage.get("status") == "failed")
    agent_failures = sum(item["failed"] for item in agent_rows)
    timeout_count = sum(item["timed_out"] for item in agent_rows)
    status = str(pipeline.get("status") or "unknown")
    decision = report.get("decision") or {}
    confidence = _number(
        decision.get("confidence"),
        _number(((report.get("debate") or {}).get("arbiter") or {}).get("confidence")),
    )
    run_row = {
        "run_id": run_id,
        "report_id": report_id,
        "created_at": str(report.get("created_at") or now_iso()),
        "status": status,
        "latency_ms": _run_latency(pipeline),
        "evidence_count": sum(_evidence_count(block) for block in evidence_blocks),
        "confidence": confidence,
        "retry_count": agent_retry_count + model_retry_count,
        "timeout_count": timeout_count,
        "failure_count": stage_failures + agent_failures,
    }

    init_metrics_tables()
    conn = connect()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO observability_runs
            (run_id, report_id, created_at, status, latency_ms, evidence_count, confidence,
             retry_count, timeout_count, failure_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(run_row[key] for key in (
                "run_id", "report_id", "created_at", "status", "latency_ms", "evidence_count",
                "confidence", "retry_count", "timeout_count", "failure_count",
            )),
        )
        conn.execute("DELETE FROM observability_agent_runs WHERE run_id = ?", (run_id,))
        for item in agent_rows:
            conn.execute(
                """
                INSERT INTO observability_agent_runs
                (run_id, agent_name, status, latency_ms, evidence_count, confidence,
                 retry_count, timed_out, failed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(item[key] for key in (
                    "run_id", "agent_name", "status", "latency_ms", "evidence_count",
                    "confidence", "retry_count", "timed_out", "failed",
                )),
            )
        conn.execute("DELETE FROM observability_model_calls WHERE run_id = ?", (run_id,))
        for index, item in enumerate(model_calls, start=1):
            conn.execute(
                """
                INSERT INTO observability_model_calls
                (call_id, run_id, provider_slot, provider, model, status, latency_ms,
                 input_tokens, output_tokens, retry_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(item.get("call_id") or f"{run_id}-model-{index:03d}"),
                    run_id,
                    str(item.get("provider_slot") or "unknown"),
                    str(item.get("provider") or "unknown"),
                    str(item.get("model") or "unknown"),
                    str(item.get("status") or "unknown"),
                    _number(item.get("latency_ms")),
                    max(0, int(_number(item.get("input_tokens")))),
                    max(0, int(_number(item.get("output_tokens")))),
                    max(0, int(_number(item.get("retry_count")))),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return {**run_row, "agent_count": len(agent_rows), "model_call_count": len(model_calls)}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(float(ordered[rank]), 3)


def _rate(count: int, total: int) -> float:
    return round(count / total, 4) if total else 0.0


def observability_metrics(limit: int = 1000) -> dict[str, Any]:
    """Aggregate durable run, agent, model, and human-override metrics."""
    init_metrics_tables()
    limit = max(1, min(int(limit), 10_000))
    conn = connect()
    conn.row_factory = sqlite3.Row
    try:
        runs = [dict(row) for row in conn.execute(
            "SELECT * FROM observability_runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()]
        run_ids = [str(item["run_id"]) for item in runs]
        if run_ids:
            placeholders = ",".join("?" for _ in run_ids)
            agents = [dict(row) for row in conn.execute(
                f"SELECT * FROM observability_agent_runs WHERE run_id IN ({placeholders})", run_ids
            ).fetchall()]
            model_calls = [dict(row) for row in conn.execute(
                f"SELECT * FROM observability_model_calls WHERE run_id IN ({placeholders})", run_ids
            ).fetchall()]
        else:
            agents = []
            model_calls = []
        report_ids = sorted({str(item["report_id"]) for item in runs if item["report_id"]})
        if report_ids:
            review_placeholders = ",".join("?" for _ in report_ids)
            latest_reviews = conn.execute(
                f"""
                SELECT hr.is_correct
                FROM human_reviews hr
                JOIN (
                    SELECT report_id, MAX(created_at) AS latest_at
                    FROM human_reviews
                    WHERE is_correct IS NOT NULL AND report_id IN ({review_placeholders})
                    GROUP BY report_id
                ) latest ON latest.report_id = hr.report_id AND latest.latest_at = hr.created_at
                WHERE hr.is_correct IS NOT NULL
                """,
                report_ids,
            ).fetchall()
        else:
            latest_reviews = []
    finally:
        conn.close()

    total = len(runs)
    latencies = [_number(item["latency_ms"]) for item in runs]
    successful = sum(item["status"] in {"completed", "degraded"} and not item["failure_count"] for item in runs)
    failed = sum(item["status"] == "failed" or bool(item["failure_count"]) for item in runs)
    timed_out = sum(bool(item["timeout_count"]) for item in runs)
    retried = sum(bool(item["retry_count"]) for item in runs)
    reviewed = len(latest_reviews)
    overrides = sum(int(row[0]) == 0 for row in latest_reviews)

    per_agent: dict[str, dict[str, Any]] = {}
    for name in sorted({str(item["agent_name"]) for item in agents}):
        rows = [item for item in agents if item["agent_name"] == name]
        count = len(rows)
        agent_latencies = [_number(item["latency_ms"]) for item in rows]
        per_agent[name] = {
            "runs": count,
            "success_rate": _rate(sum(item["status"] == "completed" for item in rows), count),
            "failure_rate": _rate(sum(bool(item["failed"]) for item in rows), count),
            "timeout_rate": _rate(sum(bool(item["timed_out"]) for item in rows), count),
            "retry_rate": _rate(sum(bool(item["retry_count"]) for item in rows), count),
            "latency_ms": {"p50": _percentile(agent_latencies, 0.50), "p95": _percentile(agent_latencies, 0.95)},
            "average_evidence_count": round(sum(item["evidence_count"] for item in rows) / count, 3),
            "average_confidence": round(sum(_number(item["confidence"]) for item in rows) / count, 4),
        }

    model_latencies = [_number(item["latency_ms"]) for item in model_calls]
    return {
        "generated_at": now_iso(),
        "window": {"limit": limit, "runs": total},
        "runs": {
            "success_rate": _rate(successful, total),
            "failure_rate": _rate(failed, total),
            "timeout_rate": _rate(timed_out, total),
            "retry_rate": _rate(retried, total),
            "latency_ms": {"p50": _percentile(latencies, 0.50), "p95": _percentile(latencies, 0.95)},
            "average_evidence_count": round(sum(item["evidence_count"] for item in runs) / total, 3) if total else 0.0,
            "average_confidence": round(sum(_number(item["confidence"]) for item in runs) / total, 4) if total else 0.0,
            "human_override_rate": _rate(overrides, reviewed),
            "human_reviewed_runs": reviewed,
        },
        "agents": per_agent,
        "models": {
            "calls": len(model_calls),
            "retry_rate": _rate(sum(bool(item["retry_count"]) for item in model_calls), len(model_calls)),
            "latency_ms": {"p50": _percentile(model_latencies, 0.50), "p95": _percentile(model_latencies, 0.95)},
            "input_tokens": sum(item["input_tokens"] for item in model_calls),
            "output_tokens": sum(item["output_tokens"] for item in model_calls),
        },
    }
