from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from malapp.observability.metrics import observability_metrics, record_run_metrics
from malapp.observability.trace import connect


def _report(
    run_id: str,
    report_id: str,
    *,
    pipeline_status: str,
    agent_status: str,
    failure_type: str = "",
    restart_count: int = 0,
    latency_seconds: float = 1.0,
    evidence_count: int = 2,
) -> dict:
    return {
        "run_id": run_id,
        "report_id": report_id,
        "created_at": f"2026-08-17T00:00:0{run_id[-1]}+00:00",
        "preprocess": {
            "agent_runtime": {
                "run_id": run_id,
                "agents": {
                    "static_analysis": {
                        "status": agent_status,
                        "failure_type": failure_type,
                        "last_latency_ms": latency_seconds * 1000,
                        "confidence": 0.8,
                        "restart_count": restart_count,
                    }
                },
            }
        },
        "evidence_blocks": [
            {
                "agent": "static_analysis",
                "evidence_items": [{"id": index} for index in range(evidence_count)],
            }
        ],
        "debate": {
            "model_calls": [
                {
                    "call_id": f"{run_id}-model-001",
                    "provider_slot": "model_a",
                    "provider": "fixture",
                    "model": "fixture-a",
                    "status": "completed",
                    "latency_ms": 25,
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "retry_count": restart_count,
                }
            ]
        },
        "decision": {"verdict": "malicious", "confidence": 0.75},
        "execution": {
            "run_id": run_id,
            "pipeline": {
                "run_id": run_id,
                "status": pipeline_status,
                "started_at": 100.0,
                "completed_at": 100.0 + latency_seconds,
                "stages": [
                    {
                        "name": "AGENT_EXECUTION",
                        "status": "failed" if pipeline_status == "failed" else pipeline_status,
                        "latency_ms": latency_seconds * 1000,
                    }
                ],
            },
        },
    }


def test_metrics_persist_and_aggregate_long_term_agent_health(tmp_path: Path) -> None:
    db_path = tmp_path / "metrics.db"
    with (
        patch("malapp.observability.trace.DATA_DIR", tmp_path),
        patch("malapp.observability.trace.DB_PATH", db_path),
    ):
        first = _report(
            "run-1",
            "report-1",
            pipeline_status="completed",
            agent_status="completed",
        )
        second = _report(
            "run-2",
            "report-2",
            pipeline_status="failed",
            agent_status="timeout",
            failure_type="timeout",
            restart_count=1,
            latency_seconds=3.0,
            evidence_count=1,
        )
        record_run_metrics(first)
        record_run_metrics(first)  # idempotent per run
        record_run_metrics(second)

        conn = connect()
        try:
            conn.execute(
                """
                INSERT INTO human_reviews
                (review_id, report_id, human_label, is_correct, created_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("review-1", "report-1", "benign", 0, "2026-08-17T01:00:00+00:00", "{}"),
            )
            conn.commit()
        finally:
            conn.close()

        metrics = observability_metrics(limit=100)

    assert metrics["window"]["runs"] == 2
    assert metrics["runs"]["success_rate"] == 0.5
    assert metrics["runs"]["failure_rate"] == 0.5
    assert metrics["runs"]["timeout_rate"] == 0.5
    assert metrics["runs"]["retry_rate"] == 0.5
    assert metrics["runs"]["latency_ms"] == {"p50": 1000.0, "p95": 3000.0}
    assert metrics["runs"]["average_evidence_count"] == 1.5
    assert metrics["runs"]["human_override_rate"] == 1.0
    agent = metrics["agents"]["static_analysis"]
    assert agent["success_rate"] == 0.5
    assert agent["failure_rate"] == 0.5
    assert agent["timeout_rate"] == 0.5
    assert agent["retry_rate"] == 0.5
    assert agent["average_evidence_count"] == 1.5
    assert metrics["models"]["calls"] == 2
    assert metrics["models"]["retry_rate"] == 0.5
    assert metrics["models"]["input_tokens"] == 20
    assert metrics["models"]["output_tokens"] == 10
