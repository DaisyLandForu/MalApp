from __future__ import annotations

import uuid
from unittest.mock import patch

from malapp.application.judgement import judge
from malapp.observability.trace import get_trace


def test_judgement_and_trace_bind_the_same_runtime_snapshot() -> None:
    rag_snapshot = {
        "snapshot_id": "rag-integration-v1",
        "corpus_version": "corpus-integration-v1",
        "sha256": "c" * 64,
    }
    rag_context = {
        "enabled": True,
        "ready": True,
        "query": "fixture",
        "items": [],
        "rag_snapshot_id": rag_snapshot["snapshot_id"],
        "status": {"snapshot_id": rag_snapshot["snapshot_id"], "snapshot": rag_snapshot},
    }
    environment = {
        "MALAPP_PROFILE": "demo",
        "MALAPP_DISABLE_LLM_RULE_FALLBACK": "0",
        "MALAPP_USE_SERVER_MODELS": "0",
        "MALAPP_USE_LOCAL_QWEN": "0",
        "MALAPP_USE_XGB": "0",
        "MALAPP_MD5_REPORT_CACHE": "0",
    }
    with (
        patch.dict("os.environ", environment),
        patch(
            "malapp.application.judgement.rag_context_for_sample",
            return_value=rag_context,
        ),
        patch("malapp.inference.xgboost.predict", return_value=None),
    ):
        report = judge(
            {
                "sample_id": f"runtime-governance-integration-{uuid.uuid4().hex}",
                "app_name": "Runtime Governance",
                "package_name": "com.malapp.runtime.governance",
                "engine_a_score": 20,
                "engine_b_score": 25,
                "force_engine_c": True,
            }
        )

    snapshot = report["runtime_snapshot"]
    assert report["report_schema_version"] == "agent-runtime-pipeline-v6-observability-trace"
    assert report["rag_snapshot_id"] == rag_snapshot["snapshot_id"]
    assert report["execution"]["runtime_snapshot_id"] == snapshot["snapshot_id"]
    assert snapshot["rag_snapshot"]["snapshot_id"] == rag_snapshot["snapshot_id"]
    assert snapshot["prompt_version"] == report["debate"]["prompt_version"]
    assert snapshot["decision_params_version"]["sha256"]
    assert snapshot["models"]["model_a"]["provider"] == "rule"

    trace = get_trace(trace_id=report["execution"]["agent_trace_id"])
    assert trace is not None
    assert trace["run_id"] == report["run_id"] == report["execution"]["run_id"]
    assert report["preprocess"]["agent_runtime"]["run_id"] == report["run_id"]
    assert report["debate"]["run_id"] == report["run_id"]
    assert report["execution"]["pipeline"]["run_id"] == report["run_id"]
    assert report["debate"]["model_calls"]
    assert all(
        call["run_id"] == report["run_id"]
        and {
            "call_id",
            "provider",
            "model",
            "prompt_version",
            "input_tokens",
            "output_tokens",
            "latency_ms",
            "retry_count",
            "finish_reason",
        }
        <= call.keys()
        for call in report["debate"]["model_calls"]
    )
    assert all(
        stage["input_digest"].startswith("sha256:")
        and stage["output_digest"].startswith("sha256:")
        and "error_type" in stage
        for stage in report["execution"]["pipeline"]["stages"]
    )
    assert trace["runtime_snapshot"]["snapshot_id"] == snapshot["snapshot_id"]
    assert get_trace(run_id=report["run_id"])["trace_id"] == trace["trace_id"]
