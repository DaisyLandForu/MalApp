from __future__ import annotations

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
                "sample_id": "runtime-governance-integration",
                "app_name": "Runtime Governance",
                "package_name": "com.malapp.runtime.governance",
                "engine_a_score": 20,
                "engine_b_score": 25,
            }
        )

    snapshot = report["runtime_snapshot"]
    assert report["report_schema_version"] == "agent-runtime-pipeline-v5-artifact-governance"
    assert report["rag_snapshot_id"] == rag_snapshot["snapshot_id"]
    assert report["execution"]["runtime_snapshot_id"] == snapshot["snapshot_id"]
    assert snapshot["rag_snapshot"]["snapshot_id"] == rag_snapshot["snapshot_id"]
    assert snapshot["prompt_version"] == report["debate"]["prompt_version"]
    assert snapshot["decision_params_version"]["sha256"]
    assert snapshot["models"]["model_a"]["provider"] == "rule"

    trace = get_trace(trace_id=report["execution"]["agent_trace_id"])
    assert trace is not None
    assert trace["runtime_snapshot"]["snapshot_id"] == snapshot["snapshot_id"]
