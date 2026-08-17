from __future__ import annotations

import json
from pathlib import Path

from malapp.governance.runtime import capture_runtime_snapshot, save_runtime_snapshot


def runtime_components() -> dict:
    return {
        "debate_result": {
            "providers": {
                "model_a": {
                    "backend": "openai_compatible",
                    "model": "model-a-v3",
                    "api_url": "https://user:password@model-a.internal:8443/v1",
                },
                "model_b": {
                    "backend": "local_qwen",
                    "model": "qwen-b-v2",
                    "api_url": "",
                },
            },
            "prompt_version": {
                "prompt_id": "prompt-test",
                "version": "3.0.0",
                "sha256": "a" * 64,
                "created_at": "2026-08-17T00:00:00+00:00",
            },
        },
        "xgb_result": {
            "artifact": {
                "artifact_id": "xgb-test-v1",
                "artifact_type": "xgboost",
                "version": "1.0.0",
                "sha256": "b" * 64,
            }
        },
        "rag_context": {
            "rag_snapshot_id": "rag-test-v1",
            "status": {
                "snapshot": {
                    "snapshot_id": "rag-test-v1",
                    "corpus_version": "corpus-v1",
                    "sha256": "c" * 64,
                }
            },
        },
        "decision_params": {
            "suspicious_threshold": 0.6,
            "malicious_threshold": 0.85,
        },
    }


def test_runtime_snapshot_binds_actual_components_without_secrets() -> None:
    components = runtime_components()
    first = capture_runtime_snapshot(**components)
    second = capture_runtime_snapshot(**components)

    assert first["snapshot_id"] == second["snapshot_id"]
    assert first["code_commit"]
    assert len(first["code_sha256"]) == 64
    assert first["models"]["model_a"]["model_id"] == "model-a-v3"
    assert first["models"]["model_a"]["endpoint"] == "https://model-a.internal:8443"
    assert first["xgb_artifacts"][0]["artifact_id"] == "xgb-test-v1"
    assert first["rag_snapshot"]["snapshot_id"] == "rag-test-v1"
    assert first["prompt_version"]["prompt_id"] == "prompt-test"
    assert first["decision_params_version"]["params_id"].startswith("decision-")
    assert set(first["agent_versions"]) == {
        "static_analysis",
        "threat_intel",
        "impersonation",
        "business_label",
    }
    serialized = json.dumps(first)
    assert "password" not in serialized
    assert "api_key" not in serialized


def test_runtime_snapshot_is_persisted_once_by_stable_identity(tmp_path: Path) -> None:
    components = runtime_components()
    first = save_runtime_snapshot(data_dir=tmp_path, **components)
    second = save_runtime_snapshot(data_dir=tmp_path, **components)

    assert first["snapshot_id"] == second["snapshot_id"]
    assert first["captured_at"] == second["captured_at"]
    assert first["path"] == second["path"]
    assert Path(first["path"]).is_file()
    persisted = json.loads(Path(first["path"]).read_text(encoding="utf-8"))
    assert persisted["snapshot_id"] == first["snapshot_id"]
