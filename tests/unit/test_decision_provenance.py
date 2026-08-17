from __future__ import annotations

import copy

from malapp.observability.provenance import (
    build_decision_provenance,
    reconstruct_decision_path,
)


def _normal_report() -> dict:
    run_id = "run-provenance"
    evidence_ids = ["static_analysis", "threat_intel", "impersonation", "business_label"]
    evidence_blocks = [
        {
            "agent": name,
            "claim": f"{name} claim",
            "score": 0.7,
            "confidence": 0.8,
            "evidence_items": [{"evidence_type": "fixture"}],
        }
        for name in evidence_ids
    ]
    return {
        "run_id": run_id,
        "report_id": "report-provenance",
        "sample": {"sample_id": "sample", "engine_a_score": 70, "engine_b_score": 75},
        "engine_c": {"executed": True, "reason": "AMBIGUOUS", "route": "engine_c"},
        "preprocess": {
            "agent_runtime": {
                "run_id": run_id,
                "status": "healthy",
                "agents": {
                    name: {"status": "completed", "confidence": 0.8}
                    for name in evidence_ids
                },
            }
        },
        "evidence_blocks": evidence_blocks,
        "evidence_layers": {
            "canonical_evidence_envelope": {
                "evidence_snapshot_id": "evidence-fixture",
                "evidence_ids": evidence_ids,
                "evidence_blocks": evidence_blocks,
            },
            "rag_context": {
                "enabled": True,
                "ready": True,
                "rag_snapshot_id": "rag-fixture",
                "items": [{"id": "rag-1"}],
            },
        },
        "debate": {
            "run_id": run_id,
            "execution_mode": "full_debate",
            "debate_conformance": "heterogeneous-development",
            "evidence_snapshot_id": "evidence-fixture",
            "model_a": {"verdict": "malicious", "score": 0.8, "confidence": 0.75},
            "model_b": {"verdict": "suspicious", "score": 0.7, "confidence": 0.7},
            "model_calls": [
                {"call_id": f"{run_id}-model-001", "provider_slot": "model_a", "status": "completed"},
                {"call_id": f"{run_id}-model-002", "provider_slot": "model_b", "status": "completed"},
            ],
            "arbiter": {"verdict": "malicious", "score": 0.78},
            "stages": [{"phase": "initial_testimony"}],
        },
        "decision": {
            "verdict": "malicious",
            "verdict_label": "恶意",
            "risk_level": "high",
            "final_score": 0.8,
            "review_required": False,
            "weights": {"engine_a": 1.0, "engine_b": 1.0, "engine_c": 1.4},
            "engine_scores": {"engine_a": 0.7, "engine_b": 0.75, "engine_c": 0.78},
            "xgb": {"probability": 0.76, "verdict": "suspicious", "artifact_id": "xgb-fixture"},
            "wec": {"policy_id": "dynamic-three-engine-wec"},
        },
        "runtime_snapshot": {"snapshot_id": "runtime-fixture"},
        "execution": {"run_id": run_id, "history_reused": False},
    }


def test_provenance_reconstructs_complete_decision_graph_without_secrets() -> None:
    report = _normal_report()
    report["debate"]["model_a"]["api_key"] = "never-persist"
    provenance = build_decision_provenance(report)
    path = reconstruct_decision_path(provenance)
    by_id = {node["node_id"]: node for node in path}

    assert provenance["run_id"] == "run-provenance"
    assert provenance["runtime_snapshot_id"] == "runtime-fixture"
    assert provenance["evidence_snapshot_id"] == "evidence-fixture"
    assert path[-1]["node_id"] == provenance["final_node_id"] == "final_label"
    assert by_id["evidence_envelope"]["status"] == "completed"
    assert by_id["rag_evidence"]["status"] == "completed"
    assert by_id["xgboost_probability"]["summary"]["probability"] == 0.76
    assert by_id["model_a"]["artifact_refs"][0]["type"] == "model_call"
    assert by_id["decision_rule"]["summary"]["policy_id"] == "dynamic-three-engine-wec"
    assert by_id["final_label"]["summary"]["verdict"] == "malicious"
    assert "never-persist" not in str(provenance)
    assert all(node["output_digest"].startswith("sha256:") for node in path)


def test_provenance_marks_engine_c_path_skipped_for_direct_ab_decision() -> None:
    report = _normal_report()
    report["run_id"] = "run-direct-ab"
    report["execution"] = {"run_id": "run-direct-ab", "history_reused": False}
    report["engine_c"] = {"executed": False, "reason": "CLEAR_CONSENSUS", "route": "direct_ab"}
    report["preprocess"]["agent_runtime"] = {"run_id": "run-direct-ab", "status": "skipped", "agents": {}}
    report["evidence_blocks"] = []
    report["evidence_layers"] = {"rag_context": {"enabled": False, "items": []}}
    report["debate"] = {"run_id": "run-direct-ab", "execution_mode": "skipped", "model_calls": []}
    report["decision"]["xgb"] = None
    provenance = build_decision_provenance(report)
    by_id = {node["node_id"]: node for node in provenance["nodes"]}

    assert all(by_id[f"agent_{name}"]["status"] == "skipped" for name in (
        "static_analysis", "threat_intel", "impersonation", "business_label"
    ))
    assert by_id["rag_evidence"]["status"] == "skipped"
    assert by_id["xgboost_probability"]["status"] == "skipped"
    assert by_id["model_a"]["status"] == "skipped"
    assert by_id["model_b"]["status"] == "skipped"
    assert by_id["debate_arbiter"]["status"] == "skipped"
    assert by_id["final_label"]["status"] == "completed"
    assert set(by_id["decision_rule"]["input_refs"]) == {
        "engine_a_input",
        "engine_b_input",
        "admission",
    }
    assert any(edge["relation"] == "direct_ab_decision" for edge in provenance["edges"])


def test_cached_run_rebuilds_provenance_as_reused_artifacts() -> None:
    report = copy.deepcopy(_normal_report())
    report["run_id"] = "run-cache-hit"
    report["execution"] = {
        "run_id": "run-cache-hit",
        "history_reused": True,
        "history_reuse_source": "strict_sample_cache",
        "cached_artifact_run_id": "run-provenance",
    }
    report["preprocess"]["agent_runtime"] = {"run_id": "run-cache-hit", "status": "skipped", "agents": {}}
    report["debate"]["run_id"] = "run-cache-hit"
    report["debate"]["model_calls"] = []
    provenance = build_decision_provenance(report)
    by_id = {node["node_id"]: node for node in provenance["nodes"]}

    assert by_id["cache_lookup"]["summary"]["cached_run_id"] == "run-provenance"
    assert by_id["agent_static_analysis"]["status"] == "reused"
    assert by_id["evidence_envelope"]["status"] == "reused"
    assert by_id["decision_rule"]["status"] == "reused"
    assert by_id["final_label"]["status"] == "reused"
