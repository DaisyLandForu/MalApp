from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from malapp.agents.base import AgentContext, EvidenceBlock
from malapp.agents.domain import (
    BusinessLabelAgent,
    ImpersonationAgent,
    StaticAnalysisAgent,
    ThreatIntelAgent,
)
from malapp.agents.evidence_contract import (
    build_evidence_envelope,
    validate_evidence_references,
)
from malapp.application.engine_c_admission import (
    AdmissionReason,
    EngineCAdmissionPolicy,
    EngineInputError,
)
from malapp.application.judgement import judge, normalize_sample
from malapp.inference.expert import EXPERT_ROLES, ExpertModelProvider
from malapp.inference.url_policy import validate_model_pair
from malapp.orchestration.debate import fallback_initial, run_debate
from malapp.orchestration.decision import DEFAULT_PARAMS, collaborative_decision


def admission(sample: dict[str, object]):
    return EngineCAdmissionPolicy(DEFAULT_PARAMS).decide(sample)


def test_engine_c_trigger_on_conflict() -> None:
    result = admission(
        {"engine_a_score": 10, "engine_b_score": 90, "engine_a_label": "benign", "engine_b_label": "malicious"}
    )
    assert result.execute is True
    assert result.reason == AdmissionReason.CONFLICT


def test_engine_c_trigger_on_ambiguous_high_risk() -> None:
    result = admission(
        {"engine_a_score": 72, "engine_b_score": 84, "engine_a_label": "malicious", "engine_b_label": "malicious"}
    )
    assert result.execute is True
    assert result.reason == AdmissionReason.AMBIGUOUS_HIGH_RISK


def test_engine_c_manual_force() -> None:
    result = admission(
        {"engine_a_score": 5, "engine_b_score": 5, "engine_a_label": "benign", "engine_b_label": "benign", "force_engine_c": True}
    )
    assert result.execute is True
    assert result.reason == AdmissionReason.MANUAL_FORCE


def test_low_risk_uncertain_does_not_enter_engine_c() -> None:
    with patch.dict("os.environ", {"MALAPP_PROFILE": "demo", "MALAPP_MD5_REPORT_CACHE": "0"}):
        report = judge({
            "sample_id": "low-risk-uncertain",
            "engine_a_score": 20,
            "engine_b_score": 22,
            "engine_a_label": "benign",
            "engine_b_label": "benign",
            "engine_a_confidence": 0.4,
            "engine_b_confidence": 0.4,
        })
    assert report["engine_c"]["executed"] is False
    assert report["engine_c"]["reason"] == "LOW_RISK_UNCERTAIN"
    assert report["decision"]["review_required"] is True
    assert report["decision"]["review_reasons"] == ["low_risk_uncertain_upstream_consensus"]


def test_engine_c_skip_on_clear_consensus() -> None:
    with patch.dict("os.environ", {"MALAPP_PROFILE": "demo", "MALAPP_MD5_REPORT_CACHE": "0"}):
        report = judge({"sample_id": "clear-consensus", "engine_a_score": 5, "engine_b_score": 6})
    assert report["engine_c"]["executed"] is False
    assert report["engine_c"]["reason"] == "CLEAR_CONSENSUS"
    assert report["engine_c"]["score_c"] is None
    assert {stage["status"] for stage in report["execution"]["pipeline"]["stages"]} == {"skipped"}


@pytest.mark.parametrize(
    "missing",
    [
        "engine_a_score",
        "engine_a_label",
        "engine_a_confidence",
        "engine_b_score",
        "engine_b_label",
        "engine_b_confidence",
    ],
)
def test_production_requires_full_ab_outputs(missing: str) -> None:
    sample = {
        "engine_a_score": 5,
        "engine_a_label": "benign",
        "engine_a_confidence": 0.9,
        "engine_b_score": 5,
        "engine_b_label": "benign",
        "engine_b_confidence": 0.9,
    }
    sample.pop(missing)
    with patch.dict("os.environ", {"MALAPP_PROFILE": "production"}):
        with pytest.raises(EngineInputError) as error:
            judge(sample)
    assert missing in error.value.missing_fields


def test_production_never_synthesizes_ab_score() -> None:
    with patch.dict("os.environ", {"MALAPP_PROFILE": "production"}):
        with pytest.raises(EngineInputError):
            normalize_sample({"sample_id": "no-ab"})
    with patch.dict("os.environ", {"MALAPP_PROFILE": "demo"}):
        sample, _ = normalize_sample({"sample_id": "demo-no-ab"})
    assert sample["ab_input_mode"] == "synthetic"


def evidence_blocks() -> list[EvidenceBlock]:
    return [
        EvidenceBlock(
            agent=name,
            claim=f"{name}-" + "完整原始结论" * 100,
            evidence=[f"{name}-raw-{index}-" + "x" * 500 for index in range(12)],
            confidence=0.7,
            score=0.6,
            evidence_items=[{"source_fields": ["field"], "source_values": ["value" * 100]}],
        )
        for name in ("static_analysis", "threat_intel", "impersonation", "business_label")
    ]


def test_initial_evidence_contract_is_complete_stable_and_shared() -> None:
    blocks = evidence_blocks()
    first = build_evidence_envelope("sample", blocks, created_at="2026-01-01T00:00:00Z")
    second = build_evidence_envelope("sample", list(reversed(blocks)), created_at="2026-01-01T00:00:00Z")
    assert first.sha256 == second.sha256
    assert first.canonical_json() == second.canonical_json()
    assert len(first.to_dict()["evidence_blocks"][0]["evidence"]) == 12
    assert len(first.to_dict()["evidence_blocks"][0]["evidence"][0]) > 500

    seen: list[str] = []

    def capture_initial(_provider, model_name, role, evidence_json, evidence, *_args):
        seen.append(evidence_json)
        return fallback_initial(model_name, role, evidence)

    with (
        patch.dict("os.environ", {"MALAPP_PROFILE": "demo", "MALAPP_DISABLE_LLM_RULE_FALLBACK": "0"}),
        patch("malapp.orchestration.debate.initial_report", side_effect=capture_initial),
    ):
        report = run_debate(
            blocks,
            {"canonical_evidence_envelope": first.to_dict(), "verification_mode": True},
        )
    assert seen[0] == seen[1] == first.canonical_json()
    assert report["initial_evidence"]["model_a_snapshot_id"] == report["initial_evidence"]["model_b_snapshot_id"]
    payload = json.loads(seen[0])
    assert set(first.evidence_ids) <= set(payload["evidence_ids"])


def test_invalid_evidence_reference_rejected() -> None:
    with pytest.raises(ValueError, match="invalid_evidence_reference"):
        validate_evidence_references({"evidence_refs": ["invented"]}, ["static_analysis"])


def test_four_agents_share_provider_and_have_distinct_boundaries() -> None:
    provider = ExpertModelProvider({"model_a": {"backend": "rule"}})
    agents = [
        StaticAnalysisAgent(lambda _: evidence_blocks()[0], provider),
        ThreatIntelAgent(lambda _sample, _iocs: evidence_blocks()[1], provider),
        ImpersonationAgent(lambda _: evidence_blocks()[2], provider),
        BusinessLabelAgent(lambda _: evidence_blocks()[3], provider),
    ]
    assert all(agent._expert_provider is provider for agent in agents)
    assert len({config["role"] for config in EXPERT_ROLES.values()}) == 4
    assert len({tuple(config["tool_scope"]) for config in EXPERT_ROLES.values()}) == 4


def test_expert_runs_inside_agent_and_cannot_create_evidence() -> None:
    provider = ExpertModelProvider({"model_a": {"backend": "rule"}})
    block = EvidenceBlock(
        agent="static_analysis", claim="deterministic", evidence=["certificate mismatch"], confidence=0.8, score=0.8
    )
    agent = StaticAnalysisAgent(lambda _: block, provider)
    with patch.object(provider, "review", wraps=provider.review) as review:
        result = agent.run(AgentContext(sample={"sample_id": "expert"}))
    review.assert_called_once()
    assert result.evidence[0].evidence == ["certificate mismatch"]


def test_missing_features_produce_zero_confidence() -> None:
    provider = ExpertModelProvider({"model_a": {"backend": "rule"}})
    block = EvidenceBlock(
        agent="static_analysis", claim="insufficient", evidence=["missing"], confidence=0.9, score=0.1, missing_fields=["sha256"]
    )
    result = StaticAnalysisAgent(lambda _: block, provider).run(AgentContext(sample={}))
    assert result.confidence == 0.0


def test_production_requires_distinct_debate_models() -> None:
    settings = {
        "server_models_enabled": True,
        "model_a_api_url": "https://models.example/a",
        "model_b_api_url": "https://models.example/b",
        "model_a_model": "same",
        "model_b_model": "same",
    }
    with (
        patch.dict("os.environ", {"MALAPP_MODEL_ALLOWED_HOSTS": "models.example"}),
        pytest.raises(ValueError, match="heterogeneous"),
    ):
        validate_model_pair(settings, profile="production")


def test_production_requires_dual_model_configuration_at_startup() -> None:
    with pytest.raises(ValueError, match="two configured"):
        validate_model_pair({"server_models_enabled": False}, profile="production")


def test_dev_same_model_simulation_is_marked() -> None:
    with patch.dict("os.environ", {"MALAPP_PROFILE": "demo", "MALAPP_DISABLE_LLM_RULE_FALLBACK": "0"}):
        report = run_debate(evidence_blocks(), {"verification_mode": True})
    assert report["debate_conformance"] == "single-model-simulation"


def decision_fixture(xgb_probability: float | None = None) -> dict[str, object]:
    blocks = evidence_blocks()
    debate = {
        "arbiter": {"score": 0.7, "verdict": "malicious", "rationale": "fixture"},
        "model_a": {"confidence": 0.7},
        "model_b": {"confidence": 0.8},
    }
    xgb = None if xgb_probability is None else {"probability": xgb_probability, "verdict": "malicious", "thresholds": {}}
    return collaborative_decision(
        {"engine_a_score": 20, "engine_b_score": 90}, debate, blocks, xgb_result=xgb
    )


def test_final_score_matches_dynamic_abc_wec_formula() -> None:
    result = decision_fixture()
    expected = sum(result["weighted_terms"].values()) / sum(result["weights"].values())
    assert result["final_score"] == pytest.approx(expected, abs=1e-6)
    assert len(set(result["weights"].values())) > 1


def test_xgb_calibrates_score_c_but_cannot_override_wec() -> None:
    result = decision_fixture(0.95)
    assert result["wec"]["score_c_calibrated"] != result["wec"]["score_c_raw"]
    expected = sum(result["weighted_terms"].values()) / sum(result["weights"].values())
    assert result["final_score"] == pytest.approx(expected, abs=1e-6)


def test_component_guardrails_cannot_override_wec_verdict() -> None:
    blocks = [
        EvidenceBlock(
            agent=name,
            claim="high-risk component fixture",
            evidence=["component signal"],
            confidence=0.95,
            score=0.95,
            rule_score=0.95,
        )
        for name in ("static_analysis", "threat_intel", "impersonation", "business_label")
    ]
    result = collaborative_decision(
        {"engine_a_score": 5, "engine_b_score": 5},
        {
            "arbiter": {"score": 0.1, "verdict": "malicious", "rationale": "conflict"},
            "model_a": {"confidence": 0.8},
            "model_b": {"confidence": 0.8},
        },
        blocks,
        runtime_params={
            "initial_weights": {"engine_a": 2.25, "engine_b": 2.25, "engine_c": 0.35},
            "score_c_xgb_calibration_weight": 0.0,
        },
        xgb_result={"probability": 0.95, "verdict": "malicious", "thresholds": {}},
    )
    assert result["final_score"] < result["parameters"]["suspicious_threshold"]
    assert result["verdict"] == "benign"
    assert result["review_required"] is True
    assert result["fusion"]["policy"]["override_applied"] is False
    assert "xgboost_native_malicious" in result["review_reasons"]


def test_runtime_snapshot_contains_business_semantics_and_no_secret() -> None:
    environment = {
        "MALAPP_PROFILE": "demo",
        "MALAPP_DISABLE_LLM_RULE_FALLBACK": "0",
        "MALAPP_USE_XGB": "0",
        "MALAPP_MD5_REPORT_CACHE": "0",
        "MALAPP_MODEL_A_API_KEY": "must-not-leak",
    }
    with patch.dict("os.environ", environment):
        report = judge({"sample_id": "governance-business", "engine_a_score": 10, "engine_b_score": 90})
    snapshot = report["runtime_snapshot"]
    assert snapshot["engine_c_admission"]["policy_id"] == "engine-c-admission"
    assert snapshot["evidence_contract"]["evidence_snapshot_id"]
    assert snapshot["expert_runtime"]["identity"]
    assert snapshot["debate_conformance"]
    assert snapshot["wec_policy"]["policy_id"] == "dynamic-three-engine-wec"
    assert "must-not-leak" not in json.dumps(snapshot)
