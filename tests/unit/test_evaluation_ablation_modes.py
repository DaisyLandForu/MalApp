from __future__ import annotations

from malapp.agents.base import EvidenceBlock
from malapp.orchestration.debate import run_debate


def evidence_blocks() -> list[EvidenceBlock]:
    return [
        EvidenceBlock(
            agent=name,
            claim=f"{name} evidence",
            evidence=[f"{name} concrete evidence"],
            confidence=0.8,
            score=score,
            rule_score=score,
            evidence_items=[
                {
                    "evidence_type": "fixture",
                    "source_fields": [name],
                    "source_values": [str(score)],
                    "direction": "supports_malicious" if score >= 0.5 else "supports_benign",
                    "strength": score,
                    "description": "deterministic evaluation fixture",
                }
            ],
        )
        for name, score in (
            ("static_analysis", 0.8),
            ("threat_intel", 0.9),
            ("impersonation", 0.7),
            ("business_label", 0.6),
        )
    ]


def test_no_debate_ablation_invokes_no_models():
    result = run_debate(
        evidence_blocks(),
        {"sample_id": "no-debate", "run_id": "run-no-debate", "evaluation_mode": "no_debate"},
    )

    assert result["execution_mode"] == "evaluation_no_debate"
    assert result["debate_conformance"] == "evaluation-no-debate"
    assert result["model_calls"] == []
    assert result["metrics"]["token_usage"]["total_tokens"] == 0
    assert result["arbiter"]["verdict"] in {"malicious", "suspicious", "benign"}


def test_single_model_ablation_invokes_only_model_a():
    result = run_debate(
        evidence_blocks(),
        {
            "sample_id": "single-model",
            "run_id": "run-single-model",
            "evaluation_mode": "single_model",
            "model_a": {"backend": "rule", "model": "fixture-a"},
            "model_b": {"backend": "rule", "model": "fixture-b"},
        },
    )

    assert result["execution_mode"] == "evaluation_single_model"
    assert result["debate_conformance"] == "evaluation-single-model"
    assert result["providers"]["model_b"]["backend"] == "not_invoked"
    assert {item["provider_slot"] for item in result["model_calls"]} == {"model_a"}
    assert result["model_b"]["status"] == "skipped"
