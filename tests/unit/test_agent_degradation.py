from __future__ import annotations

import unittest

from malapp.orchestration.degradation import (
    LOW_CONFIDENCE_THRESHOLD,
    apply_degradation_policy,
    evaluate_degradation,
    merge_unavailable_evidence,
)
from malapp.orchestration.runtime import degraded_result


class AgentDegradationTest(unittest.TestCase):
    def test_static_failure_forces_review_and_caps_benign_decision(self) -> None:
        policy = evaluate_degradation(
            [degraded_result("static_analysis", "timeout", "timeout", "timeout")]
        )
        decision = {
            "verdict": "benign",
            "verdict_label": "良性",
            "risk_level": "low",
            "risk_level_label": "低风险",
            "review_required": False,
            "review_reasons": [],
            "fusion": {"llm_confidence": 0.8, "evidence_confidence": 0.7},
            "decision_trace": [
                {"step": "final_decision", "data": {"score": 0.2, "verdict": "benign"}}
            ],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertEqual(result["verdict"], "suspicious")
        self.assertTrue(result["review_required"])
        self.assertEqual(result["confidence"], 0.5)
        self.assertIn("static_analysis_timeout", result["review_reasons"])
        self.assertEqual(result["decision_trace"][-1]["data"]["verdict"], "suspicious")
        self.assertEqual(result["decision_trace"][-1]["data"]["pre_degradation_verdict"], "benign")

    def test_threat_timeout_continues_with_confidence_penalty(self) -> None:
        policy = evaluate_degradation(
            [degraded_result("threat_intel", "timeout", "timeout", "timeout")]
        )
        self.assertFalse(policy["force_human_review"])
        self.assertEqual(policy["confidence_penalty"], 0.12)

    def test_skipped_by_plan_does_not_penalize_confidence(self) -> None:
        from malapp.agents.base import AgentResult, EvidenceBlock
        from malapp.orchestration.planner import skipped_by_plan_result

        completed = AgentResult(
            "static_analysis",
            "completed",
            0.4,
            [EvidenceBlock("static_analysis", "ok", ["e"], 0.8, score=0.4)],
            0.8,
        )
        policy = evaluate_degradation(
            [completed, skipped_by_plan_result("threat_intel", "insufficient_network_signal")]
        )
        self.assertEqual(policy["status"], "healthy")
        self.assertEqual(policy["confidence_penalty"], 0.0)
        self.assertFalse(policy["force_human_review"])

    def test_unavailable_without_uncertainty_is_audited_not_recommended(self) -> None:
        policy = merge_unavailable_evidence(
            evaluate_degradation([]),
            {"unavailable_fields": ["threat_intel_records", "official_pkg"]},
        )
        decision = {
            "verdict": "malicious",
            "final_score": 0.96,
            "fusion": {"llm_confidence": 0.9, "evidence_confidence": 0.88},
            "parameters": {"suspicious_threshold": 0.6, "malicious_threshold": 0.85},
            "engine_scores": {"engine_a": 0.92, "engine_b": 0.91, "engine_c": 0.94},
            "consensus": {"engine_score_spread": 0.03},
            "review_reasons": [],
            "decision_trace": [{"step": "final_decision", "data": {}}],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertEqual(policy["unavailable_fields"], ["threat_intel_records", "official_pkg"])
        self.assertFalse(result["review_recommended"])
        self.assertGreater(result["confidence"], 0)
        self.assertLess(result["confidence"], 0.9)

    def test_unavailable_near_boundary_recommends_review(self) -> None:
        policy = merge_unavailable_evidence(
            evaluate_degradation([]),
            {"unavailable_fields": ["official_pkg"]},
        )
        decision = {
            "verdict": "suspicious",
            "final_score": 0.62,
            "fusion": {"llm_confidence": 0.7, "evidence_confidence": 0.68},
            "parameters": {"suspicious_threshold": 0.6, "malicious_threshold": 0.85},
            "engine_scores": {"engine_a": 0.61, "engine_b": 0.63, "engine_c": 0.62},
            "consensus": {"engine_score_spread": 0.02},
            "review_reasons": [],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertTrue(result["review_recommended"])
        self.assertIn("near_decision_boundary", result["review_recommend_reasons"])

    def test_unavailable_with_engine_conflict_recommends_review(self) -> None:
        policy = merge_unavailable_evidence(
            evaluate_degradation([]),
            {"unavailable_fields": ["domains"]},
        )
        decision = {
            "verdict": "benign",
            "final_score": 0.2,
            "fusion": {"llm_confidence": 0.8, "evidence_confidence": 0.75},
            "parameters": {"suspicious_threshold": 0.6, "malicious_threshold": 0.85},
            "engine_scores": {"engine_a": 0.1, "engine_b": 0.8, "engine_c": 0.2},
            "consensus": {"engine_score_spread": 0.7},
            "review_reasons": ["component_disagreement"],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertTrue(result["review_recommended"])
        self.assertIn("engine_conflict", result["review_recommend_reasons"])

    def test_clear_benign_unavailable_is_not_recommended(self) -> None:
        policy = merge_unavailable_evidence(
            evaluate_degradation([]),
            {"unavailable_fields": ["threat_intel_records", "official_pkg"]},
        )
        decision = {
            "verdict": "benign",
            "final_score": 0.32,
            "fusion": {"llm_confidence": 0.0, "evidence_confidence": 0.72},
            "parameters": {"suspicious_threshold": 0.6, "malicious_threshold": 0.85},
            "engine_scores": {"engine_a": 0.28, "engine_b": 0.31, "engine_c": 0.33},
            "consensus": {"engine_score_spread": 0.05},
            "review_reasons": [],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertFalse(result["review_recommended"])
        self.assertTrue(result["degradation"]["unavailable_fields"])

    def test_rule_backend_zero_llm_confidence_does_not_force_review(self) -> None:
        policy = merge_unavailable_evidence(
            evaluate_degradation([]),
            {"unavailable_fields": ["threat_intel_records"]},
        )
        decision = {
            "verdict": "malicious",
            "final_score": 0.96,
            "fusion": {"llm_confidence": 0.0, "evidence_confidence": 0.82},
            "parameters": {"suspicious_threshold": 0.6, "malicious_threshold": 0.85},
            "engine_scores": {"engine_a": 0.9, "engine_b": 0.92, "engine_c": 0.95},
            "consensus": {"engine_score_spread": 0.05},
            "review_reasons": [],
        }
        result = apply_degradation_policy(decision, policy)
        self.assertFalse(result["review_recommended"])
        self.assertGreater(result["confidence"], LOW_CONFIDENCE_THRESHOLD)


if __name__ == "__main__":
    unittest.main()
