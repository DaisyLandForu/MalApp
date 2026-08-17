from __future__ import annotations

import unittest

from malapp.orchestration.degradation import apply_degradation_policy, evaluate_degradation
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


if __name__ == "__main__":
    unittest.main()
