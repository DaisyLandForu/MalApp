from __future__ import annotations

import unittest
from unittest.mock import patch

from malapp.agents.base import AgentResult, EvidenceBlock
from malapp.orchestration.degradation import evaluate_degradation, merge_unavailable_evidence
from malapp.orchestration.evidence_gate import evaluate_evidence_gate
from malapp.orchestration.planner import skipped_by_plan_result, v0_fixed_plan


def _completed(name: str, missing: list[str] | None = None) -> AgentResult:
    block = EvidenceBlock(
        agent=name,
        claim=f"{name} completed",
        evidence=["fixture"],
        confidence=0.8,
        missing_fields=list(missing or []),
    )
    return AgentResult(name, "completed", 0.4, [block], 0.8)


def _plan(*focus: str):
    plan = v0_fixed_plan()
    plan.risk_focus = focus
    return plan


class EvidenceGateCalibrationTest(unittest.TestCase):
    def test_completed_agents_mark_unobtainable_fields_unavailable(self) -> None:
        plan = _plan("static_baseline", "network_ioc", "impersonation")
        results = [
            _completed("static_analysis"),
            _completed("threat_intel", ["threat_intel_records", "domains", "ips"]),
            _completed(
                "impersonation",
                ["official_pkg", "icon_path/icon_base64/icon_hash/icon_text", "official_app_assets"],
            ),
            _completed("business_label"),
        ]
        with patch.dict("os.environ", {"MALAPP_TOOL_RUNTIME_ENABLED": "0"}, clear=False):
            gate = evaluate_evidence_gate(
                plan,
                results,
                sample={"control_url": "https://c2.example.test", "fake_app": True},
                executed_tools={"threat_intel": [], "impersonation": []},
            )
        self.assertTrue(gate.sufficient)
        self.assertEqual(gate.reason_codes, [])
        self.assertEqual(gate.suggested_agents, [])
        self.assertEqual(gate.suggested_tools, [])
        self.assertIn("network_ioc_fields_unavailable", gate.unavailable_reason_codes)
        self.assertIn("impersonation_fields_unavailable", gate.unavailable_reason_codes)
        self.assertTrue(gate.unavailable_fields)

    def test_skipped_required_agent_is_still_remediable(self) -> None:
        plan = _plan("static_baseline", "network_ioc")
        results = [
            _completed("static_analysis"),
            skipped_by_plan_result("threat_intel", "insufficient_network_signal"),
            skipped_by_plan_result("impersonation", "insufficient_impersonation_signal"),
            _completed("business_label"),
        ]
        gate = evaluate_evidence_gate(
            plan,
            results,
            sample={"control_url": "https://c2.example.test"},
        )
        self.assertFalse(gate.sufficient)
        self.assertEqual(gate.reason_codes, ["network_ioc_agent_skipped"])
        self.assertEqual(gate.suggested_agents, ["threat_intel"])
        self.assertFalse(gate.unavailable_fields)

    def test_unused_tools_are_remediable_when_tool_runtime_is_on(self) -> None:
        plan = _plan("static_baseline", "network_ioc", "impersonation")
        results = [
            _completed("static_analysis"),
            _completed("threat_intel", ["threat_intel_records"]),
            _completed("impersonation", ["official_pkg"]),
            _completed("business_label"),
        ]
        with patch.dict("os.environ", {"MALAPP_TOOL_RUNTIME_ENABLED": "1"}, clear=False):
            gate = evaluate_evidence_gate(
                plan,
                results,
                sample={"control_url": "https://c2.example.test", "fake_app": True},
                executed_tools={"threat_intel": ["network_indicator"], "impersonation": []},
            )
        self.assertFalse(gate.sufficient)
        self.assertIn("network_ioc_tools_pending", gate.reason_codes)
        self.assertIn("impersonation_tools_pending", gate.reason_codes)
        self.assertEqual(
            gate.suggested_tools,
            ["ioc_lookup", "official_asset_match", "package_similarity", "certificate_comparison"],
        )

    def test_already_executed_tools_leave_remaining_fields_unavailable(self) -> None:
        plan = _plan("static_baseline", "network_ioc", "impersonation")
        results = [
            _completed("static_analysis"),
            _completed("threat_intel", ["threat_intel_records"]),
            _completed("impersonation", ["official_app_assets"]),
            _completed("business_label"),
        ]
        with patch.dict("os.environ", {"MALAPP_TOOL_RUNTIME_ENABLED": "1"}, clear=False):
            gate = evaluate_evidence_gate(
                plan,
                results,
                sample={"control_url": "https://c2.example.test", "fake_app": True},
                executed_tools={
                    "threat_intel": ["ioc_lookup", "network_indicator"],
                    "impersonation": ["official_asset_match", "package_similarity", "certificate_comparison"],
                },
            )
        self.assertTrue(gate.sufficient)
        self.assertEqual(gate.suggested_tools, [])
        self.assertEqual(
            gate.unavailable_reason_codes,
            ["network_ioc_fields_unavailable", "impersonation_fields_unavailable"],
        )

    def test_unavailable_fields_lower_confidence_without_forcing_review(self) -> None:
        policy = evaluate_degradation([_completed("static_analysis"), _completed("threat_intel")])
        merged = merge_unavailable_evidence(
            policy,
            {"unavailable_fields": ["threat_intel_records", "official_pkg"]},
        )
        self.assertEqual(merged["status"], "degraded")
        self.assertTrue(merged["review_recommended"])
        self.assertFalse(merged["force_human_review"])
        self.assertGreater(merged["confidence_penalty"], 0)
        self.assertEqual(merged["unavailable_fields"], ["threat_intel_records", "official_pkg"])


if __name__ == "__main__":
    unittest.main()
