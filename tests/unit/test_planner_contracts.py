from __future__ import annotations

import unittest

from malapp.orchestration.planner import (
    PlanValidationError,
    build_investigation_plan,
    build_rule_plan,
    orchestration_mode,
    planner_enabled,
    skipped_by_plan_result,
    v0_fixed_plan,
    validate_plan,
)


class PlannerContractTest(unittest.TestCase):
    def test_planner_defaults_to_disabled_v0(self) -> None:
        self.assertFalse(planner_enabled())
        self.assertEqual(orchestration_mode(), "v0_fixed")

    def test_v0_plan_enables_all_agents_and_full_tools(self) -> None:
        plan = v0_fixed_plan()
        self.assertEqual(plan.enabled_agents(), [
            "static_analysis",
            "threat_intel",
            "impersonation",
            "business_label",
        ])
        self.assertEqual(plan.tool_names("static_analysis"), ("apk_metadata", "certificate", "sdk_inventory"))

    def test_static_cannot_be_disabled(self) -> None:
        payload = v0_fixed_plan().to_dict()
        payload["agents"]["static_analysis"]["enabled"] = False
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)

    def test_unknown_agent_and_tool_are_rejected(self) -> None:
        payload = v0_fixed_plan().to_dict()
        payload["agents"]["dynamic_sandbox"] = {"enabled": True, "reason_code": "nope"}
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)
        payload = v0_fixed_plan().to_dict()
        payload["tool_allowlist"]["threat_intel"] = ["ioc_lookup", "invented_tool"]
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)

    def test_static_tools_cannot_be_dropped(self) -> None:
        payload = v0_fixed_plan().to_dict()
        payload["tool_allowlist"]["static_analysis"] = ["apk_metadata"]
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)

    def test_invalid_llm_plan_falls_back_to_v0(self) -> None:
        from unittest.mock import patch

        sample = {"investigation_plan": {"plan_version": "9.9", "agents": {}}}
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "llm"}):
            plan, events = build_investigation_plan(sample)
        self.assertTrue(plan.fallback)
        self.assertEqual(plan.source, "v0_fixed")
        self.assertTrue(any(item["phase"] == "planner_fallback" for item in events))
        self.assertEqual(plan.enabled_agents(), [
            "static_analysis",
            "threat_intel",
            "impersonation",
            "business_label",
        ])

    def test_rule_plan_skips_agents_without_signals(self) -> None:
        plan = build_rule_plan({
            "sample_id": "rule-skip",
            "package_name": "com.example.app",
            "signature_status": "valid",
        })
        self.assertTrue(plan.agents["static_analysis"].enabled)
        self.assertFalse(plan.agents["threat_intel"].enabled)
        self.assertFalse(plan.agents["impersonation"].enabled)
        self.assertFalse(plan.agents["business_label"].enabled)

    def test_skipped_by_plan_keeps_envelope_shape(self) -> None:
        result = skipped_by_plan_result("threat_intel", "insufficient_network_signal")
        self.assertEqual(result.failure_type, "skipped_by_plan")
        self.assertEqual(result.status, "skipped")
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.evidence[0].agent, "threat_intel")
        self.assertIn("threat_intelligence", result.artifacts)
        self.assertTrue(result.artifacts["threat_intelligence"])

    def test_rule_plan_enables_threat_for_extract_ioc_fields(self) -> None:
        fields = {
            "callback_url": "https://cb.example.test/beacon",
            "landing_url": "https://land.example.test/app",
            "dynamic_nets": ["203.0.113.8"],
            "top_domain": "evil.example.test",
            "intelligence_records": [{"ioc": "203.0.113.8", "hit": True}],
        }
        for field, value in fields.items():
            plan = build_rule_plan({"sample_id": field, "package_name": "com.example.app", field: value})
            self.assertTrue(plan.agents["threat_intel"].enabled, field)
            self.assertIn("network_ioc", plan.risk_focus)

    def test_rule_plan_enables_impersonation_for_official_assets(self) -> None:
        plan = build_rule_plan(
            {
                "sample_id": "impersonation-assets",
                "package_name": "com.secure.wa11et",
                "icon_hash": "a" * 64,
                "icon_text": "Secure Wallet",
                "official_app_assets": [{"brand": "Secure Wallet", "icon_hash": "a" * 64}],
            }
        )
        self.assertTrue(plan.agents["impersonation"].enabled)
        self.assertIn("impersonation", plan.risk_focus)

    def test_rule_plan_enables_business_for_fast_loan_chain(self) -> None:
        plan = build_rule_plan(
            {
                "sample_id": "business-label-test",
                "app_name": "Fast Loan",
                "package_name": "com.fast.loan.update",
                "permissions": ["READ_SMS", "READ_CONTACTS", "READ_PHONE_STATE"],
                "control_url": "https://c2-loan-risk.example.net/upload",
            }
        )
        self.assertTrue(plan.agents["business_label"].enabled)
        self.assertNotEqual(plan.agents["business_label"].reason_code, "insufficient_business_signal")
        self.assertIn("business_label", plan.risk_focus)

    def test_string_false_enabled_is_rejected(self) -> None:
        payload = v0_fixed_plan().to_dict()
        payload["agents"]["threat_intel"]["enabled"] = "false"
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)

    def test_bool_max_replans_is_rejected(self) -> None:
        payload = v0_fixed_plan().to_dict()
        payload["max_replans"] = True
        with self.assertRaises(PlanValidationError):
            validate_plan(payload)

    def test_invalid_enabled_and_max_replans_fall_back_to_v0(self) -> None:
        from unittest.mock import patch

        string_false = v0_fixed_plan().to_dict()
        string_false["agents"]["threat_intel"]["enabled"] = "false"
        bool_replans = v0_fixed_plan().to_dict()
        bool_replans["max_replans"] = True
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "llm"}):
            for payload in (string_false, bool_replans):
                plan, events = build_investigation_plan({"investigation_plan": payload})
                self.assertTrue(plan.fallback)
                self.assertEqual(plan.source, "v0_fixed")
                self.assertTrue(any(item["phase"] == "planner_fallback" for item in events))
                self.assertEqual(
                    plan.enabled_agents(),
                    ["static_analysis", "threat_intel", "impersonation", "business_label"],
                )


if __name__ == "__main__":
    unittest.main()
