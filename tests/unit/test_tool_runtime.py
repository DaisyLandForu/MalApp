from __future__ import annotations

import unittest

from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.tools.executor import ToolExecutor
from malapp.tools.registry import default_registry
from malapp.tools.threat import assemble_threat_analysis, ioc_lookup, network_indicator, family_correlation


class ToolRuntimeTest(unittest.TestCase):
    def test_full_threat_tools_match_existing_analyzer(self) -> None:
        sample = {
            "sample_id": "tool-eq",
            "package_name": "com.example.app",
            "control_url": "https://c2.malware.test/gate",
            "domains": ["evil.example.test"],
        }
        facts = {
            "network_indicator": network_indicator(sample),
            "ioc_lookup": ioc_lookup(sample),
            "family_correlation": family_correlation(sample),
        }
        assembled = assemble_threat_analysis(facts, sample)
        original = analyze_threat_intelligence(sample)
        self.assertEqual(assembled["indicators"], original["indicators"])
        self.assertEqual(assembled["reputation"], original["reputation"])
        self.assertEqual(assembled["family_attribution"], original["family_attribution"])
        self.assertEqual(assembled["summary"]["missing_fields"], original["summary"]["missing_fields"])

    def test_allowlist_denies_unregistered_or_unauthorized_tool(self) -> None:
        executor = ToolExecutor(default_registry())
        result = executor.execute(
            "threat_intel",
            ["ioc_lookup"],
            {"sample_id": "deny", "control_url": "https://x.test"},
            requested=["ioc_lookup", "invented_tool", "apk_metadata"],
        )
        statuses = {item.tool_name: item.status for item in result.observations}
        self.assertEqual(statuses["ioc_lookup"], "completed")
        self.assertEqual(statuses["invented_tool"], "denied")
        self.assertEqual(statuses["apk_metadata"], "denied")
        self.assertNotIn("invented_tool", result.facts)
        self.assertTrue(result.facts["ioc_lookup"])

    def test_static_tools_emit_facts_not_explanations(self) -> None:
        executor = ToolExecutor(default_registry())
        result = executor.execute(
            "static_analysis",
            ["apk_metadata", "certificate", "sdk_inventory"],
            {
                "package_name": "com.bank.clone",
                "signature_status": "valid",
                "certificate_fingerprint": "abc",
                "sdk_list": ["com.google.firebase"],
            },
        )
        self.assertEqual(len(result.observations), 3)
        self.assertTrue(all(item.status == "completed" for item in result.observations))
        self.assertIn("package_name", result.facts["apk_metadata"])
        self.assertNotIn("claim", result.facts["apk_metadata"])


if __name__ == "__main__":
    unittest.main()
