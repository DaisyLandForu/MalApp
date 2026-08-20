from __future__ import annotations

import unittest
from unittest.mock import patch

from malapp.agents.business_label import analyze_business_label
from malapp.agents.impersonation import analyze_impersonation
from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.orchestration.planner import REGISTERED_TOOLS
from malapp.tools.base import ToolSpec
from malapp.tools.business import assemble_business_analysis, business_taxonomy, harm_chain, variant_mapping
from malapp.tools.executor import ToolExecutor
from malapp.tools.impersonation import (
    assemble_impersonation_analysis,
    certificate_comparison,
    official_asset_match,
    package_similarity,
)
from malapp.tools.registry import ToolRegistry, default_registry
from malapp.tools.threat import assemble_threat_analysis, family_correlation, ioc_lookup, network_indicator


class _TimeoutTool:
    spec = ToolSpec("ioc_lookup", "threat_intel")

    def run(self, sample, *, iocs=None):
        del sample, iocs
        raise TimeoutError("simulated tool timeout")


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

    def test_full_impersonation_and_business_tools_match_existing_analyzers(self) -> None:
        sample = {
            "sample_id": "tool-eq-domain",
            "app_name": "Fast Loan",
            "package_name": "com.fast.loan.update",
            "permissions": ["READ_SMS", "READ_CONTACTS"],
            "control_url": "https://c2-loan-risk.example.net/upload",
            "icon_hash": "a" * 64,
            "icon_text": "Secure Wallet",
            "developer_signature": "untrusted-signature",
            "official_app_assets": [
                {
                    "brand": "Secure Wallet",
                    "app_name": "Secure Wallet",
                    "package_name": "com.secure.wallet",
                    "icon_hash": "a" * 64,
                    "icon_text": "Secure Wallet",
                    "developer_signature": "official-signature",
                }
            ],
        }
        impersonation_facts = {
            "official_asset_match": official_asset_match(sample),
            "package_similarity": package_similarity(sample),
            "certificate_comparison": certificate_comparison(sample),
        }
        business_facts = {
            "business_taxonomy": business_taxonomy(sample),
            "harm_chain": harm_chain(sample),
            "variant_mapping": variant_mapping(sample),
        }
        impersonation = assemble_impersonation_analysis(impersonation_facts, sample)
        business = assemble_business_analysis(business_facts, sample)
        original_impersonation = analyze_impersonation(sample)
        original_business = analyze_business_label(sample)
        self.assertEqual(impersonation["assessment"], original_impersonation["assessment"])
        self.assertEqual(impersonation["official_asset_match"], original_impersonation["official_asset_match"])
        self.assertEqual(business["summary"]["business_labels"], original_business["summary"]["business_labels"])
        self.assertEqual(business["harm_chain"]["stages"], original_business["harm_chain"]["stages"])

    def test_allowlist_denies_unregistered_or_unauthorized_tool(self) -> None:
        executor = ToolExecutor(default_registry())
        result = executor.execute(
            "threat_intel",
            ["ioc_lookup"],
            {"sample_id": "deny", "control_url": "https://x.test"},
            requested=["ioc_lookup", "invented_tool", "apk_metadata"],
            plan_id="plan-deny",
            run_id="run-deny",
        )
        statuses = {item.tool_name: item.status for item in result.observations}
        self.assertEqual(statuses["ioc_lookup"], "completed")
        self.assertEqual(statuses["invented_tool"], "denied")
        self.assertEqual(statuses["apk_metadata"], "denied")
        self.assertNotIn("invented_tool", result.facts)
        self.assertTrue(result.facts["ioc_lookup"])
        denied = next(item for item in result.observations if item.tool_name == "invented_tool")
        self.assertEqual(denied.phase, "tool_call_denied")
        self.assertEqual(denied.run_id, "run-deny")
        self.assertEqual(denied.plan_id, "plan-deny")
        self.assertEqual(denied.agent, "threat_intel")
        self.assertIn("tool_call_started", {item["phase"] for item in result.events})
        self.assertIn("tool_call_denied", {item["phase"] for item in result.events})

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
        mutated = dict(result.facts["apk_metadata"])
        mutated["claim"] = "llm should not land here"
        self.assertNotIn("claim", result.observations[0].facts)

    def test_tool_timeout_is_classified_and_does_not_raise(self) -> None:
        executor = ToolExecutor(ToolRegistry([_TimeoutTool()]))
        result = executor.execute("threat_intel", ["ioc_lookup"], {"sample_id": "timeout"})
        observation = result.observations[0]
        self.assertEqual(observation.status, "timeout")
        self.assertEqual(observation.error_type, "timeout")
        self.assertEqual(observation.phase, "tool_call_timeout")
        self.assertEqual(result.facts, {})
        self.assertIn("tool_call_timeout", {item["phase"] for item in result.events})

    def test_default_registry_covers_all_registered_tools(self) -> None:
        registry = default_registry()
        for agent, tools in REGISTERED_TOOLS.items():
            self.assertEqual(set(registry.registered_names(agent)), set(tools))

    def test_tool_runtime_path_matches_legacy_evidence_scores(self) -> None:
        from malapp.agents.domain import (
            BusinessLabelAgent,
            ImpersonationAgent,
            StaticAnalysisAgent,
            ThreatIntelAgent,
        )
        from malapp.application.judgement import (
            business_label_agent,
            impersonation_agent,
            static_analysis_agent,
            threat_intel_agent,
        )
        from malapp.orchestration.investigation import run_investigation

        sample = {
            "sample_id": "p8-equivalence-runtime",
            "app_name": "Fast Loan",
            "package_name": "com.fast.loan.update",
            "permissions": ["READ_SMS", "READ_CONTACTS", "READ_PHONE_STATE"],
            "control_url": "https://c2-loan-risk.example.net/upload",
            "download_url": "https://fake-loan.example.net/app.apk",
            "signature_status": "valid",
            "certificate_fingerprint": "abc",
            "sdk_list": ["com.google.firebase"],
            "icon_hash": "a" * 64,
            "icon_text": "Secure Wallet",
            "developer_signature": "untrusted-signature",
            "official_app_assets": [
                {
                    "brand": "Secure Wallet",
                    "app_name": "Secure Wallet",
                    "package_name": "com.secure.wallet",
                    "icon_hash": "a" * 64,
                    "icon_text": "Secure Wallet",
                    "developer_signature": "official-signature",
                }
            ],
        }
        def agents():
            return [
                StaticAnalysisAgent(static_analysis_agent),
                ThreatIntelAgent(threat_intel_agent),
                ImpersonationAgent(impersonation_agent),
                BusinessLabelAgent(business_label_agent),
            ]
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "0", "MALAPP_TOOL_RUNTIME_ENABLED": "0"}):
            _blocks_a, _report_a, legacy = run_investigation(sample, [], run_id="run-p8-legacy", agents=agents())
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "0", "MALAPP_TOOL_RUNTIME_ENABLED": "1"}):
            _blocks_b, tooled_report, tooled = run_investigation(sample, [], run_id="run-p8-tools", agents=agents())
        self.assertEqual(
            {item.agent_name: item.score for item in legacy},
            {item.agent_name: item.score for item in tooled},
        )
        self.assertEqual(
            legacy[1].artifacts["threat_intelligence"]["indicators"],
            tooled[1].artifacts["threat_intelligence"]["indicators"],
        )
        self.assertEqual(
            legacy[2].artifacts["impersonation_analysis"]["assessment"],
            tooled[2].artifacts["impersonation_analysis"]["assessment"],
        )
        self.assertEqual(
            legacy[3].artifacts["business_label_analysis"]["summary"]["business_labels"],
            tooled[3].artifacts["business_label_analysis"]["summary"]["business_labels"],
        )
        observations = tooled_report["investigation"]["tool_observations"]
        self.assertTrue(observations)
        self.assertTrue(all(item.get("run_id") and item.get("agent") for item in observations))
        self.assertTrue(any(item.get("phase") == "tool_call_finished" for item in observations))


if __name__ == "__main__":
    unittest.main()
