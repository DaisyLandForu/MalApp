from __future__ import annotations

import unittest
from unittest.mock import patch

from malapp.agents.business_label import analyze_business_label
from malapp.agents.impersonation import analyze_impersonation
from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.orchestration.degradation import evaluate_degradation
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
from malapp.tools.registry import FunctionTool, ToolRegistry, default_registry
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
        self.assertEqual(legacy[0].score, tooled[0].score)
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

    def test_forged_facts_drive_evidence_not_raw_sample(self) -> None:
        empty_indicators = {"urls": [], "domains": [], "ips": [], "emails": [], "phones": []}
        sample = {
            "sample_id": "causal",
            "control_url": "https://c2.example.test/gate",
            "domains": ["c2.example.test"],
        }
        assembled = assemble_threat_analysis(
            {
                "network_indicator": {"indicators": empty_indicators},
                "ioc_lookup": {
                    "indicators": empty_indicators,
                    "records": [],
                    "reputation": {"items": [], "aggregate_risk": 0.0, "queried_layers": [], "notice": "forged"},
                    "social_graph": {
                        "nodes": [],
                        "edges": [],
                        "clusters": [],
                        "shared_entities": [],
                        "team_signals": {"shared_entity_count": 0, "multi_app_cluster": False, "suspicious": False},
                    },
                },
                "family_correlation": {"family_attribution": {"matches": [], "best_match": None}},
            },
            sample,
        )
        self.assertEqual(assembled["indicators"]["domains"], [])
        self.assertNotIn("c2.example.test", str(assembled["indicators"]))
        self.assertNotIn("c2.example.test", " ".join(assembled["evidence_block"]["evidence"]))

        def forged_network(sample, **_):
            del sample
            return {"indicators": empty_indicators}

        def forged_ioc(sample, **_):
            del sample
            return {
                "indicators": empty_indicators,
                "records": [],
                "reputation": {"items": [], "aggregate_risk": 0.0, "queried_layers": [], "notice": "forged"},
                "social_graph": {
                    "nodes": [],
                    "edges": [],
                    "clusters": [],
                    "shared_entities": [],
                    "team_signals": {"shared_entity_count": 0, "multi_app_cluster": False, "suspicious": False},
                },
            }

        def forged_family(sample, **_):
            del sample
            return {"family_attribution": {"matches": [], "best_match": None}}

        from malapp.agents.base import AgentContext
        from malapp.agents.domain import ThreatIntelAgent
        from malapp.application.judgement import threat_intel_agent

        result = ThreatIntelAgent(threat_intel_agent).run(
            AgentContext(
                sample=sample,
                metadata={
                    "tool_registry": ToolRegistry(
                        [
                            FunctionTool("network_indicator", "threat_intel", forged_network),
                            FunctionTool("ioc_lookup", "threat_intel", forged_ioc),
                            FunctionTool("family_correlation", "threat_intel", forged_family),
                        ]
                    ),
                    "tool_allowlist": {"threat_intel": ["network_indicator", "ioc_lookup", "family_correlation"]},
                },
                request_id="run-causal-agent",
            )
        )
        observation_domains = result.artifacts["tool_observations"][0]["facts"]["indicators"]["domains"]
        self.assertEqual(observation_domains, [])
        self.assertNotIn("c2.example.test", str(result.artifacts["threat_intelligence"]["indicators"]))
        self.assertNotIn("c2.example.test", " ".join(result.evidence[0].evidence))
        self.assertNotIn("c2.example.test", result.evidence[0].claim)

    def test_ioc_lookup_timeout_does_not_backfill_legacy_analysis(self) -> None:
        from malapp.agents.base import AgentContext
        from malapp.agents.domain import ThreatIntelAgent
        from malapp.application.judgement import threat_intel_agent

        registry = ToolRegistry(
            [
                FunctionTool("network_indicator", "threat_intel", network_indicator),
                _TimeoutTool(),
                FunctionTool("family_correlation", "threat_intel", family_correlation),
            ]
        )
        result = ThreatIntelAgent(threat_intel_agent).run(
            AgentContext(
                sample={"sample_id": "timeout-agent", "control_url": "https://c2.example.test/gate"},
                metadata={
                    "tool_registry": registry,
                    "tool_allowlist": {"threat_intel": ["network_indicator", "ioc_lookup", "family_correlation"]},
                    "plan_id": "plan-timeout",
                },
                request_id="run-timeout-agent",
            )
        )
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.failure_type, "timeout")
        intel = result.artifacts["threat_intelligence"]
        self.assertEqual(intel["reputation"].get("notice"), "ioc_lookup not executed")
        self.assertEqual(intel["reputation"]["aggregate_risk"], 0.0)
        statuses = {item["tool_name"]: item["status"] for item in result.artifacts["tool_observations"]}
        self.assertEqual(statuses["ioc_lookup"], "timeout")
        self.assertNotIn("ioc_lookup", result.artifacts["tool_execution"]["facts"])
        policy = evaluate_degradation([result])
        self.assertEqual(policy["status"], "degraded")
        self.assertIn("threat_intel_timeout", [item["code"] for item in policy["reasons"]])

    def test_empty_and_subset_allowlist_are_enforced(self) -> None:
        from malapp.agents.base import AgentContext
        from malapp.agents.domain import ThreatIntelAgent
        from malapp.application.judgement import threat_intel_agent
        from malapp.orchestration.planner import v0_fixed_plan, validate_plan

        payload = v0_fixed_plan().to_dict()
        payload["tool_allowlist"]["threat_intel"] = []
        self.assertEqual(validate_plan(payload).tool_names("threat_intel"), ())

        empty = ThreatIntelAgent(threat_intel_agent).run(
            AgentContext(
                sample={"sample_id": "empty-allow", "control_url": "https://c2.example.test/gate"},
                metadata={"tool_registry": default_registry(), "tool_allowlist": {"threat_intel": []}},
                request_id="run-empty-allow",
            )
        )
        self.assertEqual(empty.artifacts.get("tool_observations") or [], [])
        self.assertEqual(empty.artifacts["threat_intelligence"]["indicators"]["domains"], [])
        self.assertNotIn("c2.example.test", str(empty.artifacts["threat_intelligence"]["indicators"]))
        self.assertNotIn("c2.example.test", " ".join(empty.evidence[0].evidence))

        subset = ThreatIntelAgent(threat_intel_agent).run(
            AgentContext(
                sample={"sample_id": "subset-allow", "control_url": "https://c2.example.test/gate"},
                metadata={"tool_registry": default_registry(), "tool_allowlist": {"threat_intel": ["network_indicator"]}},
                request_id="run-subset-allow",
            )
        )
        names = [item["tool_name"] for item in subset.artifacts["tool_observations"]]
        self.assertEqual(names, ["network_indicator"])
        self.assertNotIn("ioc_lookup", subset.artifacts["tool_execution"]["facts"])
        self.assertEqual(subset.artifacts["threat_intelligence"]["reputation"].get("notice"), "ioc_lookup not executed")

    def test_input_digest_tracks_payload_and_nested_facts_are_isolated(self) -> None:
        sample_a = {"sample_id": "same-id", "control_url": "https://a.example.test"}
        sample_b = {"sample_id": "same-id", "control_url": "https://b.example.test"}
        executor = ToolExecutor(default_registry())
        first = executor.execute("threat_intel", ["network_indicator"], sample_a)
        second = executor.execute("threat_intel", ["network_indicator"], sample_b)
        self.assertNotEqual(first.observations[0].input_digest, second.observations[0].input_digest)
        domains = first.facts["network_indicator"]["indicators"]["domains"]
        original = list(domains)
        domains.append("injected.example")
        self.assertEqual(first.observations[0].facts["indicators"]["domains"], original)
        self.assertNotIn("injected.example", first.observations[0].facts["indicators"]["domains"])


if __name__ == "__main__":
    unittest.main()
