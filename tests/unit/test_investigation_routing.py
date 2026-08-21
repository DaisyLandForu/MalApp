from __future__ import annotations

import unittest
from unittest.mock import patch

from malapp.agents.base import AgentContext, AgentResult, EvidenceBlock
from malapp.agents.evidence_contract import AGENT_ORDER, build_evidence_envelope
from malapp.orchestration.investigation import run_investigation
from malapp.orchestration.planner import skipped_by_plan_result


class RecordingAgent:
    def __init__(self, name: str):
        self.name = name
        self.calls = 0

    def run(self, context: AgentContext) -> AgentResult:
        self.calls += 1
        del context
        block = EvidenceBlock(
            agent=self.name,
            claim=f"{self.name} completed",
            evidence=["fixture"],
            confidence=0.8,
            score=0.4,
            rule_score=0.4,
        )
        artifacts = {}
        if self.name == "threat_intel":
            artifacts["threat_intelligence"] = {"status": "ok", "indicators": {}}
        elif self.name == "impersonation":
            artifacts["impersonation_analysis"] = {"status": "ok"}
        elif self.name == "business_label":
            artifacts["business_label_analysis"] = {"status": "ok"}
        return AgentResult(self.name, "completed", 0.4, [block], 0.8, artifacts=artifacts)


class MissingFieldAgent(RecordingAgent):
    def run(self, context: AgentContext) -> AgentResult:
        result = super().run(context)
        if self.name == "threat_intel":
            result.evidence[0].missing_fields = ["threat_intel_records", "domains"]
        elif self.name == "impersonation":
            result.evidence[0].missing_fields = ["official_pkg", "official_app_assets"]
        return result


class FlakyOnceAgent(RecordingAgent):
    def run(self, context: AgentContext) -> AgentResult:
        if self.calls == 0:
            self.calls += 1
            raise RuntimeError("first-round failure")
        return super().run(context)


class InvestigationRoutingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.agents = [RecordingAgent(name) for name in AGENT_ORDER]

    def test_flag_off_runs_all_four_agents(self) -> None:
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "0"}, clear=False):
            blocks, report, results = run_investigation(
                {"sample_id": "v0", "package_name": "com.example.app"},
                [],
                run_id="run-v0",
                agents=self.agents,
            )
        self.assertEqual([item.agent_name for item in results], list(AGENT_ORDER))
        self.assertEqual([item.status for item in results], ["completed"] * 4)
        self.assertEqual([agent.calls for agent in self.agents], [1, 1, 1, 1])
        self.assertEqual(len(blocks), 4)
        self.assertEqual(report["investigation"]["orchestration_mode"], "v0_fixed")

    def test_rule_planner_skips_without_signals_and_keeps_envelope(self) -> None:
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {"sample_id": "v1-skip", "package_name": "com.example.app", "signature_status": "valid"},
                [],
                run_id="run-v1",
                agents=self.agents,
            )
        by_name = {item.agent_name: item for item in results}
        self.assertEqual(by_name["static_analysis"].status, "completed")
        self.assertEqual(by_name["threat_intel"].failure_type, "skipped_by_plan")
        self.assertTrue(by_name["threat_intel"].artifacts["threat_intelligence"])
        self.assertEqual(self.agents[0].calls, 1)
        self.assertEqual(self.agents[1].calls, 0)
        envelope = build_evidence_envelope("v1-skip", [block for item in results for block in item.evidence], results)
        self.assertEqual(list(envelope.evidence_ids), list(AGENT_ORDER))
        self.assertEqual(report["investigation"]["degradation"]["status"], "healthy")

    def test_disabled_agent_overrides_planner_and_uses_old_degradation(self) -> None:
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule"}, clear=False):
            _blocks, report, results = run_investigation(
                {
                    "sample_id": "disabled",
                    "control_url": "https://c2.example.test",
                    "agent_runtime_config": {"agents": {"threat_intel": {"enabled": False}}},
                },
                [],
                run_id="run-disabled",
                agents=self.agents,
            )
        threat = next(item for item in results if item.agent_name == "threat_intel")
        self.assertEqual(threat.failure_type, "disabled")
        self.assertNotEqual(threat.failure_type, "skipped_by_plan")
        self.assertEqual(self.agents[1].calls, 0)
        self.assertTrue(report["investigation"]["degradation"]["reasons"])

    def test_invalid_llm_plan_falls_back_to_v0(self) -> None:
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "llm"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {"sample_id": "fallback", "investigation_plan": {"plan_version": "nope"}},
                [],
                run_id="run-fallback",
                agents=self.agents,
            )
        self.assertTrue(report["investigation"]["plan"]["fallback"])
        self.assertEqual([item.status for item in results], ["completed"] * 4)
        self.assertTrue(any(item["phase"] == "planner_fallback" for item in report["investigation"]["lifecycle"]))

    def test_network_gate_replans_skipped_threat_once(self) -> None:
        plan = {
            "plan_version": "1.0",
            "risk_focus": ["static_baseline", "network_ioc"],
            "agents": {
                "static_analysis": {"enabled": True, "reason_code": "mandatory_static_baseline"},
                "threat_intel": {"enabled": False, "reason_code": "insufficient_network_signal"},
                "impersonation": {"enabled": False, "reason_code": "insufficient_impersonation_signal"},
                "business_label": {"enabled": False, "reason_code": "insufficient_business_signal"},
            },
            "max_replans": 1,
        }
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "llm", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {"sample_id": "replan", "package_name": "com.example.app", "investigation_plan": plan},
                [],
                run_id="run-replan",
                agents=self.agents,
            )
        threat = next(item for item in results if item.agent_name == "threat_intel")
        self.assertEqual(threat.status, "completed")
        self.assertEqual(report["investigation"]["recovery_used"], 1)
        self.assertEqual(self.agents[1].calls, 1)
        self.assertTrue(any(item["phase"] == "replan_started" for item in report["investigation"]["lifecycle"]))
        self.assertTrue(any(item["phase"] == "replan_finished" for item in report["investigation"]["lifecycle"]))

    def test_unavailable_fields_do_not_trigger_empty_replan(self) -> None:
        agents = [MissingFieldAgent(name) for name in AGENT_ORDER]
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {
                    "sample_id": "unavailable",
                    "package_name": "com.example.app",
                    "control_url": "https://c2.example.test",
                    "fake_app": True,
                },
                [],
                run_id="run-unavailable",
                agents=agents,
            )
        self.assertEqual(agents[0].calls, 1)
        self.assertEqual(agents[1].calls, 1)
        self.assertEqual(agents[2].calls, 1)
        self.assertEqual(report["investigation"]["recovery_used"], 0)
        self.assertTrue(report["investigation"]["evidence_gate"]["sufficient"])
        self.assertTrue(report["investigation"]["evidence_gate"]["unavailable_fields"])
        self.assertFalse(any(item["phase"] == "replan_started" for item in report["investigation"]["lifecycle"]))
        self.assertTrue(report["investigation"]["degradation"]["review_recommended"])
        threat = next(item for item in results if item.agent_name == "threat_intel")
        self.assertEqual(threat.status, "completed")

    def test_skipped_placeholder_is_not_degraded_result(self) -> None:
        result = skipped_by_plan_result("business_label", "insufficient_business_signal")
        self.assertEqual(result.failure_type, "skipped_by_plan")
        self.assertIn("business_label_analysis", result.artifacts)

    def test_v0_respects_threat_intel_disabled(self) -> None:
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "0"}, clear=False):
            _blocks, report, results = run_investigation(
                {
                    "sample_id": "v0-disabled",
                    "package_name": "com.example.app",
                    "agent_runtime_config": {"agents": {"threat_intel": {"enabled": False}}},
                },
                [],
                run_id="run-v0-disabled",
                agents=self.agents,
            )
        threat = next(item for item in results if item.agent_name == "threat_intel")
        self.assertEqual(threat.failure_type, "disabled")
        self.assertEqual(self.agents[1].calls, 0)
        self.assertEqual(self.agents[0].calls, 1)
        self.assertTrue(report["agents"]["threat_intel"]["trace"])

    def test_planner_respects_static_analysis_disabled(self) -> None:
        with patch.dict("os.environ", {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule"}, clear=False):
            _blocks, report, results = run_investigation(
                {
                    "sample_id": "planner-static-disabled",
                    "control_url": "https://c2.example.test",
                    "agent_runtime_config": {"agents": {"static_analysis": {"enabled": False}}},
                },
                [],
                run_id="run-static-disabled",
                agents=self.agents,
            )
        static = next(item for item in results if item.agent_name == "static_analysis")
        self.assertEqual(static.failure_type, "disabled")
        self.assertNotEqual(static.failure_type, "skipped_by_plan")
        self.assertEqual(self.agents[0].calls, 0)
        self.assertTrue(report["investigation"]["degradation"]["reasons"])
        self.assertTrue(report["agents"]["static_analysis"]["trace"])

    def test_rule_planner_runs_high_value_agents_from_signals(self) -> None:
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, _report, results = run_investigation(
                {
                    "sample_id": "high-value",
                    "app_name": "Fast Loan",
                    "package_name": "com.fast.loan.update",
                    "permissions": ["READ_SMS"],
                    "control_url": "https://c2-loan-risk.example.net/upload",
                    "callback_url": "https://cb.example.test/beacon",
                    "icon_hash": "a" * 64,
                    "icon_text": "Secure Wallet",
                    "official_app_assets": [{"brand": "Secure Wallet", "icon_hash": "a" * 64}],
                },
                [],
                run_id="run-high-value",
                agents=self.agents,
            )
        by_name = {item.agent_name: item for item in results}
        self.assertEqual(by_name["threat_intel"].status, "completed")
        self.assertEqual(by_name["impersonation"].status, "completed")
        self.assertEqual(by_name["business_label"].status, "completed")
        self.assertEqual([agent.calls for agent in self.agents], [1, 1, 1, 1])

    def test_skipped_agents_keep_nonempty_trace(self) -> None:
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, _results = run_investigation(
                {"sample_id": "v1-trace", "package_name": "com.example.app", "signature_status": "valid"},
                [],
                run_id="run-v1-trace",
                agents=self.agents,
            )
        for name in AGENT_ORDER:
            self.assertTrue(report["agents"][name]["trace"], name)

    def test_replan_keeps_first_round_static_trace(self) -> None:
        plan = {
            "plan_version": "1.0",
            "risk_focus": ["static_baseline", "network_ioc"],
            "agents": {
                "static_analysis": {"enabled": True, "reason_code": "mandatory_static_baseline"},
                "threat_intel": {"enabled": False, "reason_code": "insufficient_network_signal"},
                "impersonation": {"enabled": False, "reason_code": "insufficient_impersonation_signal"},
                "business_label": {"enabled": False, "reason_code": "insufficient_business_signal"},
            },
            "max_replans": 1,
        }
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "llm", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {"sample_id": "replan-trace", "package_name": "com.example.app", "investigation_plan": plan},
                [],
                run_id="run-replan-trace",
                agents=self.agents,
            )
        self.assertEqual(report["investigation"]["recovery_used"], 1)
        self.assertTrue(report["agents"]["static_analysis"]["trace"])
        lifecycle_agents = {event.get("agent") for event in report["lifecycle"] if event.get("agent")}
        self.assertIn("static_analysis", lifecycle_agents)
        self.assertIn("threat_intel", lifecycle_agents)
        self.assertTrue(report["agents"]["threat_intel"]["trace"])
        for name in AGENT_ORDER:
            self.assertTrue(report["agents"][name]["trace"], name)
        threat = next(item for item in results if item.agent_name == "threat_intel")
        self.assertEqual(threat.status, "completed")

    def test_replan_concatenates_same_agent_traces(self) -> None:
        agents = [FlakyOnceAgent("static_analysis"), *[RecordingAgent(name) for name in AGENT_ORDER[1:]]]
        with patch.dict(
            "os.environ",
            {"MALAPP_PLANNER_ENABLED": "1", "MALAPP_PLANNER_MODE": "rule", "MALAPP_TOOL_RUNTIME_ENABLED": "0"},
            clear=False,
        ):
            _blocks, report, results = run_investigation(
                {
                    "sample_id": "retry-trace",
                    "package_name": "com.example.app",
                    "signature_status": "valid",
                    "agent_runtime_config": {"agents": {"static_analysis": {"max_retries": 0}}},
                },
                [],
                run_id="run-retry-trace",
                agents=agents,
            )
        static = next(item for item in results if item.agent_name == "static_analysis")
        self.assertEqual(static.status, "completed")
        self.assertEqual(agents[0].calls, 2)
        self.assertEqual(report["investigation"]["recovery_used"], 1)
        phases = [event.get("phase") for event in report["agents"]["static_analysis"]["trace"]]
        self.assertGreaterEqual(phases.count("registered"), 2)
        self.assertIn("failed", phases)
        self.assertIn("completed", phases)


if __name__ == "__main__":
    unittest.main()
