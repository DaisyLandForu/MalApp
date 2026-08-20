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

    def test_skipped_placeholder_is_not_degraded_result(self) -> None:
        result = skipped_by_plan_result("business_label", "insufficient_business_signal")
        self.assertEqual(result.failure_type, "skipped_by_plan")
        self.assertIn("business_label_analysis", result.artifacts)


if __name__ == "__main__":
    unittest.main()
