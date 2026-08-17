from __future__ import annotations

import unittest

from malapp.orchestration.runtime import AgentRegistry, AgentRuntime
from tests.unit.agent_runtime_fixtures import SleepingAgent


class AgentTimeoutTest(unittest.TestCase):
    def test_timeout_is_distinct_and_has_trace(self) -> None:
        runtime = AgentRuntime(AgentRegistry([SleepingAgent("slow_agent", 0.05)]))
        results, report = runtime.execute(
            {"sample_id": "timeout"},
            config={"agents": {"slow_agent": {"timeout_ms": 10, "max_retries": 0}}},
        )
        result = results[0]
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.failure_type, "timeout")
        self.assertEqual(report["status"], "degraded")
        self.assertIn("timeout", [event["phase"] for event in report["agents"]["slow_agent"]["trace"]])
        self.assertEqual(result.evidence[0].status, "degraded")


if __name__ == "__main__":
    unittest.main()
