from __future__ import annotations

import unittest

from malapp.orchestration.runtime import AgentRegistry, AgentRuntime
from tests.unit.agent_runtime_fixtures import FailingAgent, FlakyAgent


class AgentFailureTest(unittest.TestCase):
    def test_one_failure_does_not_destroy_other_results(self) -> None:
        runtime = AgentRuntime(
            AgentRegistry([FailingAgent("failed_agent"), FlakyAgent("healthy_agent", failures=0)])
        )
        results, report = runtime.execute(
            {"sample_id": "failure"},
            config={"default_max_retries": 0},
        )
        by_name = {item.agent_name: item for item in results}
        self.assertEqual(by_name["failed_agent"].status, "failed")
        self.assertEqual(by_name["failed_agent"].failure_type, "exception")
        self.assertEqual(by_name["healthy_agent"].status, "completed")
        self.assertEqual(report["status"], "degraded")


if __name__ == "__main__":
    unittest.main()
