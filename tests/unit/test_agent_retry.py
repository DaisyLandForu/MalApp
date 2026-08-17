from __future__ import annotations

import unittest

from malapp.orchestration.runtime import AgentRegistry, AgentRuntime
from tests.unit.agent_runtime_fixtures import FlakyAgent


class AgentRetryTest(unittest.TestCase):
    def test_transient_failure_is_retried_and_recovered(self) -> None:
        agent = FlakyAgent("flaky_agent", failures=1)
        results, report = AgentRuntime(AgentRegistry([agent])).execute(
            {"sample_id": "retry"},
            config={"agents": {"flaky_agent": {"max_retries": 1}}},
        )
        self.assertEqual(results[0].status, "completed")
        self.assertEqual(results[0].attempts, 2)
        self.assertEqual(report["agents"]["flaky_agent"]["restart_count"], 1)
        attempt_statuses = [
            event["status"]
            for event in report["agents"]["flaky_agent"]["trace"]
            if event["phase"] == "attempt"
        ]
        self.assertEqual(attempt_statuses, ["failed", "completed"])


if __name__ == "__main__":
    unittest.main()
