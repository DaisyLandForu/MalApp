from __future__ import annotations

import unittest

from malapp.orchestration.runtime import AgentRegistry, AgentRuntime
from tests.unit.agent_runtime_fixtures import FailingAgent, FlakyAgent, success_result


class FixtureAgent:
    name = "fixture_agent"

    def run(self, context):
        del context
        return success_result(self.name)


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

    def test_fault_matrix_modes_are_observable_and_recoverable(self) -> None:
        for mode, error_type in (
            ("transient_failure", "RuntimeError"),
            ("timeout", "TimeoutError"),
            ("invalid_schema", "ValueError"),
        ):
            runtime = AgentRuntime(AgentRegistry([FixtureAgent()]))
            results, report = runtime.execute(
                {
                    "sample_id": mode,
                    "agent_runtime_faults": {
                        "fixture_agent": {"failures": 1, "mode": mode}
                    },
                },
                config={"agents": {"fixture_agent": {"max_restarts": 1}}},
            )
            self.assertEqual("completed", results[0].status)
            self.assertEqual(2, results[0].attempts)
            trace = report["agents"]["fixture_agent"]["trace"]
            self.assertTrue(any(error_type in item["message"] for item in trace))


if __name__ == "__main__":
    unittest.main()
