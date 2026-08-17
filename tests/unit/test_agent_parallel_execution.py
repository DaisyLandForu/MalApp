from __future__ import annotations

import threading
import unittest

from malapp.orchestration.runtime import AgentRegistry, AgentRuntime
from tests.unit.agent_runtime_fixtures import BarrierAgent


class AgentParallelExecutionTest(unittest.TestCase):
    def test_registered_agents_execute_in_parallel(self) -> None:
        barrier = threading.Barrier(2)
        runtime = AgentRuntime(
            AgentRegistry([BarrierAgent("agent_a", barrier), BarrierAgent("agent_b", barrier)])
        )
        results, report = runtime.execute(
            {"sample_id": "parallel"},
            config={"max_workers": 2, "default_timeout_ms": 1000},
        )
        self.assertTrue(report["scheduler"]["concurrent"])
        self.assertEqual([item.status for item in results], ["completed", "completed"])


if __name__ == "__main__":
    unittest.main()
