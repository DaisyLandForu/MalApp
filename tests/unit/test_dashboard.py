from __future__ import annotations

import unittest

from malapp.application.dashboard import dashboard_overview


class DashboardTest(unittest.TestCase):
    def test_overview_exposes_operational_metrics(self) -> None:
        overview = dashboard_overview(cache_seconds=0)

        self.assertIn("counts", overview)
        self.assertIn("engine_records", overview["counts"])
        self.assertIn("saved_reports", overview["counts"])
        self.assertEqual(
            overview["counts"]["judgement_reports"],
            overview["counts"]["saved_reports"],
        )
        self.assertIn("storage", overview)
        self.assertIn("observability", overview)
        self.assertIn("latency_ms", overview["observability"]["runs"])
        self.assertIn("human_override_rate", overview["observability"]["runs"])
        self.assertIsInstance(overview["agents"], list)
        self.assertEqual(4, len(overview["agents"]))
        self.assertTrue(all("name" in agent and "status" in agent for agent in overview["agents"]))


if __name__ == "__main__":
    unittest.main()
