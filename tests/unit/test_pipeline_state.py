from __future__ import annotations

import unittest

from malapp.orchestration.pipeline import PIPELINE_STAGES, PipelineStateMachine


class PipelineStateTest(unittest.TestCase):
    def test_all_stages_have_terminal_status(self) -> None:
        pipeline = PipelineStateMachine("pipeline-test")
        for stage in PIPELINE_STAGES:
            pipeline.start(stage)
            if stage == "RAG_RETRIEVAL":
                pipeline.degrade(stage, "retrieval_miss")
            elif stage == "XGB_INFERENCE":
                pipeline.skip(stage, "disabled")
            else:
                pipeline.complete(stage)
        snapshot = pipeline.snapshot()
        self.assertEqual(snapshot["pipeline_id"], "pipeline-test")
        self.assertEqual(snapshot["stage_order"], list(PIPELINE_STAGES))
        self.assertEqual(snapshot["status"], "degraded")
        self.assertTrue(
            all(item["status"] in {"completed", "failed", "degraded", "skipped"} for item in snapshot["stages"])
        )

    def test_stage_order_is_enforced(self) -> None:
        pipeline = PipelineStateMachine()
        with self.assertRaises(RuntimeError):
            pipeline.start("AGENT_EXECUTION")


if __name__ == "__main__":
    unittest.main()
