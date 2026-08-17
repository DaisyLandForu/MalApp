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
        self.assertTrue(snapshot["run_id"].startswith("run-"))
        self.assertEqual(snapshot["stage_order"], list(PIPELINE_STAGES))
        self.assertEqual(snapshot["status"], "degraded")
        self.assertTrue(
            all(item["status"] in {"completed", "failed", "degraded", "skipped"} for item in snapshot["stages"])
        )
        self.assertTrue(all(item["input_digest"].startswith("sha256:") for item in snapshot["stages"]))
        self.assertTrue(all(item["output_digest"].startswith("sha256:") for item in snapshot["stages"]))

    def test_failure_records_exception_type_without_input_payload(self) -> None:
        pipeline = PipelineStateMachine(run_id="run-test")
        pipeline.start("NORMALIZE", {"api_key": "never-persist-this", "sample_id": "sample"})
        pipeline.fail("NORMALIZE", ValueError("invalid sample"))
        stage = pipeline.snapshot()["by_name"]["NORMALIZE"]
        self.assertEqual(stage["error_type"], "ValueError")
        self.assertNotIn("never-persist-this", str(stage))

    def test_stage_order_is_enforced(self) -> None:
        pipeline = PipelineStateMachine()
        with self.assertRaises(RuntimeError):
            pipeline.start("AGENT_EXECUTION")


if __name__ == "__main__":
    unittest.main()
