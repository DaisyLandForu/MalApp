from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from malapp.evaluation.five_layer import (
    collect_five_layer_experiments,
    list_five_layer_suites,
    selected_five_layer_suite,
)


class FiveLayerHistoryTest(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test_tmp"
        test_tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_history_keeps_old_results_and_selects_exact_suite(self) -> None:
        data_dir = self.root / "data"
        suite_root = data_dir / "evaluation" / "five_layer"
        old_suite = suite_root / "suite-old"
        new_suite = suite_root / "suite-new"
        for suite, created in (
            (old_suite, "2026-08-04T00:00:00+00:00"),
            (new_suite, "2026-08-05T00:00:00+00:00"),
        ):
            suite.mkdir(parents=True)
            manifest = {
                "suite_id": suite.name,
                "suite_dir": str(suite),
                "created_at": created,
                "status": "generated",
                "dataset_counts": {},
                "selection": {},
            }
            (suite / "manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
        (suite_root / "latest.json").write_text(
            (new_suite / "manifest.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        run_dir = (
            data_dir
            / "evaluation"
            / "five_layer_runs"
            / "suite-old-model-release"
        )
        run_dir.mkdir(parents=True)
        (run_dir / "checkpoint.json").write_text(
            json.dumps(
                {
                    "items": {
                        "A": {"status": "completed"},
                        "B": {"status": "failed"},
                    }
                }
            ),
            encoding="utf-8",
        )

        history = list_five_layer_suites(data_dir=data_dir)
        self.assertEqual(
            ["suite-new", "suite-old"], [item["suite_id"] for item in history]
        )
        old = next(item for item in history if item["suite_id"] == "suite-old")
        self.assertTrue(old["has_results"])
        self.assertEqual(1, old["completed_executions"])
        self.assertEqual(1, old["failed_executions"])
        self.assertEqual(
            "suite-old",
            selected_five_layer_suite("suite-old", data_dir=data_dir)["suite_id"],
        )
        self.assertEqual(
            "suite-new",
            selected_five_layer_suite("missing", data_dir=data_dir)["suite_id"],
        )

    def test_results_recover_without_job_index(self) -> None:
        data_dir = self.root / "data"
        suite = data_dir / "evaluation" / "five_layer" / "suite-recover"
        suite.mkdir(parents=True)
        runs = data_dir / "evaluation" / "five_layer_runs"
        for suffix in (
            "full",
            "no-static_analysis",
            "no-threat_intel",
            "no-impersonation",
            "no-business_label",
        ):
            run_dir = runs / f"suite-recover-{suffix}"
            run_dir.mkdir(parents=True)
            (run_dir / "result.json").write_text(
                json.dumps(
                    {"status": "completed", "completed_this_invocation": 1}
                ),
                encoding="utf-8",
            )
            (run_dir / "checkpoint.json").write_text(
                json.dumps({"items": {"A": {"status": "completed"}}}),
                encoding="utf-8",
            )
        result = collect_five_layer_experiments(
            {"suite_id": "suite-recover", "suite_dir": str(suite)}, data_dir
        )
        agent = result["agent_ablation"]
        self.assertEqual("completed", agent["status"])
        self.assertEqual(5, agent["completed_variants"])
        self.assertTrue(str(agent["job_id"]).startswith("recovered-"))

    def test_strict_reference_metrics_use_all_release_rows(self) -> None:
        data_dir = self.root / "data"
        suite = data_dir / "evaluation" / "five_layer" / "suite-full"
        release = suite / "layer1_model" / "model_release_holdout.jsonl"
        release.parent.mkdir(parents=True)
        release.write_text(
            "\n".join(
                json.dumps(row)
                for row in (
                    {"id": "A", "expected": {"verdict": "malicious"}},
                    {
                        "id": "B",
                        "expected": {"verdict": "benign"},
                        "label_tier": "strict_source_reference",
                    },
                )
            )
            + "\n",
            encoding="utf-8",
        )
        run_dir = data_dir / "evaluation" / "five_layer_runs" / "suite-full-model-release"
        runtime_data = run_dir / "data"
        runtime_data.mkdir(parents=True)
        (run_dir / "result.json").write_text(
            json.dumps({"status": "completed", "completed_this_invocation": 2}),
            encoding="utf-8",
        )
        (run_dir / "checkpoint.json").write_text(
            json.dumps(
                {
                    "items": {
                        "A": {"status": "completed"},
                        "B": {"status": "completed"},
                    }
                }
            ),
            encoding="utf-8",
        )
        reports = (
            {
                "sample": {"md5": "A"},
                "decision": {
                    "verdict": "malicious",
                    "xgb": {"verdict": "malicious"},
                },
                "debate": {
                    "model_a": {"verdict": "malicious"},
                    "model_b": {"verdict": "benign"},
                },
            },
            {
                "sample": {"md5": "B"},
                "decision": {
                    "verdict": "benign",
                    "xgb": {"verdict": "malicious"},
                },
                "debate": {
                    "model_a": {"verdict": "benign"},
                    "model_b": {"verdict": "benign"},
                },
            },
        )
        connection = sqlite3.connect(runtime_data / "mvp.db")
        try:
            connection.execute(
                "CREATE TABLE judgements (payload_json TEXT, created_at TEXT)"
            )
            connection.executemany(
                "INSERT INTO judgements VALUES (?, ?)",
                [
                    (json.dumps(report), f"2026-08-05T00:00:0{index}Z")
                    for index, report in enumerate(reports)
                ],
            )
            connection.commit()
        finally:
            connection.close()

        result = collect_five_layer_experiments(
            {"suite_id": "suite-full", "suite_dir": str(suite)}, data_dir
        )["model_release"]
        channels = result["reference_channels"]
        self.assertEqual(2, result["reference_total"])
        self.assertEqual(2, channels["pipeline_final"]["available_outputs"])
        self.assertEqual(1.0, channels["pipeline_final"]["decided_accuracy"])
        self.assertEqual(0.5, channels["model_b"]["decided_accuracy"])
        self.assertEqual(1.0, channels["xgboost"]["benign_false_positive_rate"])


if __name__ == "__main__":
    unittest.main()
