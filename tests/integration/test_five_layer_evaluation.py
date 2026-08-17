from __future__ import annotations

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from malapp.evaluation.five_layer import (
    build_structured_rag_corpus,
    collect_five_layer_experiments,
    five_layer_test_results,
    list_rag_annotations,
    save_rag_annotation,
    score_model_predictions,
    score_production_drift,
    segmented_model_baseline,
    validate_five_layer_suite,
)
from malapp.evaluation.workflows import (
    build_commands,
    live_job_batch_progress,
    prepare_workflow_batch,
    workflow_cumulative_progress,
    workflow_dataset_total,
)
from malapp.rag.store import add_document, rebuild_graph_index
from scripts.evaluation.run_evaluation import (
    blind_model_input,
    load_requested_sample_ids,
    stage_isolated_runtime_assets,
)


class FiveLayerEvaluationTest(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test_tmp"
        test_tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def write_jsonl(path: Path, rows: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
            encoding="utf-8",
        )

    def test_score_model_predictions(self) -> None:
        dataset = self.root / "dataset.jsonl"
        predictions = self.root / "predictions.jsonl"
        self.write_jsonl(
            dataset,
            [
                {"id": "A", "expected": {"verdict": "malicious"}},
                {"id": "B", "expected": {"verdict": "benign"}},
            ],
        )
        self.write_jsonl(
            predictions,
            [
                {
                    "id": "A",
                    "verdict": "malicious",
                    "score": 0.9,
                    "evidence_refs": ["e1"],
                    "latency_ms": 100,
                },
                {
                    "id": "B",
                    "verdict": "benign",
                    "score": 0.1,
                    "evidence_refs": [],
                    "latency_ms": 200,
                },
            ],
        )
        result = score_model_predictions(dataset, predictions)
        self.assertEqual(1.0, result["metrics"]["decided_accuracy"])
        self.assertEqual(1.0, result["metrics"]["json_schema_success_rate"])
        self.assertEqual(195.0, result["metrics"]["latency_ms"]["p95"])

    def test_release_metrics_separate_expert_gold_from_source_reference(self) -> None:
        rows = [
            {
                "_row_id": "A" * 32,
                "_gold_label": "malicious",
                "label_tier": "frozen_validation_gold",
                "annotation_status": "gold_from_frozen_validation",
                "intended_use": "release_gate",
            },
            {
                "_row_id": "B" * 32,
                "_gold_label": "malicious",
                "label_tier": "source_reference_requires_two_expert_reviews",
                "annotation_status": "strict_source_reference_requires_two_expert_reviews",
                "intended_use": "provisional_strict_release_diagnostic",
            },
        ]
        reports = {
            "A" * 32: {
                "debate": {
                    "model_a": {"verdict": "malicious"},
                    "model_b": {"verdict": "malicious"},
                }
            },
            "B" * 32: {
                "debate": {
                    "model_a": {"verdict": "benign"},
                    "model_b": {"verdict": "benign"},
                }
            },
        }
        result = segmented_model_baseline(rows, reports)
        self.assertEqual(1, result["official_gold"]["dataset_total"])
        self.assertEqual(1.0, result["model_a"]["decided_accuracy"])
        self.assertEqual(
            0.0,
            result["provisional_source_reference"]["model_a"]["decided_accuracy"],
        )

    def test_drift_same_data_has_zero_psi(self) -> None:
        csv_path = self.root / "current.csv"
        with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["md5", "gold_label", "label_source"],
            )
            writer.writeheader()
            writer.writerows(
                [
                    {"md5": "A" * 32, "gold_label": "malicious", "label_source": "x"},
                    {"md5": "B" * 32, "gold_label": "benign", "label_source": "y"},
                ]
            )
        suite = self.root / "suite"
        reference = {
            "distributions": [
                {
                    "field": "gold_label",
                    "values": {
                        "malicious": {"count": 1, "rate": 0.5},
                        "benign": {"count": 1, "rate": 0.5},
                    },
                }
            ]
        }
        reference_path = suite / "layer5_production" / "drift_reference.json"
        reference_path.parent.mkdir(parents=True, exist_ok=True)
        reference_path.write_text(json.dumps(reference), encoding="utf-8")
        result = score_production_drift(suite, csv_path)
        self.assertEqual("ok", result["status"])
        self.assertEqual(0.0, result["max_categorical_psi"])

    def test_suite_validation_checks_disjoint_release_and_challenge(self) -> None:
        suite = self.root / "suite"
        validation_csv = self.root / "validation.csv"
        with validation_csv.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["md5", "gold_label", "label_source"],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "md5": "A" * 32,
                    "gold_label": "malicious",
                    "label_source": "expert",
                }
            )
        manifest = {
            "suite_id": "test-suite",
            "suite_dir": str(suite),
            "validation_source": {"path": str(validation_csv)},
        }
        suite.mkdir(parents=True)
        (suite / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        files = (
            "layer1_model/model_release_holdout.jsonl",
            "layer1_model/expert_gold_holdout.jsonl",
            "layer1_model/model_diagnostic_eval.jsonl",
            "layer1_model/model_schema_challenges.jsonl",
            "layer2_rag/rag_retrieval_eval.jsonl",
            "layer2_rag/rag_corpus_inventory.jsonl",
            "layer2_rag/evidence_faithfulness_eval.jsonl",
            "layer3_agent/agent_trace_eval.jsonl",
            "layer3_agent/agent_fault_eval.jsonl",
            "layer3_agent/agent_ablation_eval.jsonl",
            "layer4_e2e/end_to_end_release_holdout.jsonl",
            "layer4_e2e/end_to_end_diagnostic_all.jsonl",
            "layer4_e2e/end_to_end_challenge_eval.jsonl",
            "layer5_production/production_replay_eval.jsonl",
            "layer5_production/production_reliability_eval.jsonl",
            "fresh_expert_holdout_candidates.jsonl",
        )
        for relative in files:
            row_id = "C" * 32
            row = {"id": row_id}
            if relative.endswith("model_release_holdout.jsonl"):
                row = {
                    "id": "A" * 32,
                    "training_overlap": False,
                    "label_tier": "frozen_validation_gold",
                    "annotation_status": "gold_from_frozen_validation",
                    "intended_use": "release_gate",
                }
            elif relative.endswith("expert_gold_holdout.jsonl"):
                row = {
                    "id": "A" * 32,
                    "training_overlap": False,
                    "label_tier": "frozen_validation_gold",
                    "annotation_status": "gold_from_frozen_validation",
                    "intended_use": "release_gate",
                }
            elif relative.endswith("end_to_end_release_holdout.jsonl"):
                row = {"id": "A" * 32, "training_overlap": False}
            elif relative.endswith("end_to_end_challenge_eval.jsonl"):
                row = {"id": "B" * 32}
            elif relative == "fresh_expert_holdout_candidates.jsonl":
                row = {"id": "D" * 32}
            self.write_jsonl(suite / relative, [row])
        result = validate_five_layer_suite(suite)
        self.assertTrue(result["passed"])

    def test_five_layer_test_results_exposes_each_layer(self) -> None:
        suite = self.root / "results-suite"
        suite.mkdir()
        (suite / "baseline_scorecards.json").write_text(
            json.dumps(
                {
                    "layer1_model": {
                        "release_holdout": {
                            "model_a": {
                                "available_outputs": 1,
                                "decided_accuracy": 1.0,
                                "malicious_recall": 1.0,
                                "benign_false_positive_rate": 0.0,
                            },
                            "model_b": {
                                "available_outputs": 1,
                                "decided_accuracy": 1.0,
                                "malicious_recall": 1.0,
                                "benign_false_positive_rate": 0.0,
                            },
                        }
                    },
                    "layer2_rag": {"rag_enabled_reports": 1},
                    "layer3_agent": {"reports_with_saved_output": 1},
                    "layer4_e2e": {
                        "release_holdout": {
                            "dataset_total": 1,
                            "evaluated_total": 1,
                            "coverage": 1.0,
                        }
                    },
                    "layer5_production": {"saved_reports": 1},
                }
            ),
            encoding="utf-8",
        )
        (suite / "suite_validation.json").write_text(
            json.dumps(
                {
                    "passed": True,
                    "checks_total": 23,
                    "checks_passed": 23,
                    "checks_failed": 0,
                }
            ),
            encoding="utf-8",
        )
        manifest = {
            "suite_id": "results-suite",
            "suite_dir": str(suite),
            "selection": {"release_holdout_count": 1},
            "dataset_counts": {
                "layer2_rag": {"rag_retrieval_eval": 1},
                "layer3_agent": {"agent_trace_eval": 1},
                "layer5_production": {"production_replay_eval": 1},
            },
        }
        readiness = {
            "layers": {
                key: {"status": "ready"}
                for key in (
                    "layer1_model",
                    "layer2_rag",
                    "layer3_agent",
                    "layer4_e2e",
                    "layer5_production",
                )
            }
        }
        experiments = {
            "model_release": {
                "status": "completed",
                "variants": [
                    {"completed_samples": 1, "failed_samples": 0}
                ],
                "model_a": {
                    "available_outputs": 1,
                    "decided_accuracy": 1.0,
                    "malicious_recall": 1.0,
                },
                "model_b": {
                    "available_outputs": 1,
                    "decided_accuracy": 1.0,
                    "malicious_recall": 1.0,
                },
            }
        }
        result = five_layer_test_results(manifest, readiness, experiments)
        self.assertEqual(23, result["suite_validation"]["checks_passed"])
        self.assertEqual(
            {
                "layer1_model",
                "layer2_rag",
                "layer3_agent",
                "layer4_e2e",
                "layer5_production",
            },
            set(result["layers"]),
        )
        self.assertEqual(
            1.0,
            result["layers"]["layer1_model"]["metrics"]["model_a_coverage"],
        )
        self.assertEqual(
            1,
            result["layers"]["layer1_model"]["metrics"][
                "historical_model_a_outputs"
            ],
        )
        self.assertEqual(
            "completed",
            result["layers"]["layer1_model"]["metrics"][
                "model_release_status"
            ],
        )

    def test_graph_rebuild_repairs_zero_node_legacy_state(self) -> None:
        path = self.root / "rag.db"
        add_document(
            doc_id="doc-1",
            source_type="test",
            source_name="test",
            title="sample",
            content="md5=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; package_name=com.example",
            metadata={"md5": "A" * 32, "package_name": "com.example"},
            path=path,
        )
        conn = sqlite3.connect(path)
        try:
            conn.execute("DELETE FROM kg_edges")
            conn.execute("DELETE FROM kg_nodes")
            conn.execute("DELETE FROM kg_document_links")
            conn.commit()
            self.assertEqual(
                1,
                conn.execute("SELECT COUNT(*) FROM kg_index_state").fetchone()[0],
            )
        finally:
            conn.close()
        result = rebuild_graph_index(path)
        self.assertGreater(result["nodes"], 0)
        self.assertGreater(result["edges"], 0)
        self.assertEqual(1, result["processed_documents"])

    def test_structured_rag_corpus_excludes_answers_and_validation_ids(self) -> None:
        data_dir = self.root / "data"
        data_dir.mkdir()
        validation_csv = self.root / "validation.csv"
        with validation_csv.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["md5", "gold_label", "label_source"],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "md5": "A" * 32,
                    "gold_label": "malicious",
                    "label_source": "expert",
                }
            )
        conn = sqlite3.connect(data_dir / "mvp.db")
        try:
            conn.execute(
                """
                CREATE TABLE app_md5_labels (
                    md5 TEXT, source_sheet TEXT, label TEXT, app_name TEXT,
                    fraud_type TEXT, fraud_subtype TEXT, raw_json TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE engine_detections (
                    engine TEXT, md5 TEXT, sha1 TEXT, sha256 TEXT,
                    package_name TEXT, app_name TEXT, fake_app TEXT,
                    virus_name TEXT, detect_type TEXT, score REAL,
                    virus_description TEXT, description TEXT,
                    control_url TEXT, download_url TEXT,
                    fraud_category_big TEXT, fraud_category_small TEXT,
                    fraud_family TEXT, official_pkg TEXT,
                    official_app_name TEXT, sdk_list TEXT,
                    cert_sha1 TEXT, cert_sha256 TEXT, find_time TEXT
                )
                """
            )
            conn.execute(
                "INSERT INTO app_md5_labels VALUES(?,?,?,?,?,?,?)",
                (
                    "B" * 32,
                    "sheet",
                    "malicious",
                    "Example",
                    "fraud",
                    "sub",
                    json.dumps(
                        {
                            "package_name": "com.example",
                            "gold_label": "malicious",
                            "xgb_probability": 0.99,
                        }
                    ),
                ),
            )
            conn.execute(
                """
                INSERT INTO engine_detections
                (engine,md5,package_name,app_name,virus_name,control_url)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    "360",
                    "B" * 32,
                    "com.example",
                    "Example",
                    "Risk.Test",
                    "https://example.test/path",
                ),
            )
            conn.commit()
        finally:
            conn.close()
        rag_db = data_dir / "rag" / "rag_store.db"
        result = build_structured_rag_corpus(
            data_dir=data_dir,
            validation_csv=validation_csv,
            size=10,
            rag_db_path=rag_db,
            reserved_fresh_size=0,
        )
        self.assertEqual(1, result["documents_added_or_updated"])
        self.assertTrue(result["rag_status"]["graph"]["ready"])
        conn = sqlite3.connect(rag_db)
        try:
            rows = conn.execute(
                "SELECT doc_id,metadata_json,content FROM rag_documents"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(1, len(rows))
        self.assertIn("B" * 32, rows[0][0])
        self.assertNotIn("A" * 32, rows[0][0])
        metadata = json.loads(rows[0][1])
        self.assertNotIn("gold_label", metadata)
        self.assertNotIn("xgb_probability", metadata)
        self.assertNotIn("malicious", rows[0][2].lower())

    def test_rag_expert_annotation_updates_dataset_and_scorecard(self) -> None:
        data_dir = self.root / "data"
        suite = data_dir / "evaluation" / "five_layer" / "suite-1"
        dataset = suite / "layer2_rag" / "rag_retrieval_eval.jsonl"
        self.write_jsonl(
            dataset,
            [
                {
                    "id": "A" * 32,
                    "query": "判断样本证据",
                    "retrieved_doc_ids": ["doc-right", "doc-noise"],
                    "retrieved_items": [
                        {"doc_id": "doc-right", "title": "命中证据", "content": "evidence"},
                        {"doc_id": "doc-noise", "title": "干扰证据", "content": "noise"},
                    ],
                    "annotation_status": "needs_expert_review",
                    "relevant_doc_ids": [],
                    "hard_negative_doc_ids": [],
                }
            ],
        )
        latest = data_dir / "evaluation" / "five_layer" / "latest.json"
        latest.parent.mkdir(parents=True, exist_ok=True)
        latest.write_text(
            json.dumps({"suite_id": "suite-1", "suite_dir": str(suite)}),
            encoding="utf-8",
        )

        pending = list_rag_annotations(data_dir=data_dir, status="pending")
        self.assertEqual(1, len(pending["items"]))
        saved = save_rag_annotation(
            data_dir=data_dir,
            sample_id="a" * 32,
            relevant_doc_ids=["doc-right"],
            hard_negative_doc_ids=["doc-noise"],
            annotation_status="approved",
            reviewer="专家甲",
            review_notes="证据与样本一致",
            evidence_supported=True,
            hallucination=False,
        )
        self.assertTrue(saved["saved"])
        self.assertEqual(1.0, saved["scorecard"]["metrics"]["recall_at_5"])
        self.assertTrue((suite / "layer2_rag" / "rag_scorecard.json").exists())
        self.assertEqual(
            1,
            len(list_rag_annotations(data_dir=data_dir, status="approved")["items"]),
        )

    def test_workflow_commands_cover_every_layer_action(self) -> None:
        data_dir = self.root / "data"
        suite = self.root / "suite-workflow"
        validation_csv = self.root / "validation-workflow.csv"
        validation_csv.write_text("md5,gold_label\n", encoding="utf-8")
        for relative in (
            "layer1_model/model_release_holdout.jsonl",
            "layer1_model/expert_gold_holdout.jsonl",
            "layer2_rag/rag_retrieval_eval.jsonl",
            "layer3_agent/agent_ablation_eval.jsonl",
            "layer4_e2e/end_to_end_challenge_eval.jsonl",
        ):
            self.write_jsonl(suite / relative, [{"id": "A" * 32}])
        manifest = {
            "suite_dir": str(suite),
            "validation_source": {"path": str(validation_csv)},
            "workflow_validation_source": {"path": str(validation_csv)},
            "selection": {"release_holdout_count": 1},
            "dataset_counts": {
                "layer1_model": {"expert_gold_holdout": 1},
                "layer2_rag": {"rag_retrieval_eval": 1},
                "layer3_agent": {"agent_ablation_eval": 1},
                "layer4_e2e": {"end_to_end_challenge_eval": 1},
            },
        }
        expected = {
            "gold_compare": 1,
            "model_release": 1,
            "rag_compare": 3,
            "agent_ablation": 5,
            "complete_release": 1,
            "production_reliability": 2,
        }
        for action, count in expected.items():
            commands = build_commands(
                action,
                manifest=manifest,
                data_dir=data_dir,
                job_id="test-job",
            )
            self.assertEqual(count, len(commands), action)
            self.assertTrue(all("--sample-id-file" in item["args"] for item in commands))
            self.assertTrue(
                all("--isolation-sample-id-file" in item["args"] for item in commands)
            )
        pending = build_commands(
            "complete_release",
            manifest=manifest,
            data_dir=data_dir,
            job_id="test-job",
        )
        self.assertIn("--pending-only", pending[0]["args"])

    def test_workflow_batch_limits_accumulate_and_preserve_replay(self) -> None:
        data_dir = self.root / "data-batches"
        suite = self.root / "suite-batches"
        validation_csv = self.root / "validation-batches.csv"
        validation_csv.write_text("md5,gold_label\n", encoding="utf-8")
        for relative in (
            "layer1_model/model_release_holdout.jsonl",
            "layer1_model/expert_gold_holdout.jsonl",
            "layer2_rag/rag_retrieval_eval.jsonl",
            "layer3_agent/agent_ablation_eval.jsonl",
            "layer4_e2e/end_to_end_challenge_eval.jsonl",
        ):
            self.write_jsonl(suite / relative, [{"id": "A" * 32}])
        manifest = {
            "suite_id": "suite-batches",
            "suite_dir": str(suite),
            "workflow_validation_source": {"path": str(validation_csv)},
            "selection": {"release_holdout_count": 100},
            "dataset_counts": {
                "layer1_model": {"expert_gold_holdout": 95},
                "layer2_rag": {"rag_retrieval_eval": 80},
                "layer3_agent": {"agent_ablation_eval": 60},
                "layer4_e2e": {"end_to_end_challenge_eval": 30},
            },
        }
        for action in (
            "gold_compare",
            "model_release",
            "rag_compare",
            "agent_ablation",
            "complete_release",
        ):
            commands = build_commands(
                action,
                manifest=manifest,
                data_dir=data_dir,
                job_id="batch-job",
                batch_size=7,
            )
            for item in commands:
                args = item["args"]
                self.assertEqual("7", args[args.index("--limit") + 1])
                self.assertIn("--next-unfinished", args)

        reliability = build_commands(
            "production_reliability",
            manifest=manifest,
            data_dir=data_dir,
            job_id="batch-job",
            batch_size=7,
        )
        self.assertIn("--next-unfinished", reliability[0]["args"])
        self.assertNotIn("--replay-last-selection", reliability[0]["args"])
        self.assertIn("--replay-last-selection", reliability[1]["args"])
        self.assertNotIn("--next-unfinished", reliability[1]["args"])

        self.assertEqual(
            30,
            workflow_dataset_total("production_reliability", manifest),
        )
        reliability_custom = build_commands(
            "production_reliability",
            manifest=manifest,
            data_dir=data_dir,
            job_id="batch-job-custom",
            batch_size=27,
        )
        for item in reliability_custom:
            args = item["args"]
            self.assertEqual("27", args[args.index("--limit") + 1])

    def test_workflow_progress_uses_minimum_completed_variant(self) -> None:
        data_dir = self.root / "data-progress"
        suite_id = "suite-progress"
        manifest = {
            "suite_id": suite_id,
            "selection": {"release_holdout_count": 10},
            "dataset_counts": {
                "layer2_rag": {"rag_retrieval_eval": 10},
            },
        }
        root = data_dir / "evaluation" / "five_layer_runs"
        for variant, completed in (("rag_off", 5), ("rag_vector", 4), ("rag_hybrid", 3)):
            checkpoint = root / f"{suite_id}-{variant}" / "checkpoint.json"
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            checkpoint.write_text(
                json.dumps(
                    {
                        "items": {
                            f"sample-{index}": {"status": "completed"}
                            for index in range(completed)
                        }
                    }
                ),
                encoding="utf-8",
            )
        progress = workflow_cumulative_progress("rag_compare", manifest, data_dir)
        self.assertEqual(3, progress["completed_base_samples"])
        self.assertEqual(7, progress["remaining_base_samples"])
        self.assertEqual(12, progress["completed_executions"])

    def test_workflow_batch_keeps_variants_on_same_sample_ids(self) -> None:
        data_dir = self.root / "data-paired-batch"
        suite = self.root / "suite-paired-batch"
        dataset = suite / "layer2_rag" / "rag_retrieval_eval.jsonl"
        sample_ids = [character * 32 for character in "ABCD"]
        self.write_jsonl(dataset, [{"id": sample_id} for sample_id in sample_ids])
        manifest = {
            "suite_id": "suite-paired-batch",
            "suite_dir": str(suite),
            "dataset_counts": {"layer2_rag": {"rag_retrieval_eval": 4}},
        }
        checkpoint_root = data_dir / "evaluation" / "five_layer_runs"
        for variant, completed in (
            ("rag_off", sample_ids[:2]),
            ("rag_vector", sample_ids[:1]),
            ("rag_hybrid", sample_ids[:1]),
        ):
            path = checkpoint_root / f"suite-paired-batch-{variant}" / "checkpoint.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {"items": {sample_id: {"status": "completed"} for sample_id in completed}}
                ),
                encoding="utf-8",
            )
        selection = prepare_workflow_batch(
            "rag_compare",
            manifest=manifest,
            data_dir=data_dir,
            source_file=dataset,
            job_id="paired-job",
            batch_size=2,
        )
        self.assertEqual(sample_ids[1:3], selection["selected_sample_ids"])
        self.assertEqual(2, selection["selected_count"])

    def test_live_batch_progress_reads_child_checkpoint(self) -> None:
        output_root = self.root / "runs-live"
        run_id = "live-run"
        checkpoint = output_root / run_id / "checkpoint.json"
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        checkpoint.write_text(
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
        job = {
            "planned_executions": 3,
            "batch_selection": {"selected_sample_ids": ["A", "B", "C"]},
            "commands": [
                {
                    "args": [
                        "run",
                        "--run-id",
                        run_id,
                        "--output-root",
                        str(output_root),
                    ]
                }
            ],
            "results": [],
        }
        progress = live_job_batch_progress(job)
        self.assertEqual(1, progress["completed_executions"])
        self.assertEqual(1, progress["failed_executions"])
        self.assertEqual(2, progress["finished_executions"])

    def test_isolated_runtime_stages_mapping_and_rag_database(self) -> None:
        source = self.root / "source"
        target = self.root / "target"
        (source / "rag").mkdir(parents=True)
        (source / "field_mapping.json").write_text("{}", encoding="utf-8")
        conn = sqlite3.connect(source / "rag" / "rag_store.db")
        try:
            conn.execute("CREATE TABLE marker(value TEXT)")
            conn.execute("INSERT INTO marker VALUES('ok')")
            conn.execute(
                "CREATE TABLE rag_documents(doc_id TEXT, metadata_json TEXT)"
            )
            conn.execute(
                "INSERT INTO rag_documents VALUES(?,?)",
                ("leak", json.dumps({"md5": "A" * 32})),
            )
            conn.execute(
                "INSERT INTO rag_documents VALUES(?,?)",
                ("safe", json.dumps({"md5": "B" * 32})),
            )
            conn.commit()
        finally:
            conn.close()
        staged = stage_isolated_runtime_assets(
            source, target, excluded_sample_ids={"A" * 32}
        )
        self.assertTrue(staged["field_mapping"])
        self.assertTrue(staged["rag_database"])
        conn = sqlite3.connect(target / "rag" / "rag_store.db")
        try:
            self.assertEqual("ok", conn.execute("SELECT value FROM marker").fetchone()[0])
            self.assertEqual(
                [("safe",)],
                conn.execute("SELECT doc_id FROM rag_documents").fetchall(),
            )
        finally:
            conn.close()
        self.assertEqual(1, staged["rag_documents_excluded"])

    def test_blind_model_input_removes_answer_fields(self) -> None:
        sample = blind_model_input(
            {
                "md5": "A" * 32,
                "app_name": "example",
                "gold_label": "malicious",
                "label_source": "expert",
                "annotation_status": "approved",
                "_gold_label": "malicious",
            }
        )
        self.assertEqual({"md5": "A" * 32, "app_name": "example"}, sample)

    def test_experiment_collector_requires_successful_five_variants(self) -> None:
        data_dir = self.root / "data"
        runs = data_dir / "evaluation" / "five_layer_runs"
        commands = []
        for index in range(5):
            run_id = f"agent-{index}"
            run_dir = runs / run_id
            run_dir.mkdir(parents=True)
            (run_dir / "result.json").write_text(
                json.dumps(
                    {
                        "status": "completed",
                        "completed_this_invocation": 1,
                        "failed_this_invocation": 0,
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "scorecard.json").write_text(
                json.dumps({"metrics": {"malicious_recall": 1.0}}),
                encoding="utf-8",
            )
            (run_dir / "checkpoint.json").write_text(
                json.dumps({"items": {"A": {"status": "completed"}}}),
                encoding="utf-8",
            )
            commands.append(
                {
                    "name": f"variant-{index}",
                    "args": [
                        "run",
                        "--run-id",
                        run_id,
                        "--output-root",
                        str(runs),
                    ],
                }
            )
        jobs = data_dir / "evaluation" / "five_layer_jobs"
        jobs.mkdir(parents=True)
        (jobs / "agent.json").write_text(
            json.dumps(
                {
                    "job_id": "agent",
                    "action": "agent_ablation",
                    "suite_id": "suite-1",
                    "status": "completed",
                    "created_at": "2026-08-03T00:00:00Z",
                    "commands": commands,
                }
            ),
            encoding="utf-8",
        )
        result = collect_five_layer_experiments(
            {"suite_id": "suite-1"}, data_dir
        )
        self.assertEqual("completed", result["agent_ablation"]["status"])
        self.assertEqual(5, result["agent_ablation"]["completed_variants"])

    def test_sample_id_file_accepts_supported_keys_and_normalizes(self) -> None:
        path = self.root / "sample-ids.jsonl"
        self.write_jsonl(
            path,
            [
                {"id": "a" * 32},
                {"sample_id": "B" * 32},
                {"md5": "c" * 32},
                {"id": "a" * 32},
            ],
        )
        self.assertEqual(
            {"A" * 32, "B" * 32, "C" * 32},
            load_requested_sample_ids(path),
        )


if __name__ == "__main__":
    unittest.main()
