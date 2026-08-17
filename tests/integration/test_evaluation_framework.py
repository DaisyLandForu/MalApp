from __future__ import annotations

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from malapp.evaluation.framework import (
    build_rag_retrieval_scorecard,
    build_scorecard,
    freeze_evaluation_manifest,
    generate_evaluation_datasets,
    normalize_error_types,
)


class EvaluationFrameworkTest(unittest.TestCase):
    def setUp(self) -> None:
        test_tmp = Path(__file__).resolve().parents[1] / ".test_tmp"
        test_tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_tmp)
        self.root = Path(self.temp.name)
        self.csv_path = self.root / "validation.csv"
        with self.csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "md5",
                    "gold_label",
                    "app_name",
                    "package_name",
                    "label_source",
                    "xgb_probability",
                    "engine_360_score",
                    "engine_cm_score",
                ],
            )
            writer.writeheader()
            writer.writerows(
                [
                    {
                        "md5": "A",
                        "gold_label": "malicious",
                        "app_name": "bad-a",
                        "package_name": "pkg.a",
                        "label_source": "expert",
                        "xgb_probability": "0.95",
                        "engine_360_score": "95",
                        "engine_cm_score": "90",
                    },
                    {
                        "md5": "B",
                        "gold_label": "malicious",
                        "app_name": "bad-b",
                        "package_name": "pkg.b",
                        "label_source": "manual_conflict",
                        "xgb_probability": "0.55",
                        "engine_360_score": "90",
                        "engine_cm_score": "20",
                    },
                    {
                        "md5": "C",
                        "gold_label": "benign",
                        "app_name": "good-c",
                        "package_name": "pkg.c",
                        "label_source": "expert",
                        "xgb_probability": "0.05",
                        "engine_360_score": "5",
                        "engine_cm_score": "10",
                    },
                    {
                        "md5": "D",
                        "gold_label": "benign",
                        "app_name": "good-d",
                        "package_name": "pkg.d",
                        "label_source": "expert",
                        "xgb_probability": "0.45",
                        "engine_360_score": "50",
                        "engine_cm_score": "55",
                    },
                ]
            )
        self.db_path = self.root / "mvp.db"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE judgements (
                    id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            for report in (
                self.report("r-a", "A", "malicious", 0.9, 1000),
                self.report("r-b", "B", "benign", 0.2, 3000),
                self.report("r-c", "C", "benign", 0.1, 2000),
            ):
                conn.execute(
                    "INSERT INTO judgements(id,payload_json,created_at) VALUES(?,?,?)",
                    (report["report_id"], json.dumps(report), report["created_at"]),
                )
            conn.execute(
                """
                CREATE TABLE human_reviews (
                    review_id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            review = {
                "review_id": "review-a",
                "report_id": "r-a",
                "md5": "A",
                "evidence_supported": True,
                "json_valid": True,
                "concise": False,
                "punctuation_valid": True,
                "hallucination": False,
            }
            conn.execute(
                "INSERT INTO human_reviews(review_id,report_id,created_at,payload_json) VALUES(?,?,?,?)",
                ("review-a", "r-a", "2026-07-30T00:00:00+00:00", json.dumps(review)),
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def report(
        report_id: str,
        md5: str,
        verdict: str,
        score: float,
        latency_ms: int,
    ) -> dict:
        return {
            "report_id": report_id,
            "created_at": "2026-07-30T00:00:00+00:00",
            "sample": {"md5": md5},
            "evidence_blocks": [
                {"agent": name, "evidence_items": [{"description": "e"}]}
                for name in ("static_analysis", "threat_intel", "impersonation", "business_label")
            ],
            "evidence_layers": {
                "rag_context": {
                    "enabled": True,
                    "query": f"query-{md5}",
                    "items": [{"doc_id": f"doc-{md5}"}],
                }
            },
            "debate": {
                "arbiter": {"verdict": verdict},
                "metrics": {"latency_ms": latency_ms},
                "stages": [],
            },
            "decision": {"verdict": verdict, "final_score": score},
            "execution": {},
        }

    def test_scorecard_reports_quality_calibration_and_latency(self) -> None:
        result = build_scorecard(self.csv_path, self.root)
        metrics = result["metrics"]

        self.assertEqual(4, metrics["validation_total"])
        self.assertEqual(3, metrics["evaluated_total"])
        self.assertEqual(1, metrics["pending_total"])
        self.assertEqual(2, metrics["correct"])
        self.assertEqual(1, metrics["incorrect"])
        self.assertEqual(0.5, metrics["malicious_recall"])
        self.assertEqual(0.0, metrics["benign_false_positive_rate"])
        self.assertEqual(2000.0, metrics["latency_ms"]["p50"])
        self.assertEqual(3, metrics["calibration"]["count"])
        self.assertEqual(1, metrics["error_counts"]["false_negative"])
        self.assertEqual(1, metrics["human_review"]["reviewed_reports"])
        self.assertEqual(1.0, metrics["human_review"]["evidence_faithfulness_rate"])
        self.assertEqual(0.0, metrics["human_review"]["hallucination_rate"])

    def test_rag_retrieval_scorecard_uses_only_approved_annotations(self) -> None:
        rag_path = self.root / "rag.jsonl"
        rows = [
            {
                "annotation_status": "approved",
                "retrieved_doc_ids": ["noise", "right", "also-right"],
                "relevant_doc_ids": ["right", "also-right"],
            },
            {
                "annotation_status": "pending",
                "retrieved_doc_ids": [],
                "relevant_doc_ids": ["ignored"],
            },
        ]
        rag_path.write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n",
            encoding="utf-8",
        )
        result = build_rag_retrieval_scorecard(rag_path)
        self.assertTrue(result["valid"])
        self.assertEqual(1, result["approved_rows"])
        self.assertEqual(1.0, result["metrics"]["recall_at_5"])
        self.assertEqual(0.5, result["metrics"]["mrr"])
        self.assertAlmostEqual(2 / 3, result["metrics"]["context_precision"], places=6)

    def test_freeze_manifest_and_annotation_candidates(self) -> None:
        manifest = freeze_evaluation_manifest(
            name="test-v1",
            validation_csv=self.csv_path,
            data_dir=self.root,
        )
        self.assertEqual("frozen", manifest["status"])
        self.assertEqual(4, manifest["counts"]["total"])
        self.assertEqual(3, manifest["counts"]["judged"])
        self.assertTrue(Path(manifest["path"]).exists())

        datasets = generate_evaluation_datasets(
            validation_csv=self.csv_path,
            data_dir=self.root,
            core_size=2,
            challenge_size=2,
            rag_size=2,
        )
        self.assertEqual(2, datasets["counts"]["expert_core_candidates"])
        self.assertEqual(2, datasets["counts"]["challenge_candidates"])
        self.assertEqual(2, datasets["counts"]["rag_retrieval_candidates"])
        self.assertEqual(0, datasets["leakage_audit"]["core_challenge_id_overlap"])
        self.assertEqual(0, datasets["leakage_audit"]["core_challenge_group_overlap"])
        core_path = Path(datasets["files"]["expert_core_candidates"])
        first = json.loads(core_path.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual("pending", first["annotation_status"])
        self.assertIsNone(first["gold_label"])

    def test_error_taxonomy_rejects_unknown_values(self) -> None:
        self.assertEqual(
            ["false_negative", "schema_error"],
            normalize_error_types(["false_negative", "schema_error"]),
        )
        with self.assertRaises(ValueError):
            normalize_error_types(["made_up_error"])


if __name__ == "__main__":
    unittest.main()
