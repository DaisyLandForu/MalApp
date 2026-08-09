from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from contextlib import closing
from unittest.mock import patch

from engine import batch_judgement, dashboard, preprocess


class BatchJudgementTest(unittest.TestCase):
    def test_retryable_schema_failure_is_retried_once(self) -> None:
        report = {
            "report_id": "retry-success",
            "decision": {"verdict": "malicious", "risk_level": "high", "final_score": 0.91},
            "execution": {"orchestrator": "hermes"},
        }
        with (
            patch.object(batch_judgement, "load_feature_context", return_value={"md5": "A" * 32}),
            patch.object(
                batch_judgement,
                "judge",
                side_effect=[
                    RuntimeError("output did not satisfy debate schema at closing_statement"),
                    report,
                ],
            ) as mocked_judge,
            patch.object(batch_judgement.time, "sleep"),
            patch.dict(os.environ, {"MALAPP_BATCH_ITEM_MAX_ATTEMPTS": "2"}),
        ):
            outcome = batch_judgement._judge_job_item("job-test", "A" * 32)

        self.assertTrue(outcome["ok"])
        self.assertEqual(2, outcome["attempts"])
        self.assertEqual(2, mocked_judge.call_count)

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.runtime_ready_patcher = patch.object(
            batch_judgement,
            "ensure_runtime_ready_for_judgement",
            return_value={"ready": True, "mode": "unit_test"},
        )
        self.runtime_ready_patcher.start()
        data_dir = Path(self.temp_dir.name)
        self.db_path = data_dir / "mvp.db"
        self.originals = {
            "preprocess_data_dir": preprocess.DATA_DIR,
            "preprocess_db_path": preprocess.DB_PATH,
            "preprocess_bloom_path": preprocess.BLOOM_PATH,
            "dashboard_data_dir": dashboard.DATA_DIR,
            "dashboard_db_path": dashboard.DB_PATH,
            "batch_judge_workers": os.environ.get("MALAPP_BATCH_JUDGE_WORKERS"),
        }
        os.environ["MALAPP_BATCH_JUDGE_WORKERS"] = "1"
        preprocess.DATA_DIR = data_dir
        preprocess.DB_PATH = self.db_path
        preprocess.BLOOM_PATH = data_dir / "sample_seen.bloom"
        dashboard.DATA_DIR = data_dir
        dashboard.DB_PATH = self.db_path
        preprocess.FIELD_REGISTRY_CACHE.clear()
        batch_judgement.JOBS.clear()
        batch_judgement.CONTROLS.clear()

    def tearDown(self) -> None:
        self.runtime_ready_patcher.stop()
        preprocess.DATA_DIR = self.originals["preprocess_data_dir"]
        preprocess.DB_PATH = self.originals["preprocess_db_path"]
        preprocess.BLOOM_PATH = self.originals["preprocess_bloom_path"]
        dashboard.DATA_DIR = self.originals["dashboard_data_dir"]
        dashboard.DB_PATH = self.originals["dashboard_db_path"]
        if self.originals["batch_judge_workers"] is None:
            os.environ.pop("MALAPP_BATCH_JUDGE_WORKERS", None)
        else:
            os.environ["MALAPP_BATCH_JUDGE_WORKERS"] = self.originals["batch_judge_workers"]
        preprocess.FIELD_REGISTRY_CACHE.clear()
        batch_judgement.JOBS.clear()
        batch_judgement.CONTROLS.clear()
        self.temp_dir.cleanup()

    def test_import_n_records_and_judge_only_m_from_same_batch(self) -> None:
        records = [
            {"MD5": "A" * 32, "应用名称": "样本一", "包名": "com.demo.one"},
            {"md5": "B" * 32, "appName": "样本二", "pkgName": "com.demo.two"},
            {"MD5": "C" * 32, "应用名称": "样本三", "控制端地址": "c2.example"},
        ]
        imported = dashboard.import_feature_records(records, source="unit_test")
        self.assertEqual(3, imported["batch_count"])

        def fake_judge(sample):
            return {
                "report_id": f"report-{sample['md5']}",
                "decision": {
                    "verdict": "suspicious",
                    "risk_level": "medium",
                    "final_score": 0.6,
                },
            }

        with patch.object(batch_judgement, "judge", side_effect=fake_judge):
            job = batch_judgement.start_batch_judgement(imported["batch_id"], 2)
            deadline = time.time() + 5
            while time.time() < deadline:
                job = batch_judgement.get_batch_job(job["job_id"])
                if job["status"] == "completed":
                    break
                time.sleep(0.02)
            time.sleep(0.05)

        self.assertEqual("completed", job["status"])
        self.assertEqual(2, job["total"])
        self.assertEqual(2, job["succeeded"])
        with closing(sqlite3.connect(self.db_path)) as conn:
            statuses = dict(
                conn.execute(
                    "SELECT status, COUNT(*) FROM sample_tasks GROUP BY status"
                ).fetchall()
            )
        self.assertEqual(2, statuses.get("completed"))
        self.assertEqual(1, statuses.get("pending"))

    def test_pause_and_resume_keeps_persistent_progress(self) -> None:
        records = [
            {"MD5": char * 32, "应用名称": f"暂停样本{index}"}
            for index, char in enumerate(("D", "E", "F"), start=1)
        ]
        imported = dashboard.import_feature_records(records, source="pause_test")
        entered = threading.Event()
        release = threading.Event()

        def controlled_judge(sample):
            if not entered.is_set():
                entered.set()
                release.wait(timeout=5)
            return {
                "report_id": f"report-{sample['md5']}",
                "decision": {
                    "verdict": "benign",
                    "risk_level": "low",
                    "final_score": 0.2,
                },
                "execution": {"orchestrator": "hermes", "history_reused": False},
            }

        with patch.object(batch_judgement, "judge", side_effect=controlled_judge):
            job = batch_judgement.start_batch_judgement(imported["batch_id"], 3)
            self.assertTrue(entered.wait(timeout=3))
            batch_judgement.pause_batch_judgement(job["job_id"])
            release.set()
            deadline = time.time() + 5
            while time.time() < deadline:
                job = batch_judgement.get_batch_job(job["job_id"])
                if job["status"] == "paused":
                    break
                time.sleep(0.02)
            self.assertEqual("paused", job["status"])
            self.assertEqual(1, job["processed"])

            batch_judgement.JOBS.clear()
            persisted = batch_judgement.get_batch_job(job["job_id"])
            self.assertEqual("paused", persisted["status"])
            batch_judgement.resume_batch_judgement(job["job_id"])
            deadline = time.time() + 5
            while time.time() < deadline:
                job = batch_judgement.get_batch_job(job["job_id"])
                if job["status"] == "completed":
                    break
                time.sleep(0.02)

        self.assertEqual("completed", job["status"])
        self.assertEqual(3, job["processed"])
        self.assertEqual(3, job["succeeded"])

    def test_report_record_is_reused_after_expiry_time(self) -> None:
        sample = {"md5": "9" * 32, "app_name": "历史复用样本"}
        report = {
            "report_id": "saved-report",
            "sample": sample,
            "preprocess": {
                "threat_intelligence": {},
                "impersonation_analysis": {},
                "business_label_analysis": {},
                "agent_output_validation": {},
                "agent_runtime": {},
            },
            "decision": {"decision_trace": []},
        }
        preprocess.set_cached_report(sample, report)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "UPDATE report_cache SET expires_at = '2000-01-01T00:00:00+00:00'"
            )
            conn.commit()
        reused = preprocess.get_cached_report(sample)
        self.assertEqual("saved-report", reused["report_id"])

    def test_interrupted_running_job_recovers_as_paused(self) -> None:
        records = [{"MD5": "8" * 32, "应用名称": "重启恢复样本"}]
        imported = dashboard.import_feature_records(records, source="recovery_test")
        with patch.object(batch_judgement, "launch_worker"):
            job = batch_judgement.start_batch_judgement(imported["batch_id"], 1)
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "UPDATE batch_job_items SET status='processing' WHERE job_id=?",
                (job["job_id"],),
            )
            conn.commit()
        batch_judgement.JOBS.clear()
        recovered = batch_judgement.recover_interrupted_jobs()
        job = batch_judgement.get_batch_job(job["job_id"])
        self.assertEqual(1, recovered)
        self.assertEqual("paused", job["status"])


if __name__ == "__main__":
    unittest.main()
