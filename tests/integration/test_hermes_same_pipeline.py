from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.server.app import create_app
from apps.server.config import load_server_config
from integrations.hermes.adapter import HermesAdapter
from malapp.application import batch
from malapp.orchestration.pipeline import PIPELINE_STAGES


class HermesSamePipelineTest(unittest.TestCase):
    def test_web_batch_and_hermes_use_same_decision_chain(self) -> None:
        base = {
            "app_name": "Same Pipeline Wallet",
            "package_name": "com.same.pipeline.wallet",
            "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
            "control_url": "https://risk.example.test/c2",
            "engine_a_score": 75,
            "engine_b_score": 68,
        }
        with patch.dict("os.environ", {"MALAPP_MD5_REPORT_CACHE": "0"}):
            app = create_app(
                load_server_config({"MALAPP_PROFILE": "demo"}),
                initialize_runtime=False,
            )
            with TestClient(app) as client:
                response = client.post("/api/judgements", json={**base, "sample_id": "same-web"})
            self.assertEqual(response.status_code, 201)
            web = response.json()
            batch_report = batch.judge({**base, "sample_id": "same-batch"})
            hermes = HermesAdapter().judge({"sample": {**base, "sample_id": "same-hermes"}})

        reports = [web, batch_report, hermes]
        self.assertEqual({item["decision"]["verdict"] for item in reports}, {web["decision"]["verdict"]})
        self.assertEqual(
            {item["execution"]["service_pipeline"] for item in reports},
            {"malapp.agent-runtime.v2"},
        )
        self.assertEqual(
            [item["execution"]["entrypoint"] for item in reports],
            ["web_api", "batch", "hermes_mcp"],
        )
        for report in reports:
            self.assertEqual(report["execution"]["pipeline"]["stage_order"], list(PIPELINE_STAGES))
            self.assertEqual(report["execution"]["orchestrator"], "agent_runtime")
            self.assertTrue(
                all(
                    stage["status"] in {"completed", "failed", "degraded", "skipped"}
                    for stage in report["execution"]["pipeline"]["stages"]
                )
            )
            self.assertTrue(
                all(state["trace"] for state in report["preprocess"]["agent_runtime"]["agents"].values())
            )


if __name__ == "__main__":
    unittest.main()
