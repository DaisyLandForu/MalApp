from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from apps.server.app import create_app
from apps.server.config import ServerConfig, load_server_config
from malapp.application.contracts import JudgementRequest
from malapp.application.service import JudgementService


class ApiSecurityTest(unittest.TestCase):
    def config(self, **overrides: object) -> ServerConfig:
        values = {
            "profile": "production",
            "api_key": "user-key",
            "admin_api_key": "admin-key",
            "max_json_bytes": 128,
            "max_upload_bytes": 256,
            "max_query_limit": 10,
            "max_batch_items": 2,
            "max_rag_top_k": 5,
            "max_graph_hops": 2,
            "max_excel_rows": 10,
            "model_allowed_hosts": ("models.example",),
        }
        values.update(overrides)
        return ServerConfig(**values)

    @staticmethod
    def auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def client(self, **overrides: object) -> TestClient:
        return TestClient(
            create_app(self.config(**overrides), initialize_runtime=False),
            raise_server_exceptions=False,
        )

    def test_health_and_web_are_public_but_api_write_requires_bearer(self) -> None:
        with self.client() as client:
            self.assertEqual(client.get("/api/health").status_code, 200)
            self.assertEqual(client.get("/").status_code, 200)
            response = client.post("/api/judgements", json={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers.get("www-authenticate"), "Bearer")

    def test_authenticated_key_cannot_access_admin_route(self) -> None:
        with self.client() as client:
            no_key = client.get("/api/model/settings")
            user_key = client.get("/api/model/settings", headers=self.auth("user-key"))
        self.assertEqual(no_key.status_code, 401)
        self.assertEqual(user_key.status_code, 403)

    def test_admin_response_never_contains_model_api_keys(self) -> None:
        environment = {
            "MALAPP_MODEL_A_API_KEY": "secret-a-value",
            "MALAPP_MODEL_B_API_KEY": "secret-b-value",
        }
        with patch.dict(os.environ, environment, clear=False), self.client() as client:
            response = client.get("/api/model/settings", headers=self.auth("admin-key"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["model_a_api_key"], "")
        self.assertEqual(response.json()["model_b_api_key"], "")
        self.assertNotIn("secret-a-value", response.text)
        self.assertNotIn("secret-b-value", response.text)

    def test_declared_json_and_upload_payloads_are_limited(self) -> None:
        with self.client() as client:
            json_response = client.post(
                "/api/judgements",
                content=b"x" * 129,
                headers={**self.auth("user-key"), "Content-Type": "application/json"},
            )
            upload_response = client.post(
                "/api/data/import-excel",
                content=b"x" * 257,
                headers={**self.auth("admin-key"), "Content-Type": "application/octet-stream"},
            )
        self.assertEqual(json_response.status_code, 413)
        self.assertEqual(upload_response.status_code, 413)

    def test_streamed_payload_is_limited_without_trusting_content_length(self) -> None:
        def chunks():
            yield b"x" * 80
            yield b"y" * 80

        with self.client() as client:
            response = client.post(
                "/api/judgements",
                content=chunks(),
                headers={**self.auth("user-key"), "Content-Type": "application/json"},
            )
        self.assertEqual(response.status_code, 413)

    def test_query_rag_and_batch_limits_are_centralized(self) -> None:
        with self.client() as client:
            reports = client.get("/api/reports?limit=11", headers=self.auth("user-key"))
            metrics = client.get(
                "/api/observability/metrics?limit=11",
                headers=self.auth("user-key"),
            )
            rag = client.post(
                "/api/rag/search",
                json={"query": "risk", "top_k": 6},
                headers=self.auth("user-key"),
            )
            batch = client.post(
                "/api/data/import",
                json={"items": [{}, {}, {}]},
                headers=self.auth("admin-key"),
            )
        self.assertEqual(reports.status_code, 400)
        self.assertEqual(metrics.status_code, 400)
        self.assertEqual(rag.status_code, 400)
        self.assertEqual(batch.status_code, 400)

    def test_production_without_api_key_fails_fast(self) -> None:
        with self.assertRaisesRegex(ValueError, "MALAPP_API_KEY"):
            load_server_config({"MALAPP_PROFILE": "production"})

    def test_transport_cannot_inject_evaluation_ablation_controls(self) -> None:
        request = JudgementRequest.from_payload(
            {
                "sample_id": "evaluation-injection",
                "evaluation_config": {"debate_mode": "no_debate", "xgb_mode": "off"},
            },
            source="web_api",
        )
        with self.assertRaisesRegex(ValueError, "isolated evaluation runner"):
            JudgementService().judge(request)


if __name__ == "__main__":
    unittest.main()
