from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from malapp.inference import settings
from malapp.inference.url_policy import validate_model_endpoint, validate_model_pair
from malapp.orchestration.debate import build_provider


class ModelSecurityTest(unittest.TestCase):
    def test_rejects_unsupported_embedded_and_unlisted_model_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "scheme"):
            validate_model_endpoint("file:///etc/passwd", profile="production", allowed_hosts=("models.example",))
        with self.assertRaisesRegex(ValueError, "embedded credentials"):
            validate_model_endpoint(
                "https://user:password@models.example/v1",
                profile="production",
                allowed_hosts=("models.example",),
            )
        with self.assertRaisesRegex(ValueError, "not allowed"):
            validate_model_endpoint(
                "https://metadata.internal/v1",
                profile="production",
                allowed_hosts=("models.example",),
            )
        self.assertEqual(
            validate_model_endpoint(
                "https://models.example/v1/",
                profile="production",
                allowed_hosts=("models.example",),
            ),
            "https://models.example/v1",
        )

    def test_production_model_pair_requires_allowlist_and_complete_pair(self) -> None:
        payload = {
            "server_models_enabled": True,
            "model_a_api_url": "https://models.example/v1",
            "model_a_model": "model-a",
            "model_b_api_url": "",
            "model_b_model": "",
        }
        with patch.dict(os.environ, {"MALAPP_MODEL_ALLOWED_HOSTS": "models.example"}, clear=False):
            with self.assertRaisesRegex(ValueError, "Model B|model B"):
                validate_model_pair(payload, profile="production")

    def test_secret_fields_are_removed_from_legacy_runtime_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "model_settings.json"
            path.write_text(
                json.dumps(
                    {
                        "server_models_enabled": False,
                        "model_a_api_key": "legacy-secret-a",
                        "model_b_api_key": "legacy-secret-b",
                        "model": "local-model",
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.object(settings, "SETTINGS_PATH", path),
                patch.dict(
                    os.environ,
                    {
                        "MALAPP_MODEL_A_API_KEY": "environment-secret-a",
                        "MALAPP_MODEL_B_API_KEY": "environment-secret-b",
                    },
                    clear=False,
                ),
            ):
                loaded = settings.load_model_settings_without_apply()
            persisted = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["model_a_api_key"], "environment-secret-a")
        self.assertEqual(loaded["model_b_api_key"], "environment-secret-b")
        self.assertNotIn("model_a_api_key", persisted)
        self.assertNotIn("model_b_api_key", persisted)

    def test_settings_api_refuses_secret_persistence(self) -> None:
        with self.assertRaisesRegex(ValueError, "environment variables"):
            settings.update_model_settings({"model_a_api_key": "must-not-persist"})

    def test_disabled_server_models_never_probe_saved_endpoints(self) -> None:
        configured = {
            "server_models_enabled": False,
            "model_a_api_url": "https://models.example/v1",
            "model_a_model": "model-a",
            "model_b_api_url": "https://models.example/v1",
            "model_b_model": "model-b",
            "model_a_api_key": "",
            "model_b_api_key": "",
            "local_qwen_enabled": False,
            "model": "local-model",
        }
        with (
            patch.object(settings, "load_model_settings_without_apply", return_value=configured),
            patch.object(settings, "server_model_status") as remote_status,
            patch.dict(os.environ, {"MALAPP_PROFILE": "demo"}, clear=False),
        ):
            result = settings.model_runtime_status(check_remote=True)
        remote_status.assert_not_called()
        self.assertEqual(result["mode"], "deterministic_evidence")

    def test_judgement_provider_ignores_request_endpoint_and_secret(self) -> None:
        with patch.dict(
            os.environ,
            {"MALAPP_USE_SERVER_MODELS": "0", "MALAPP_USE_LOCAL_QWEN": "0"},
            clear=False,
        ):
            provider = build_provider(
                "model_a",
                {
                    "model_a": {
                        "api_url": "http://169.254.169.254/latest",
                        "api_key": "request-secret",
                    }
                },
            )
        self.assertEqual(provider.backend, "rule")
        self.assertEqual(provider.api_url, "")
        self.assertEqual(provider.api_key, "")


if __name__ == "__main__":
    unittest.main()
