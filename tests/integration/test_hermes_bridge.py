from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from integrations.hermes.adapter import HermesAdapter, hermes_status
from integrations.hermes.bridge import TOOL_DEFINITIONS, TOOL_HANDLERS
from malapp.application.contracts import JudgementRequest

ROOT = Path(__file__).resolve().parents[2]


class RecordingService:
    def __init__(self):
        self.request: JudgementRequest | None = None

    def judge(self, request: JudgementRequest) -> dict:
        self.request = request
        return {"ok": True, "source": request.source, "sample": request.sample}


class HermesBridgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sample = {
            "sample_id": "hermes-bridge-test",
            "package_name": "com.fake.wallet",
            "app_name": "Secure Wallet",
            "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
            "control_url": "https://c2-risk.example.net/checkin",
            "fraud_family": "wallet-fraud",
            "engine_a_score": 82,
            "engine_b_score": 76,
        }

    def test_adapter_only_converts_to_judgement_request(self) -> None:
        service = RecordingService()
        result = HermesAdapter(service=service).judge({"sample": self.sample})
        self.assertTrue(result["ok"])
        self.assertIsNotNone(service.request)
        self.assertEqual(service.request.source, "hermes_mcp")
        self.assertEqual(service.request.sample, self.sample)

    def test_only_authoritative_judgement_tool_is_exposed(self) -> None:
        self.assertEqual(list(TOOL_HANDLERS), ["malapp_full_judgement"])
        self.assertEqual(len(TOOL_DEFINITIONS), 1)
        definition = TOOL_DEFINITIONS[0]
        self.assertEqual(definition["name"], "malapp_full_judgement")
        self.assertEqual(definition["inputSchema"]["type"], "object")
        self.assertIn("sample", definition["inputSchema"]["required"])

    def test_mcp_server_initializes_and_lists_one_tool(self) -> None:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        payload = "".join(json.dumps(item) + "\n" for item in requests)
        completed = subprocess.run(
            [sys.executable, str(ROOT / "integrations" / "hermes" / "mcp_server.py")],
            input=payload,
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=20,
            check=True,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "malapp-hermes-tools")
        self.assertEqual(len(responses[1]["result"]["tools"]), 1)

    def test_full_judgement_tool_uses_authoritative_service(self) -> None:
        report = TOOL_HANDLERS["malapp_full_judgement"]({"sample": self.sample})
        self.assertEqual(len(report["evidence_blocks"]), 4)
        self.assertEqual(report["execution"]["entrypoint"], "hermes_mcp")
        self.assertEqual(report["execution"]["orchestrator"], "agent_runtime")
        self.assertEqual(report["execution"]["service_pipeline"], "malapp.agent-runtime.v2")

    def test_status_declares_adapter_not_orchestrator(self) -> None:
        status = hermes_status()
        self.assertEqual(status["mode"], "judgement_service_adapter")
        self.assertFalse(status["capabilities"]["agent_orchestration"])


if __name__ == "__main__":
    unittest.main()
