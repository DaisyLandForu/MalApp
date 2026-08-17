from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from integrations.hermes.bridge import TOOL_DEFINITIONS, TOOL_HANDLERS

ROOT = Path(__file__).resolve().parents[2]


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

    def test_all_domain_tools_return_evidence_blocks(self) -> None:
        expected_agents = {
            "malapp_static_analysis": "static_analysis",
            "malapp_threat_intelligence": "threat_intel",
            "malapp_impersonation_analysis": "impersonation",
            "malapp_business_labeling": "business_label",
        }
        for tool_name, expected_agent in expected_agents.items():
            result = TOOL_HANDLERS[tool_name]({"sample": self.sample})
            block = result["evidence_block"]
            self.assertEqual(block["agent"], expected_agent)
            self.assertIn("claim", block)
            self.assertIsInstance(block["evidence"], list)
            self.assertGreaterEqual(block["confidence"], 0)
            self.assertLessEqual(block["confidence"], 1)

    def test_run_all_agents_returns_four_validated_blocks(self) -> None:
        result = TOOL_HANDLERS["malapp_run_all_agents"]({"sample": self.sample})
        self.assertEqual(len(result["evidence_blocks"]), 4)
        self.assertTrue(result["validation"]["valid"])
        self.assertTrue(result["runtime"]["scheduler"]["concurrent"])

    def test_tool_definitions_have_json_schema(self) -> None:
        self.assertEqual(len(TOOL_DEFINITIONS), 6)
        for definition in TOOL_DEFINITIONS:
            self.assertEqual(definition["inputSchema"]["type"], "object")
            self.assertIn("sample", definition["inputSchema"]["required"])

    def test_mcp_server_initializes_and_lists_tools(self) -> None:
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
        self.assertEqual(len(responses[1]["result"]["tools"]), 6)

    def test_full_judgement_tool_keeps_existing_pipeline(self) -> None:
        report = TOOL_HANDLERS["malapp_full_judgement"]({"sample": self.sample})
        self.assertEqual(len(report["evidence_blocks"]), 4)
        self.assertIn("arbiter", report["debate"])
        self.assertIn(report["decision"]["verdict"], {"malicious", "suspicious", "benign"})


if __name__ == "__main__":
    unittest.main()
