from __future__ import annotations

import unittest
from unittest.mock import patch

from malapp.application.judgement import judge


class DomainAgentIsolationTest(unittest.TestCase):
    def test_threat_domain_timeout_isolated_inside_runtime(self) -> None:
        sample = {
            "sample_id": "domain-timeout-isolation",
            "app_name": "Domain Timeout",
            "package_name": "com.domain.timeout",
            "permissions": ["READ_SMS"],
            "control_url": "https://risk.example.test/c2",
            "engine_a_score": 65,
            "engine_b_score": 62,
            "force_engine_c": True,
            "agent_runtime_config": {
                "default_timeout_ms": 500,
                "agents": {"threat_intel": {"max_retries": 0}},
            },
        }
        environment = {
            "MALAPP_MD5_REPORT_CACHE": "0",
            "MALAPP_RAG_ENABLED": "0",
            "MALAPP_USE_XGB": "0",
        }
        with (
            patch.dict("os.environ", environment),
            patch(
                "malapp.agents.threat_intelligence.analyze_threat_intelligence",
                side_effect=TimeoutError("threat intelligence provider timeout"),
            ),
        ):
            report = judge(sample)

        runtime = report["preprocess"]["agent_runtime"]
        self.assertEqual(
            report["report_schema_version"],
            "agent-runtime-pipeline-v6.1-decision-provenance",
        )
        self.assertEqual(runtime["agents"]["threat_intel"]["status"], "timeout")
        self.assertEqual(runtime["agents"]["threat_intel"]["failure_type"], "timeout")
        self.assertEqual(runtime["agents"]["static_analysis"]["status"], "completed")
        self.assertEqual(runtime["agents"]["impersonation"]["status"], "completed")
        self.assertEqual(runtime["agents"]["business_label"]["status"], "completed")
        self.assertEqual(report["preprocess"]["threat_intelligence"], {})
        self.assertIn(
            "threat_intel_timeout",
            [item["code"] for item in report["degradation"]["reasons"]],
        )
        pipeline = report["execution"]["pipeline"]["by_name"]
        self.assertEqual(pipeline["AGENT_EXECUTION"]["status"], "degraded")
        self.assertEqual(pipeline["DEBATE"]["status"], "completed")
        self.assertEqual(pipeline["FINAL_DECISION"]["status"], "degraded")
        self.assertIn(report["decision"]["verdict"], {"malicious", "suspicious", "benign"})


if __name__ == "__main__":
    unittest.main()
