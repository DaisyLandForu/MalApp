from __future__ import annotations

import unittest

from malapp.application.judgement import cached_report_usable


class CachedReportModeTest(unittest.TestCase):
    def test_rejects_cross_mode_cache(self) -> None:
        cached = {
            "report_schema_version": "agent-runtime-pipeline-v6.1-decision-provenance",
            "execution": {"orchestration_mode": "v0_fixed"},
            "preprocess": {
                "threat_intelligence": {"ok": True},
                "impersonation_analysis": {"ok": True},
                "business_label_analysis": {"ok": True},
                "agent_output_validation": {"ok": True},
                "agent_runtime": {"ok": True},
            },
            "decision": {"decision_trace": [{}]},
            "evidence_blocks": [],
        }
        self.assertTrue(
            cached_report_usable(
                cached,
                require_learned_agent_scores=False,
                has_valid_md5_for_xgb=False,
                orchestration_mode_name="v0_fixed",
            )
        )
        self.assertFalse(
            cached_report_usable(
                cached,
                require_learned_agent_scores=False,
                has_valid_md5_for_xgb=False,
                orchestration_mode_name="v1_planner",
            )
        )


if __name__ == "__main__":
    unittest.main()
