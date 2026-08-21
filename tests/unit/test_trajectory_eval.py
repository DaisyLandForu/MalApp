from __future__ import annotations

import unittest

from malapp.evaluation.trajectory import (
    build_benchmark_manifest,
    extract_trajectory,
    run_rule_trajectory_benchmark,
    score_reports,
    score_trajectory,
    summarize_trajectories,
)


def sample_report(mode: str, selected: list[str], skipped: list[str]) -> dict:
    agents = {}
    for name in selected:
        agents[name] = {"status": "completed", "failure_type": None}
    for name in skipped:
        agents[name] = {"status": "skipped", "failure_type": "skipped_by_plan"}
    return {
        "run_id": f"run-{mode}",
        "sample": {"sample_id": "S1"},
        "execution": {"orchestration_mode": mode},
        "decision": {"verdict": "suspicious", "score": 0.6},
        "debate": {"execution_mode": "rule", "model_calls": []},
        "evidence_blocks": [
            {"agent": name, "claim": "c", "evidence": ["e"], "evidence_items": [{}], "missing_fields": []}
            for name in selected
        ]
        + [
            {"agent": name, "claim": "skipped", "evidence": ["skipped"], "evidence_items": [{}], "missing_fields": ["skipped_by_plan"]}
            for name in skipped
        ],
        "preprocess": {
            "agent_runtime": {
                "agents": agents,
                "investigation": {
                    "orchestration_mode": mode,
                    "plan": {
                        "fallback": False,
                        "agents": {
                            **{name: {"enabled": True, "reason_code": "x"} for name in selected},
                            **{name: {"enabled": False, "reason_code": "skip"} for name in skipped},
                        },
                    },
                    "lifecycle": [],
                    "evidence_gate": {"sufficient": True},
                },
                "results": [],
            }
        },
    }


class TrajectoryEvalTest(unittest.TestCase):
    def test_scores_existing_reports_without_model_calls(self) -> None:
        v0 = sample_report("v0_fixed", ["static_analysis", "threat_intel", "impersonation", "business_label"], [])
        v1 = sample_report("v1_planner", ["static_analysis", "threat_intel"], ["impersonation", "business_label"])
        result = score_reports([v0, v1])
        comparison = result["comparison"]
        self.assertEqual(comparison["variants"]["v0_fixed"]["average_selected_agents"], 4.0)
        self.assertEqual(comparison["variants"]["v1_planner"]["average_selected_agents"], 2.0)
        self.assertIn("average_selected_agents", comparison["deltas_vs_v0"]["v1_planner"])
        self.assertEqual(
            result["trajectories"][0]["metrics"]["token_usage"]["note"],
            "rule_backend_tokens_omitted",
        )

    def test_manifest_is_capped_and_stratified(self) -> None:
        rows = []
        for index in range(80):
            rows.append({"md5": f"{index:032x}", "_gold_label": "malicious", "control_url": "https://c2.test"})
        for index in range(80, 160):
            rows.append({"md5": f"{index:032x}", "_gold_label": "benign", "package_name": "com.app"})
        for index in range(160, 220):
            rows.append(
                {
                    "md5": f"{index:032x}",
                    "_gold_label": "malicious",
                    "fake_app": "1",
                    "official_pkg": "com.bank",
                }
            )
        manifest = build_benchmark_manifest(rows, size=120)
        self.assertGreaterEqual(manifest["size"], 100)
        self.assertLessEqual(manifest["size"], 200)
        self.assertTrue(manifest["manifest_sha256"])
        self.assertGreater(manifest["strata"]["ioc"], 0)
        self.assertGreater(manifest["strata"]["impersonation"], 0)

    def test_extract_trajectory_reads_plan_lifecycle(self) -> None:
        report = sample_report("v2_planner_tools", ["static_analysis"], ["threat_intel", "impersonation", "business_label"])
        report["preprocess"]["agent_runtime"]["investigation"]["lifecycle"] = [
            {"phase": "replan_started"},
            {"phase": "replan_finished"},
        ]
        report["preprocess"]["agent_runtime"]["investigation"]["tool_observations"] = [
            {"tool_name": "apk_metadata", "status": "completed"}
        ]
        traj = extract_trajectory(report)
        metrics = score_trajectory(traj)
        self.assertTrue(metrics["replan"])
        self.assertEqual(metrics["tool_calls"], 1)
        self.assertTrue(metrics["trajectory_success"])
        summary = summarize_trajectories([metrics])
        self.assertIn("Selected Agent Recall", summary["notes"][0])

    def test_rule_benchmark_compares_v0_v1_v2_without_model_calls(self) -> None:
        import tempfile

        samples = [
            {
                "sample_id": "p9-static-only",
                "package_name": "com.example.app",
                "signature_status": "valid",
                "certificate_fingerprint": "abc",
            },
            {
                "sample_id": "p9-ioc",
                "package_name": "com.example.app",
                "signature_status": "valid",
                "control_url": "https://c2.example.test/gate",
            },
        ]
        with tempfile.TemporaryDirectory(prefix="malapp-traj-test-") as workdir:
            result = run_rule_trajectory_benchmark(samples, data_dir=workdir)
        self.assertFalse(result["invokes_models"])
        self.assertEqual(result["backend"], "rule")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["sample_count"], 2)
        comparison = result["comparison"]
        self.assertEqual(comparison["variants"]["v0_fixed"]["average_selected_agents"], 4.0)
        self.assertLess(
            comparison["variants"]["v1_planner"]["average_selected_agents"],
            comparison["variants"]["v0_fixed"]["average_selected_agents"],
        )
        self.assertGreater(comparison["variants"]["v2_planner_tools"]["average_tool_calls"], 0)
        self.assertIn("v1_planner", comparison["deltas_vs_v0"])
        self.assertIn("v2_planner_tools", comparison["deltas_vs_v0"])
        by_mode: dict[str, list] = {}
        for item in result["trajectories"]:
            by_mode.setdefault(item["orchestration_mode"], []).append(item)
            self.assertEqual(item["metrics"]["token_usage"].get("note"), "rule_backend_tokens_omitted")
        static_v1 = next(
            item for item in by_mode["v1_planner"] if item["sample_id"] == "p9-static-only"
        )
        self.assertIn("threat_intel", static_v1["skipped_agents"])
        ioc_v2 = next(item for item in by_mode["v2_planner_tools"] if item["sample_id"] == "p9-ioc")
        self.assertGreater(ioc_v2["metrics"]["tool_calls"], 0)
        self.assertTrue(any(obs.get("tool_name") == "network_indicator" for obs in ioc_v2["tool_observations"]))

    def test_existing_regression_gate_policy_is_unchanged(self) -> None:
        from malapp.evaluation.gates import load_gate_policy

        policy = load_gate_policy()
        self.assertEqual(
            [item["id"] for item in policy["gates"]],
            [
                "malicious_recall_not_below_baseline",
                "benign_fpr_no_significant_increase",
                "structured_output_success",
                "high_confidence_errors_not_increase",
                "wrong_rag_citations_not_increase",
            ],
        )


if __name__ == "__main__":
    unittest.main()
