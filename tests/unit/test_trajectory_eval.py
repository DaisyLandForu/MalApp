from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from malapp.evaluation.trajectory import (
    STRATA,
    build_benchmark_manifest,
    extract_trajectory,
    freeze_judge_input,
    input_sha256,
    load_benchmark_manifest,
    run_rule_trajectory_benchmark,
    score_evaluation_payload,
    score_reports,
    score_trajectory,
    summarize_trajectories,
    trajectory_success,
    write_json,
)


def sample_report(mode: str, selected: list[str], skipped: list[str]) -> dict:
    agents = {}
    runtime_lifecycle = []
    for name in selected:
        agents[name] = {
            "status": "completed",
            "failure_type": None,
            "attempts": 1,
            "restart_count": 0,
            "trace": [{"phase": "attempt", "agent": name, "status": "completed", "ts": 2}],
        }
        runtime_lifecycle.extend(
            [
                {"phase": "registered", "agent": name, "ts": 1},
                {"phase": "started", "agent": name, "ts": 2},
                {"phase": "completed", "agent": name, "status": "completed", "ts": 3},
            ]
        )
    for name in skipped:
        agents[name] = {"status": "skipped", "failure_type": "skipped_by_plan", "attempts": 0, "trace": []}
    return {
        "run_id": f"run-{mode}",
        "sample": {"sample_id": "S1"},
        "execution": {"orchestration_mode": mode, "status": "healthy"},
        "decision": {"verdict": "suspicious", "score": 0.6},
        "debate": {
            "execution_mode": "evaluation_no_debate",
            "model_calls": [],
            "providers": {"model_a": {"backend": "not_invoked"}, "model_b": {"backend": "not_invoked"}},
        },
        "evidence_blocks": [
            {
                "agent": name,
                "evidence_id": name,
                "claim": "c",
                "evidence": ["e"],
                "evidence_items": [{"evidence_type": name}],
                "missing_fields": [],
            }
            for name in selected
        ]
        + [
            {
                "agent": name,
                "evidence_id": name,
                "claim": "skipped",
                "evidence": ["skipped"],
                "evidence_items": [{"evidence_type": name}],
                "missing_fields": ["skipped_by_plan"],
                "status": "skipped",
            }
            for name in skipped
        ],
        "preprocess": {
            "agent_runtime": {
                "status": "healthy",
                "agents": agents,
                "lifecycle": runtime_lifecycle,
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
        self.assertFalse(result["invokes_models"])
        variants = comparison["variants"]
        self.assertIn("review_recommended_rate", variants["v0_fixed"])
        self.assertIn("degraded_rate", variants["v0_fixed"])
        self.assertIn("average_confidence_penalty", variants["v0_fixed"])
        self.assertEqual(variants["v1_planner"]["agent_skip_rate"]["impersonation"], 1.0)
        self.assertEqual(variants["v1_planner"]["agent_skip_reasons"]["impersonation"]["skip"], 1)
        self.assertEqual(variants["v1_planner"]["verdict_agreement_rate"], 1.0)

    def test_stratum_summary_reports_skip_reasons_and_agreement(self) -> None:
        v0 = sample_report("v0_fixed", ["static_analysis", "threat_intel", "impersonation", "business_label"], [])
        v1 = sample_report("v1_planner", ["static_analysis"], ["threat_intel", "impersonation", "business_label"])
        v0["sample"]["sample_id"] = "S-ioc"
        v1["sample"]["sample_id"] = "S-ioc"
        result = score_reports([v0, v1], stratum_by_sample={"S-ioc": "ioc"})
        layer = result["comparison"]["by_stratum"]["ioc"]
        self.assertEqual(layer["sample_count"], 1)
        self.assertEqual(layer["variants"]["v1_planner"]["agent_skip_rate"]["threat_intel"], 1.0)
        self.assertEqual(layer["variants"]["v1_planner"]["agent_skip_reasons"]["threat_intel"]["skip"], 1)
        self.assertEqual(layer["variants"]["v1_planner"]["verdict_agreement_rate"], 1.0)
        self.assertEqual(layer["variants"]["v1_planner"]["trajectory_success_rate"], 1.0)

    def test_manifest_freezes_blinded_inputs_and_actual_source(self) -> None:
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
                    "fake_app": "true",
                    "official_pkg": "com.bank",
                }
            )
        source = Path("/tmp/malapp-traj-source.csv")
        manifest = build_benchmark_manifest(
            rows,
            size=120,
            runtime_snapshot_id="runtime-test",
            source=source,
            source_sha256="abc123",
        )
        self.assertGreaterEqual(manifest["size"], 100)
        self.assertLessEqual(manifest["size"], 200)
        self.assertEqual(manifest["source"], str(source))
        self.assertEqual(manifest["source_sha256"], "abc123")
        self.assertEqual(manifest["runtime_snapshot_id"], "runtime-test")
        self.assertTrue(manifest["manifest_sha256"])
        for name in STRATA:
            self.assertGreaterEqual(manifest["strata"][name], 1, name)
        first = manifest["samples"][0]
        self.assertIn("blinded_input", first)
        self.assertEqual(first["input_sha256"], input_sha256(first["blinded_input"]))
        mutated = json.loads(json.dumps(rows))
        mutated[0]["control_url"] = "https://c2.changed.test"
        changed = build_benchmark_manifest(
            mutated,
            size=120,
            runtime_snapshot_id="runtime-test",
            source=source,
            source_sha256="abc123",
        )
        self.assertNotEqual(manifest["manifest_sha256"], changed["manifest_sha256"])

    def test_manifest_requires_strata_or_waiver(self) -> None:
        rows = [{"md5": f"{index:032x}", "_gold_label": "malicious", "control_url": "https://c2.test"} for index in range(120)]
        with self.assertRaises(ValueError):
            build_benchmark_manifest(
                rows,
                size=120,
                runtime_snapshot_id="runtime-test",
                fill_missing_strata=False,
                allow_stratum_waiver=False,
            )
        waived = build_benchmark_manifest(
            rows,
            size=120,
            runtime_snapshot_id="runtime-test",
            fill_missing_strata=False,
            allow_stratum_waiver=True,
        )
        self.assertTrue(waived["stratum_waivers"])

    def test_extract_trajectory_reads_plan_lifecycle(self) -> None:
        report = sample_report("v2_planner_tools", ["static_analysis"], ["threat_intel", "impersonation", "business_label"])
        report["preprocess"]["agent_runtime"]["investigation"]["lifecycle"] = [
            {"phase": "replan_started", "ts": 10},
            {"phase": "replan_finished", "ts": 12},
        ]
        report["preprocess"]["agent_runtime"]["lifecycle"].append(
            {"phase": "started", "agent": "threat_intel", "ts": 11}
        )
        report["preprocess"]["agent_runtime"]["investigation"]["tool_observations"] = [
            {"tool_name": "apk_metadata", "status": "completed", "arguments_valid": True}
        ]
        traj = extract_trajectory(report)
        metrics = score_trajectory(traj)
        self.assertTrue(metrics["replan"])
        self.assertEqual(metrics["tool_calls"], 1)
        self.assertEqual(metrics["agent_calls"], 2)
        self.assertEqual(metrics["replan_agent_calls"], 1)
        self.assertNotEqual(metrics["agent_calls"], metrics["selected_agents"])
        self.assertTrue(metrics["trajectory_success"])
        summary = summarize_trajectories([metrics])
        self.assertIn("Selected Agent Recall", summary["notes"][0])

    def test_trajectory_success_requires_final_gate(self) -> None:
        report = sample_report("v1_planner", ["static_analysis", "threat_intel"], [])
        report["preprocess"]["agent_runtime"]["investigation"]["evidence_gate"] = {"sufficient": False}
        report["preprocess"]["agent_runtime"]["investigation"]["lifecycle"] = [{"phase": "replan_started", "ts": 1}]
        traj = extract_trajectory(report)
        self.assertTrue(str(traj.get("verdict") or ""))
        self.assertFalse(traj["gate"]["sufficient"])
        self.assertFalse(trajectory_success(traj))
        self.assertFalse(score_trajectory(traj)["trajectory_success"])

    def test_coverage_uses_requirements_and_ignores_placeholders(self) -> None:
        report = sample_report("v1_planner", ["static_analysis"], ["threat_intel"])
        traj = extract_trajectory(report)
        metrics = score_trajectory(
            traj,
            expected_evidence_requirements=["static_analysis", "threat_intel"],
        )
        self.assertEqual(metrics["evidence_coverage"], 0.5)
        self.assertEqual(metrics["missing_critical_evidence_rate"], 0.5)
        self.assertLessEqual(metrics["missing_critical_evidence_rate"], 1.0)
        doubled = sample_report("v0_fixed", ["static_analysis"], [])
        doubled["evidence_blocks"][0]["evidence"] = ["a", "b", "c"]
        doubled["evidence_blocks"][0]["evidence_items"] = [
            {"evidence_type": "static_analysis"},
            {"evidence_type": "static_analysis"},
        ]
        same = score_trajectory(
            extract_trajectory(doubled),
            expected_evidence_requirements=["static_analysis"],
        )
        self.assertEqual(same["evidence_coverage"], 1.0)

    def test_tool_argument_valid_is_not_status_proxy(self) -> None:
        traj = extract_trajectory(sample_report("v2_planner_tools", ["static_analysis"], []))
        traj["tool_observations"] = [
            {"tool_name": "network_indicator", "agent": "threat_intel", "status": "denied", "arguments_valid": True},
            {
                "tool_name": "apk_metadata",
                "agent": "static_analysis",
                "status": "completed",
                "arguments_valid": False,
                "argument_errors": ["sample_not_object"],
            },
        ]
        metrics = score_trajectory(traj)
        self.assertEqual(metrics["tool_argument_valid_rate"], 0.5)
        self.assertEqual(metrics["tool_denial_rate"], 0.5)
        self.assertFalse(metrics["trajectory_success"])

    def test_rule_benchmark_compares_v0_v1_v2_without_model_calls(self) -> None:
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
            self.assertEqual(result["isolated_data_dir"], str(Path(workdir).resolve()))
            self.assertTrue((Path(workdir) / "mvp.db").exists())
        self.assertFalse(result["invokes_models"])
        self.assertFalse(result["invokes_api"])
        self.assertEqual(result["backend"], "rule")
        self.assertEqual(result["debate_mode"], "no_debate")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["cache_hits"], 0)
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
            self.assertEqual(item["debate_execution_mode"], "evaluation_no_debate")
            self.assertEqual(item["model_calls"], [])
            self.assertFalse(item["invokes_models"])
            self.assertFalse(item["cache_hit"])
        static_v1 = next(item for item in by_mode["v1_planner"] if item["sample_id"] == "p9-static-only")
        self.assertIn("threat_intel", static_v1["skipped_agents"])
        ioc_v2 = next(item for item in by_mode["v2_planner_tools"] if item["sample_id"] == "p9-ioc")
        self.assertGreater(ioc_v2["metrics"]["tool_calls"], 0)
        self.assertTrue(any(obs.get("tool_name") == "network_indicator" for obs in ioc_v2["tool_observations"]))
        self.assertTrue(all(obs.get("arguments_valid") for obs in ioc_v2["tool_observations"]))
        v1_ioc = next(item for item in by_mode["v1_planner"] if item["sample_id"] == "p9-ioc")
        if not v1_ioc["gate"].get("sufficient", True):
            self.assertFalse(v1_ioc["metrics"]["trajectory_success"])

    def test_replay_manifest_roundtrip(self) -> None:
        rows = [
            {
                "md5": "aa" * 16,
                "_gold_label": "malicious",
                "package_name": "com.example.app",
                "control_url": "https://c2.example.test/gate",
            }
        ]
        with tempfile.TemporaryDirectory() as workdir:
            path = Path(workdir) / "trajectory_benchmark.json"
            manifest = build_benchmark_manifest(
                rows,
                size=1,
                min_size=1,
                max_size=8,
                runtime_snapshot_id="runtime-replay",
                source=path,
                source_sha256=hashlib.sha256(b"csv").hexdigest(),
            )
            path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            loaded = load_benchmark_manifest(path)
            self.assertEqual(loaded["manifest_sha256"], manifest["manifest_sha256"])
            self.assertEqual(freeze_judge_input(loaded["samples"][0]["blinded_input"])["control_url"], "https://c2.example.test/gate")
            tampered = json.loads(path.read_text(encoding="utf-8"))
            tampered["samples"][0]["blinded_input"]["control_url"] = "https://evil.test"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_benchmark_manifest(path)

    def test_trajectory_success_requires_explicit_gate_and_rejects_denied_or_invalid_args(self) -> None:
        traj = extract_trajectory(sample_report("v0_fixed", ["static_analysis"], []))
        self.assertTrue(trajectory_success(traj))
        missing_gate = dict(traj)
        missing_gate["gate"] = {}
        self.assertFalse(trajectory_success(missing_gate))
        denied = dict(traj)
        denied["tool_observations"] = [
            {"tool_name": "network_indicator", "agent": "threat_intel", "status": "denied", "arguments_valid": True}
        ]
        self.assertFalse(trajectory_success(denied))
        invalid_args = dict(traj)
        invalid_args["tool_observations"] = [
            {
                "tool_name": "apk_metadata",
                "agent": "static_analysis",
                "status": "completed",
                "arguments_valid": False,
            }
        ]
        self.assertFalse(trajectory_success(invalid_args))

    def test_generated_trajectory_score_file_roundtrips_sample_ids_and_success(self) -> None:
        v0 = sample_report("v0_fixed", ["static_analysis", "threat_intel", "impersonation", "business_label"], [])
        v1 = sample_report("v1_planner", ["static_analysis", "threat_intel"], ["impersonation", "business_label"])
        first = score_reports(
            [v0, v1],
            requirements_by_sample={"S1": ["static_analysis", "threat_intel"]},
        )
        self.assertEqual([item["sample_id"] for item in first["trajectories"]], ["S1", "S1"])
        self.assertTrue(first["trajectories"][0]["metrics"]["trajectory_success"])
        with tempfile.TemporaryDirectory() as workdir:
            reports_path = Path(workdir) / "trajectory_score.json"
            output_path = Path(workdir) / "trajectory_score_roundtrip.json"
            write_json(
                reports_path,
                {
                    "manifest_sha256": "roundtrip",
                    "comparison": first["comparison"],
                    "trajectories": first["trajectories"],
                },
            )
            second = score_evaluation_payload(json.loads(reports_path.read_text(encoding="utf-8")))
            self.assertEqual([item["sample_id"] for item in second["trajectories"]], ["S1", "S1"])
            self.assertEqual(
                second["comparison"]["variants"]["v0_fixed"]["trajectory_success_rate"],
                first["comparison"]["variants"]["v0_fixed"]["trajectory_success_rate"],
            )
            self.assertEqual(
                second["comparison"]["variants"]["v1_planner"]["average_selected_agents"],
                first["comparison"]["variants"]["v1_planner"]["average_selected_agents"],
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/evaluation/run_evaluation.py",
                    "trajectory-score",
                    "--reports",
                    str(reports_path),
                    "--output",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).resolve().parents[2]),
            )
            self.assertIn("trajectory_success_rate", completed.stdout)
            cli_result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual([item["sample_id"] for item in cli_result["trajectories"]], ["S1", "S1"])
            self.assertTrue(cli_result["trajectories"][0]["metrics"]["trajectory_success"])
            self.assertEqual(
                cli_result["comparison"]["variants"]["v0_fixed"]["trajectory_success_rate"],
                first["comparison"]["variants"]["v0_fixed"]["trajectory_success_rate"],
            )

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
