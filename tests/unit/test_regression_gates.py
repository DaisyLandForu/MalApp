from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from malapp.evaluation.gates import evaluate_regression_gate, load_gate_policy

ROOT = Path(__file__).resolve().parents[2]


def scorecard(**metric_overrides):
    metrics = {
        "validation_total": 500,
        "evaluated_total": 500,
        "coverage": 1.0,
        "malicious_recall": 0.99,
        "benign_false_positive_rate": 0.01,
        "structure_success_rate": 1.0,
        "high_confidence_error_count": 1,
        "human_review": {"wrong_rag_citation_count": 0},
    }
    for key, value in metric_overrides.items():
        if key == "wrong_rag_citation_count":
            metrics["human_review"][key] = value
        else:
            metrics[key] = value
    return {
        "validation_sha256": "frozen-benchmark-sha256",
        "metrics": metrics,
    }


def run_gate_cli(tmp_path: Path, baseline: dict, candidate: dict) -> subprocess.CompletedProcess[str]:
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "gate-report.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.evaluation.run_evaluation",
            "gate",
            "--baseline",
            str(baseline_path),
            "--candidate",
            str(candidate_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_regression_gate_pass(tmp_path: Path):
    baseline = scorecard()
    result = evaluate_regression_gate(baseline, copy.deepcopy(baseline), load_gate_policy())
    completed = run_gate_cli(tmp_path, baseline, copy.deepcopy(baseline))

    assert result["status"] == "pass"
    assert result["summary"]["failed"] == 0
    assert result["summary"]["blocked"] == 0
    assert len(result["gate_report_sha256"]) == 64
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["status"] == "pass"


def test_regression_gate_fail(tmp_path: Path):
    baseline = scorecard()
    candidate = scorecard(malicious_recall=0.98, high_confidence_error_count=2)
    result = evaluate_regression_gate(
        baseline,
        candidate,
        load_gate_policy(),
    )
    completed = run_gate_cli(tmp_path, baseline, candidate)

    assert result["status"] == "fail"
    failed = {item["id"] for item in result["checks"] if item["status"] == "fail"}
    assert "malicious_recall_not_below_baseline" in failed
    assert "high_confidence_errors_not_increase" in failed
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["status"] == "fail"


def test_regression_gate_blocked(tmp_path: Path):
    baseline = scorecard()
    candidate = scorecard()
    candidate["validation_sha256"] = "different-benchmark"
    candidate["metrics"]["evaluated_total"] = 499
    candidate["metrics"]["coverage"] = 0.998
    candidate["metrics"]["human_review"].pop("wrong_rag_citation_count")

    result = evaluate_regression_gate(baseline, candidate, load_gate_policy())
    completed = run_gate_cli(tmp_path, baseline, candidate)

    assert result["status"] == "blocked"
    blocked = {item["id"] for item in result["checks"] if item["status"] == "blocked"}
    assert "same_frozen_benchmark" in blocked
    assert "same_evaluated_total" in blocked
    assert "minimum_candidate_coverage" in blocked
    assert "wrong_rag_citations_not_increase" in blocked
    assert completed.returncode == 2
    assert json.loads(completed.stdout)["status"] == "blocked"
