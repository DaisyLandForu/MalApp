from __future__ import annotations

import copy

from malapp.evaluation.gates import evaluate_regression_gate, load_gate_policy


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


def test_identical_candidate_passes_default_policy():
    baseline = scorecard()
    result = evaluate_regression_gate(baseline, copy.deepcopy(baseline), load_gate_policy())

    assert result["status"] == "pass"
    assert result["summary"]["failed"] == 0
    assert result["summary"]["blocked"] == 0
    assert len(result["gate_report_sha256"]) == 64


def test_quality_regression_fails_gate():
    result = evaluate_regression_gate(
        scorecard(),
        scorecard(malicious_recall=0.98, high_confidence_error_count=2),
        load_gate_policy(),
    )

    assert result["status"] == "fail"
    failed = {item["id"] for item in result["checks"] if item["status"] == "fail"}
    assert "malicious_recall_not_below_baseline" in failed
    assert "high_confidence_errors_not_increase" in failed


def test_non_comparable_or_incomplete_scorecard_is_blocked():
    candidate = scorecard()
    candidate["validation_sha256"] = "different-benchmark"
    candidate["metrics"]["evaluated_total"] = 499
    candidate["metrics"]["coverage"] = 0.998
    candidate["metrics"]["human_review"].pop("wrong_rag_citation_count")

    result = evaluate_regression_gate(scorecard(), candidate, load_gate_policy())

    assert result["status"] == "blocked"
    blocked = {item["id"] for item in result["checks"] if item["status"] == "blocked"}
    assert "same_frozen_benchmark" in blocked
    assert "same_evaluated_total" in blocked
    assert "minimum_candidate_coverage" in blocked
    assert "wrong_rag_citations_not_increase" in blocked
