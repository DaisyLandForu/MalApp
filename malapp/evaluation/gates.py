from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[1]
    / "config"
    / "defaults"
    / "eval"
    / "regression_gate.json"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def load_gate_policy(path: Path | None = None) -> dict[str, Any]:
    source = (path or DEFAULT_POLICY_PATH).expanduser().resolve()
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load regression gate policy: {source}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("gates"), list):
        raise ValueError(f"invalid regression gate policy: {source}")
    value = dict(value)
    value["source"] = str(source)
    value["sha256"] = sha256_json(
        {key: item for key, item in value.items() if key not in {"source", "sha256"}}
    )
    return value


def load_scorecard(path: Path) -> dict[str, Any]:
    source = path.expanduser().resolve()
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load scorecard: {source}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("metrics"), dict):
        raise ValueError(f"invalid scorecard: {source}")
    result = dict(value)
    result["_source"] = str(source)
    return result


def nested_value(payload: dict[str, Any], path: str) -> Any:
    value: Any = payload
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _identity(scorecard: dict[str, Any]) -> dict[str, Any]:
    metrics = scorecard.get("metrics") or {}
    return {
        "source": scorecard.get("_source", ""),
        "validation_sha256": scorecard.get("validation_sha256"),
        "validation_total": metrics.get("validation_total"),
        "evaluated_total": metrics.get("evaluated_total"),
        "coverage": metrics.get("coverage"),
        "runtime_snapshot_id": scorecard.get("runtime_snapshot_id"),
    }


def _comparability_checks(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    policy: dict[str, Any],
) -> list[dict[str, Any]]:
    config = policy.get("comparability") or {}
    checks: list[dict[str, Any]] = []

    def add(check_id: str, actual: Any, expected: Any, passed: bool, reason: str) -> None:
        checks.append(
            {
                "id": check_id,
                "kind": "comparability",
                "status": "pass" if passed else "blocked",
                "actual": actual,
                "expected": expected,
                "reason": reason,
            }
        )

    baseline_hash = baseline.get("validation_sha256")
    candidate_hash = candidate.get("validation_sha256")
    if config.get("require_same_validation_sha256", True):
        add(
            "same_frozen_benchmark",
            candidate_hash,
            baseline_hash,
            bool(baseline_hash) and candidate_hash == baseline_hash,
            "baseline and candidate must use the same frozen validation bytes",
        )

    baseline_total = nested_value(baseline, "metrics.validation_total")
    candidate_total = nested_value(candidate, "metrics.validation_total")
    if config.get("require_same_validation_total", True):
        add(
            "same_validation_total",
            candidate_total,
            baseline_total,
            baseline_total is not None and candidate_total == baseline_total,
            "baseline and candidate must contain the same validation population",
        )

    baseline_evaluated = nested_value(baseline, "metrics.evaluated_total")
    candidate_evaluated = nested_value(candidate, "metrics.evaluated_total")
    if config.get("require_same_evaluated_total", True):
        add(
            "same_evaluated_total",
            candidate_evaluated,
            baseline_evaluated,
            baseline_evaluated is not None and candidate_evaluated == baseline_evaluated,
            "partial candidate runs cannot be compared with a complete baseline",
        )

    minimum_coverage = _number(config.get("minimum_candidate_coverage"))
    if minimum_coverage is not None:
        coverage = _number(nested_value(candidate, "metrics.coverage"))
        add(
            "minimum_candidate_coverage",
            coverage,
            minimum_coverage,
            coverage is not None and coverage >= minimum_coverage,
            "candidate coverage must satisfy the release benchmark requirement",
        )
    return checks


def _gate_check(
    definition: dict[str, Any],
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    gate_id = str(definition.get("id") or "unnamed_gate")
    metric = str(definition.get("metric") or "")
    operator = str(definition.get("operator") or "")
    baseline_value = _number(nested_value(baseline, f"metrics.{metric}"))
    candidate_value = _number(nested_value(candidate, f"metrics.{metric}"))
    result: dict[str, Any] = {
        "id": gate_id,
        "kind": "quality",
        "metric": metric,
        "operator": operator,
        "baseline": baseline_value,
        "candidate": candidate_value,
        "status": "blocked",
        "reason": str(definition.get("description") or ""),
    }
    if candidate_value is None:
        result["reason"] = f"candidate metric is missing: metrics.{metric}"
        return result

    passed = False
    expected: Any = None
    if operator in {"gte_baseline", "lte_baseline", "lte_baseline_delta"}:
        if baseline_value is None:
            result["reason"] = f"baseline metric is missing: metrics.{metric}"
            return result
        tolerance = float(definition.get("tolerance") or 0.0)
        if operator == "gte_baseline":
            expected = baseline_value - tolerance
            passed = candidate_value >= expected
        elif operator == "lte_baseline":
            expected = baseline_value + tolerance
            passed = candidate_value <= expected
        else:
            expected = baseline_value + float(definition.get("max_delta") or 0.0)
            passed = candidate_value <= expected
    elif operator in {"gte", "lte"}:
        expected = _number(definition.get("value"))
        if expected is None:
            result["reason"] = f"gate policy value is missing: {gate_id}"
            return result
        passed = candidate_value >= expected if operator == "gte" else candidate_value <= expected
    else:
        result["reason"] = f"unsupported gate operator: {operator}"
        return result

    result["expected"] = expected
    result["delta_vs_baseline"] = (
        round(candidate_value - baseline_value, 9) if baseline_value is not None else None
    )
    result["status"] = "pass" if passed else "fail"
    return result


def evaluate_regression_gate(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_policy = dict(policy or load_gate_policy())
    comparisons = _comparability_checks(baseline, candidate, selected_policy)
    quality_checks = [
        _gate_check(definition, baseline, candidate)
        for definition in selected_policy.get("gates") or []
        if isinstance(definition, dict)
    ]
    checks = comparisons + quality_checks
    if any(item["status"] == "blocked" for item in checks):
        status = "blocked"
    elif any(item["status"] == "fail" for item in checks):
        status = "fail"
    else:
        status = "pass"
    summary = {
        "total": len(checks),
        "passed": sum(item["status"] == "pass" for item in checks),
        "failed": sum(item["status"] == "fail" for item in checks),
        "blocked": sum(item["status"] == "blocked" for item in checks),
    }
    digest_payload = {
        "policy": {
            "id": selected_policy.get("policy_id"),
            "version": selected_policy.get("version"),
            "sha256": selected_policy.get("sha256")
            or sha256_json(selected_policy),
        },
        "baseline": _identity(baseline),
        "candidate": _identity(candidate),
        "checks": checks,
        "status": status,
    }
    return {
        "schema_version": 1,
        "generated_at": now_iso(),
        **digest_payload,
        "summary": summary,
        "gate_report_sha256": sha256_json(digest_payload),
    }
