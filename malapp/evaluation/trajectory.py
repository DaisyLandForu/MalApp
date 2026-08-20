"""Agent trajectory evaluation. Scores existing reports; does not invoke models."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.evaluation.framework import DEFAULT_VALIDATION_CSV, _as_float, _clean, now_iso

ORCHESTRATION_MODES = ("v0_fixed", "v1_planner", "v2_planner_tools")
STRATA = (
    "malicious",
    "benign",
    "ab_conflict",
    "impersonation",
    "ioc",
    "static_risk",
    "missing_fields",
)


def extract_trajectory(report: dict[str, Any]) -> dict[str, Any]:
    runtime = (report.get("preprocess") or {}).get("agent_runtime") or {}
    investigation = runtime.get("investigation") or report.get("investigation") or {}
    plan = investigation.get("plan") or {}
    agents = runtime.get("agents") or {}
    evidence_blocks = report.get("evidence_blocks") or []
    execution = report.get("execution") or {}
    debate = report.get("debate") or {}
    model_calls = debate.get("model_calls") if isinstance(debate.get("model_calls"), list) else []
    tool_obs = _collect_tool_observations(report)
    selected = [
        name
        for name, spec in (plan.get("agents") or {}).items()
        if isinstance(spec, dict) and spec.get("enabled")
    ] or [
        name
        for name in AGENT_ORDER
        if str((agents.get(name) or {}).get("failure_type") or "") != "skipped_by_plan"
        and str((agents.get(name) or {}).get("status") or "") != "skipped"
    ]
    skipped = [
        name
        for name in AGENT_ORDER
        if str((agents.get(name) or {}).get("failure_type") or "") == "skipped_by_plan"
    ]
    lifecycle = investigation.get("lifecycle") or []
    pipeline = execution.get("pipeline") if isinstance(execution.get("pipeline"), dict) else {}
    return {
        "run_id": report.get("run_id") or execution.get("run_id") or "",
        "sample_id": (report.get("sample") or {}).get("sample_id") or (report.get("sample") or {}).get("md5") or "",
        "orchestration_mode": execution.get("orchestration_mode") or investigation.get("orchestration_mode") or "v0_fixed",
        "plan": plan,
        "plan_valid": not bool(plan.get("fallback")),
        "fallback": bool(plan.get("fallback")),
        "selected_agents": selected,
        "skipped_agents": skipped,
        "agent_calls": len(selected),
        "replan": any(item.get("phase") == "replan_started" for item in lifecycle if isinstance(item, dict)),
        "gate": investigation.get("evidence_gate") or {},
        "tool_observations": tool_obs,
        "tool_calls": len(tool_obs),
        "evidence_blocks": evidence_blocks,
        "missing_fields": [
            field
            for block in evidence_blocks
            if isinstance(block, dict)
            for field in block.get("missing_fields") or []
        ],
        "verdict": (report.get("decision") or {}).get("verdict"),
        "score": (report.get("decision") or {}).get("score"),
        "latency_ms": _as_float(runtime.get("latency_ms") or pipeline.get("latency_ms"), 0.0) or 0.0,
        "model_backend": str((debate.get("providers") or {}).get("model_a", {}).get("backend") or debate.get("execution_mode") or ""),
        "token_usage": _token_usage(model_calls),
        "lifecycle": lifecycle,
        "runtime_snapshot_id": (report.get("runtime_snapshot") or {}).get("snapshot_id") or execution.get("runtime_snapshot_id") or "",
    }


def _collect_tool_observations(report: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    runtime = (report.get("preprocess") or {}).get("agent_runtime") or {}
    for result in runtime.get("results") or []:
        if not isinstance(result, dict):
            continue
        artifacts = result.get("artifacts")
        if isinstance(artifacts, dict) and isinstance(artifacts.get("tool_observations"), list):
            found.extend(item for item in artifacts["tool_observations"] if isinstance(item, dict))
    investigation = runtime.get("investigation") or {}
    extra = investigation.get("tool_observations")
    if isinstance(extra, list):
        found.extend(item for item in extra if isinstance(item, dict))
    for block in report.get("evidence_blocks") or []:
        if not isinstance(block, dict):
            continue
        for item in block.get("evidence_items") or []:
            if isinstance(item, dict) and item.get("evidence_type") == "tool_observation":
                found.append(item)
    return found


def _token_usage(model_calls: list[dict[str, Any]]) -> dict[str, int]:
    input_tokens = sum(int(item.get("prompt_tokens") or item.get("input_tokens") or 0) for item in model_calls)
    output_tokens = sum(int(item.get("completion_tokens") or item.get("output_tokens") or 0) for item in model_calls)
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "model_calls": len(model_calls),
    }


def score_trajectory(trajectory: dict[str, Any], *, v0_reference: dict[str, Any] | None = None) -> dict[str, Any]:
    tools = trajectory.get("tool_observations") or []
    success = sum(1 for item in tools if item.get("status") == "completed")
    denied = sum(1 for item in tools if item.get("status") == "denied")
    timeout = sum(1 for item in tools if item.get("status") == "timeout")
    failed = sum(1 for item in tools if item.get("status") in {"failed", "timeout"})
    evidence_blocks = trajectory.get("evidence_blocks") or []
    coverage = _evidence_coverage(evidence_blocks)
    unsupported = sum(
        1
        for block in evidence_blocks
        if isinstance(block, dict) and not block.get("evidence_items") and block.get("claim")
    )
    missing_critical = [
        field
        for field in trajectory.get("missing_fields") or []
        if any(token in str(field) for token in ("ioc", "threat_intel", "official", "static", "skipped_by_plan"))
    ]
    v0_coverage = _evidence_coverage(v0_reference.get("evidence_blocks") or []) if v0_reference else None
    tokens = trajectory.get("token_usage") or {}
    backend = str(trajectory.get("model_backend") or "").lower()
    report_tokens = backend not in {"", "rule"} and int(tokens.get("model_calls") or 0) > 0
    return {
        "plan_valid": bool(trajectory.get("plan_valid", True)),
        "fallback": bool(trajectory.get("fallback")),
        "selected_agents": len(trajectory.get("selected_agents") or []),
        "skipped_agents": len(trajectory.get("skipped_agents") or []),
        "agent_calls": int(trajectory.get("agent_calls") or 0),
        "replan": bool(trajectory.get("replan")),
        "trajectory_success": str(trajectory.get("verdict") or "") in {"malicious", "suspicious", "benign"},
        "tool_calls": len(tools),
        "tool_success_rate": (success / len(tools)) if tools else 1.0,
        "tool_denial_rate": (denied / len(tools)) if tools else 0.0,
        "tool_timeout_rate": (timeout / len(tools)) if tools else 0.0,
        "tool_argument_valid_rate": ((len(tools) - failed) / len(tools)) if tools else 1.0,
        "evidence_coverage": coverage,
        "evidence_coverage_vs_v0": None if v0_coverage is None else round(coverage - v0_coverage, 4),
        "unsupported_evidence_rate": (unsupported / len(evidence_blocks)) if evidence_blocks else 0.0,
        "missing_critical_evidence_rate": (len(missing_critical) / max(1, len(evidence_blocks))),
        "cost_reported": report_tokens,
        "token_usage": tokens if report_tokens else {"note": "rule_backend_tokens_omitted"},
        "latency_ms": trajectory.get("latency_ms") or 0.0,
    }


def _evidence_coverage(blocks: list[dict[str, Any]]) -> float:
    if not blocks:
        return 0.0
    scores = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        known = len(block.get("evidence") or []) + len(block.get("evidence_items") or [])
        missing = len(block.get("missing_fields") or [])
        scores.append(known / (known + missing) if known + missing else 0.5)
    return round(sum(scores) / len(scores), 4) if scores else 0.0


def summarize_trajectories(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [item for item in items if isinstance(item, dict)]
    count = len(rows) or 1
    def avg(key: str) -> float:
        values = [float(item.get(key) or 0) for item in rows]
        return round(sum(values) / count, 4)

    return {
        "count": len(rows),
        "plan_valid_rate": avg("plan_valid"),
        "planner_fallback_rate": avg("fallback"),
        "average_selected_agents": avg("selected_agents"),
        "average_agent_calls": avg("agent_calls"),
        "replan_rate": avg("replan"),
        "trajectory_success_rate": avg("trajectory_success"),
        "average_tool_calls": avg("tool_calls"),
        "tool_call_success_rate": avg("tool_success_rate"),
        "tool_denial_rate": avg("tool_denial_rate"),
        "tool_timeout_rate": avg("tool_timeout_rate"),
        "tool_argument_valid_rate": avg("tool_argument_valid_rate"),
        "evidence_coverage": avg("evidence_coverage"),
        "unsupported_evidence_rate": avg("unsupported_evidence_rate"),
        "missing_critical_evidence_rate": avg("missing_critical_evidence_rate"),
        "notes": [
            "Selected Agent Recall and Unnecessary Agent Rate are omitted without required-agent labels.",
            "Token/P50/P95 are only meaningful on real LLM backends; rule backends omit token claims.",
        ],
    }


def compare_variants(by_mode: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    summary = {mode: summarize_trajectories(items) for mode, items in by_mode.items()}
    v0 = summary.get("v0_fixed") or summary.get("v0") or {}
    deltas = {}
    for mode, stats in summary.items():
        if mode in {"v0_fixed", "v0"}:
            continue
        deltas[mode] = {
            "average_selected_agents": round(
                float(stats.get("average_selected_agents") or 0) - float(v0.get("average_selected_agents") or 0),
                4,
            ),
            "evidence_coverage": round(
                float(stats.get("evidence_coverage") or 0) - float(v0.get("evidence_coverage") or 0),
                4,
            ),
            "average_agent_calls": round(
                float(stats.get("average_agent_calls") or 0) - float(v0.get("average_agent_calls") or 0),
                4,
            ),
        }
    return {"variants": summary, "deltas_vs_v0": deltas}


def row_stratum(row: dict[str, Any]) -> str:
    gold = _clean(row.get("_gold_label") or row.get("gold_label")).lower()
    if any(_clean(row.get(key)) for key in ("control_url", "download_url", "domains", "ips", "threat_intel_records")):
        return "ioc"
    if any(_clean(row.get(key)) for key in ("fake_app", "official_pkg", "official_app_name", "brand_similarity")):
        return "impersonation"
    label_a = _clean(row.get("engine_a_label"))
    label_b = _clean(row.get("engine_b_label"))
    if label_a and label_b and label_a != label_b:
        return "ab_conflict"
    if any(_clean(row.get(key)) for key in ("packer", "sdk_list", "permissions")):
        return "static_risk"
    required = ("package_name", "app_name", "md5")
    if sum(1 for key in required if not _clean(row.get(key))) >= 2:
        return "missing_fields"
    if gold in {"malicious", "1"}:
        return "malicious"
    return "benign"


def build_benchmark_manifest(
    rows: list[dict[str, Any]],
    *,
    size: int = 150,
    runtime_snapshot_id: str = "",
) -> dict[str, Any]:
    size = max(100, min(int(size), 200))
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        buckets[row_stratum(row)].append(row)
    selected: list[dict[str, Any]] = []
    quota = max(1, size // max(1, len(STRATA)))
    for stratum in STRATA:
        for row in buckets.get(stratum, [])[:quota]:
            selected.append(_manifest_row(row, stratum, runtime_snapshot_id))
        if len(selected) >= size:
            break
    if len(selected) < size:
        for row in rows:
            sample_id = _clean(row.get("md5") or row.get("sample_id") or row.get("_row_id")).upper()
            if sample_id and sample_id not in {item["sample_id"] for item in selected}:
                selected.append(_manifest_row(row, row_stratum(row), runtime_snapshot_id))
            if len(selected) >= size:
                break
    selected = selected[:size]
    payload = {
        "created_at": now_iso(),
        "size": len(selected),
        "target_size": size,
        "runtime_snapshot_id": runtime_snapshot_id,
        "source": str(DEFAULT_VALIDATION_CSV),
        "samples": selected,
        "strata": {name: sum(1 for item in selected if item["stratum"] == name) for name in STRATA},
    }
    digest = hashlib.sha256(json.dumps(payload["samples"], ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    payload["manifest_sha256"] = digest
    return payload


def _manifest_row(row: dict[str, Any], stratum: str, runtime_snapshot_id: str) -> dict[str, Any]:
    sample_id = _clean(row.get("md5") or row.get("sample_id") or row.get("_row_id")).upper()
    return {
        "sample_id": sample_id,
        "stratum": stratum,
        "gold_label": _clean(row.get("_gold_label") or row.get("gold_label")),
        "runtime_snapshot_id": runtime_snapshot_id,
        "expected_evidence_requirements": _expected_evidence(stratum),
    }


def _expected_evidence(stratum: str) -> list[str]:
    mapping = {
        "ioc": ["threat_intel", "network_indicator"],
        "impersonation": ["impersonation", "official_asset_match"],
        "static_risk": ["static_analysis"],
        "ab_conflict": ["static_analysis", "threat_intel"],
        "missing_fields": ["static_analysis"],
        "malicious": ["static_analysis"],
        "benign": ["static_analysis"],
    }
    return mapping.get(stratum, ["static_analysis"])


def score_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    scored = []
    v0_by_sample = {}
    trajectories = [extract_trajectory(report) for report in reports]
    for item in trajectories:
        if item.get("orchestration_mode") == "v0_fixed":
            v0_by_sample[item.get("sample_id")] = item
    for item in trajectories:
        metrics = score_trajectory(item, v0_reference=v0_by_sample.get(item.get("sample_id")))
        record = {**item, "metrics": metrics}
        scored.append(record)
        by_mode[item.get("orchestration_mode") or "v0_fixed"].append(metrics)
    return {
        "created_at": now_iso(),
        "trajectories": scored,
        "comparison": compare_variants(by_mode),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
