"""Agent trajectory evaluation. Scores existing reports; does not invoke models."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.evaluation.framework import DEFAULT_VALIDATION_CSV, _as_float, _clean, now_iso, sha256_file
from malapp.governance.artifacts import canonical_json
from malapp.tools.base import validate_tool_arguments

DEFAULT_PUBLISH_DIR = Path(__file__).resolve().parents[1] / "config" / "defaults" / "eval"

ORCHESTRATION_MODES = ("v0_fixed", "v1_planner", "v2_planner_tools")
DEBATE_MODE = "no_debate"
EVAL_VARIANT = "trajectory"
RULE_TRAJECTORY_ENV = {
    "MALAPP_PROFILE": "demo",
    "MALAPP_RAG_ENABLED": "0",
    "MALAPP_USE_XGB": "0",
    "MALAPP_MD5_REPORT_CACHE": "0",
    "MALAPP_USE_SERVER_MODELS": "0",
    "MALAPP_USE_LOCAL_QWEN": "0",
    "MALAPP_EVAL_VARIANT": EVAL_VARIANT,
}
ORCHESTRATION_ENV = {
    "v0_fixed": {
        "MALAPP_PLANNER_ENABLED": "0",
        "MALAPP_TOOL_RUNTIME_ENABLED": "0",
        "MALAPP_ORCHESTRATION_MODE": "v0_fixed",
    },
    "v1_planner": {
        "MALAPP_PLANNER_ENABLED": "1",
        "MALAPP_PLANNER_MODE": "rule",
        "MALAPP_TOOL_RUNTIME_ENABLED": "0",
        "MALAPP_ORCHESTRATION_MODE": "v1_planner",
    },
    "v2_planner_tools": {
        "MALAPP_PLANNER_ENABLED": "1",
        "MALAPP_PLANNER_MODE": "rule",
        "MALAPP_TOOL_RUNTIME_ENABLED": "1",
        "MALAPP_ORCHESTRATION_MODE": "v2_planner_tools",
    },
}
STRATA = (
    "malicious",
    "benign",
    "ab_conflict",
    "impersonation",
    "ioc",
    "static_risk",
    "missing_fields",
)
ANSWER_ONLY_FIELDS = {
    "gold_label",
    "label",
    "raw_label",
    "reference_label",
    "human_label",
    "candidate_label",
    "target",
    "annotation_status",
    "label_source",
    "label_quality",
    "release_tier",
    "strict_untrained",
    "_gold_label",
    "_row_id",
}
COMMERCIAL_BACKENDS = {
    "openai",
    "azure",
    "dashscope",
    "qwen",
    "server",
    "http",
    "https",
    "anthropic",
    "deepseek",
}
RULE_BACKENDS = {"", "rule", "fixture", "not_invoked", "none", "evaluation_no_debate"}
VALID_VERDICTS = {"malicious", "suspicious", "benign"}
STARTED_PHASES = {"started"}
ATTEMPT_PHASES = {"attempt"}
REPLAN_PHASES = {"replan_started"}
PLACEHOLDER_STATUSES = {"skipped_by_plan", "disabled"}
_PATH_ATTRS = {
    "DATA_DIR": lambda data_dir: data_dir,
    "DB_PATH": lambda data_dir: data_dir / "mvp.db",
    "BLOOM_PATH": lambda data_dir: data_dir / "sample_seen.bloom",
    "RAG_DB_PATH": lambda data_dir: data_dir / "rag" / "rag_store.db",
    "SETTINGS_PATH": lambda data_dir: data_dir / "model_settings.json",
    "CALIBRATION_PATH": lambda data_dir: data_dir / "eval" / "best_params.json",
    "BEST_PARAMS_PATH": lambda data_dir: data_dir / "eval" / "best_params.json",
    "DECISION_PARAMS_PATH": lambda data_dir: data_dir / "decision_params.json",
    "ASSET_LIBRARY_PATH": lambda data_dir: data_dir / "official_app_assets.json",
}


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
    investigation_lifecycle = [item for item in (investigation.get("lifecycle") or []) if isinstance(item, dict)]
    runtime_lifecycle = [item for item in (runtime.get("lifecycle") or []) if isinstance(item, dict)]
    agent_traces = _agent_traces(agents)
    counts = _agent_activity_counts(runtime_lifecycle, investigation_lifecycle, agent_traces, agents)
    gate = investigation.get("evidence_gate") if isinstance(investigation.get("evidence_gate"), dict) else {}
    pipeline = execution.get("pipeline") if isinstance(execution.get("pipeline"), dict) else {}
    return {
        "run_id": report.get("run_id") or execution.get("run_id") or "",
        "sample_id": (report.get("sample") or {}).get("sample_id") or (report.get("sample") or {}).get("md5") or "",
        "orchestration_mode": execution.get("orchestration_mode") or investigation.get("orchestration_mode") or "v0_fixed",
        "plan": plan,
        "plan_valid": not bool(plan.get("fallback")),
        "fallback": bool(plan.get("fallback")),
        "agents": agents,
        "selected_agents": selected,
        "skipped_agents": skipped,
        "agent_calls": counts["agent_calls"],
        "agent_attempts": counts["agent_attempts"],
        "agent_retries": counts["agent_retries"],
        "replan_agent_calls": counts["replan_agent_calls"],
        "replan": counts["replan"],
        "gate": gate,
        "runtime_status": str(runtime.get("status") or execution.get("status") or ""),
        "cache_hit": bool(execution.get("history_reuse_source") or report.get("cache_source")),
        "cache_source": str(execution.get("history_reuse_source") or report.get("cache_source") or ""),
        "debate_execution_mode": str(debate.get("execution_mode") or ""),
        "model_calls": model_calls,
        "invokes_models": report_invokes_models(report),
        "invokes_api": report_invokes_api(report),
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
        "lifecycle": investigation_lifecycle,
        "runtime_lifecycle": runtime_lifecycle,
        "runtime_snapshot_id": (report.get("runtime_snapshot") or {}).get("snapshot_id") or execution.get("runtime_snapshot_id") or "",
        "data_dir": str(execution.get("data_dir") or ""),
    }


def _agent_traces(agents: dict[str, Any]) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for state in agents.values():
        if not isinstance(state, dict):
            continue
        traces.extend(item for item in (state.get("trace") or []) if isinstance(item, dict))
    return traces


def _agent_activity_counts(
    runtime_lifecycle: list[dict[str, Any]],
    investigation_lifecycle: list[dict[str, Any]],
    agent_traces: list[dict[str, Any]],
    agents: dict[str, Any],
) -> dict[str, Any]:
    started = [item for item in runtime_lifecycle if item.get("phase") in STARTED_PHASES]
    if not started:
        started = [item for item in agent_traces if item.get("phase") in STARTED_PHASES]
    attempts = [item for item in agent_traces if item.get("phase") in ATTEMPT_PHASES]
    if not attempts:
        attempts = [
            {"agent": name, "phase": "attempt", "status": "completed"}
            for name, state in agents.items()
            if isinstance(state, dict) and str(state.get("failure_type") or "") not in PLACEHOLDER_STATUSES
            for _ in range(max(1, int(state.get("attempts") or 0)))
        ]
    retries = sum(
        max(0, int((state or {}).get("restart_count") or max(0, int((state or {}).get("attempts") or 1) - 1)))
        for state in agents.values()
        if isinstance(state, dict) and str(state.get("failure_type") or "") not in PLACEHOLDER_STATUSES
    )
    replan_events = [item for item in investigation_lifecycle if item.get("phase") in REPLAN_PHASES]
    replan_ts_values = [float(item["ts"]) for item in replan_events if item.get("ts") not in (None, "")]
    replan_calls = 0
    if replan_ts_values:
        replan_ts = min(replan_ts_values)
        replan_calls = sum(1 for item in started if float(item.get("ts") or 0) >= replan_ts)
    return {
        "agent_calls": len(started),
        "agent_attempts": len(attempts) if attempts else len(started),
        "agent_retries": retries,
        "replan_agent_calls": replan_calls,
        "replan": bool(replan_events),
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


def report_invokes_models(report: dict[str, Any]) -> bool:
    debate = report.get("debate") if isinstance(report.get("debate"), dict) else {}
    mode = str(debate.get("execution_mode") or "").lower()
    if mode in {"evaluation_no_debate", "no_debate"}:
        return False
    if any(_commercial_backend(item) for item in _provider_backends(debate)):
        return True
    for call in debate.get("model_calls") or []:
        if isinstance(call, dict) and _commercial_model_call(call):
            return True
    return False


def report_invokes_api(report: dict[str, Any]) -> bool:
    if str(os.getenv("MALAPP_USE_SERVER_MODELS", "0")).lower() in {"1", "true", "yes", "y"}:
        return True
    debate = report.get("debate") if isinstance(report.get("debate"), dict) else {}
    if any(_commercial_backend(item) for item in _provider_backends(debate)):
        return True
    for call in debate.get("model_calls") or []:
        if isinstance(call, dict) and (call.get("api_url") or _commercial_model_call(call)):
            return True
    return False


def _provider_backends(debate: dict[str, Any]) -> list[str]:
    providers = debate.get("providers") if isinstance(debate.get("providers"), dict) else {}
    return [
        str((providers.get(name) or {}).get("backend") or "").lower()
        for name in ("model_a", "model_b")
    ]


def _commercial_backend(backend: str) -> bool:
    value = str(backend or "").lower()
    if value in RULE_BACKENDS:
        return False
    return any(token in value for token in COMMERCIAL_BACKENDS)


def _commercial_model_call(call: dict[str, Any]) -> bool:
    backend = str(call.get("backend") or call.get("provider") or "").lower()
    if backend in RULE_BACKENDS or "rule" in backend:
        return False
    return bool(call.get("api_url")) or _commercial_backend(backend)


def score_trajectory(
    trajectory: dict[str, Any],
    *,
    v0_reference: dict[str, Any] | None = None,
    expected_evidence_requirements: list[str] | None = None,
) -> dict[str, Any]:
    tools = [item for item in (trajectory.get("tool_observations") or []) if isinstance(item, dict)]
    success = sum(1 for item in tools if item.get("status") == "completed")
    denied = sum(1 for item in tools if item.get("status") == "denied")
    timeout = sum(1 for item in tools if item.get("status") == "timeout")
    argument_valid = sum(1 for item in tools if _tool_arguments_valid(item))
    evidence_blocks = [item for item in (trajectory.get("evidence_blocks") or []) if isinstance(item, dict)]
    requirements = list(expected_evidence_requirements or [])
    coverage, missing_critical = _requirement_coverage(evidence_blocks, requirements)
    unsupported = sum(
        1
        for block in evidence_blocks
        if not _is_placeholder_block(block)
        and not block.get("evidence_items")
        and not _unique_evidence_ids(block)
        and block.get("claim")
    )
    v0_coverage = None
    if v0_reference is not None:
        v0_coverage, _ = _requirement_coverage(
            [item for item in (v0_reference.get("evidence_blocks") or []) if isinstance(item, dict)],
            requirements,
        )
    tokens = trajectory.get("token_usage") or {}
    backend = str(trajectory.get("model_backend") or "").lower()
    report_tokens = backend not in RULE_BACKENDS and int(tokens.get("model_calls") or 0) > 0
    return {
        "plan_valid": bool(trajectory.get("plan_valid", True)),
        "fallback": bool(trajectory.get("fallback")),
        "selected_agents": len(trajectory.get("selected_agents") or []),
        "skipped_agents": len(trajectory.get("skipped_agents") or []),
        "agent_calls": int(trajectory.get("agent_calls") or 0),
        "agent_attempts": int(trajectory.get("agent_attempts") or 0),
        "agent_retries": int(trajectory.get("agent_retries") or 0),
        "replan_agent_calls": int(trajectory.get("replan_agent_calls") or 0),
        "replan": bool(trajectory.get("replan")),
        "trajectory_success": trajectory_success(trajectory),
        "tool_calls": len(tools),
        "tool_success_rate": (success / len(tools)) if tools else 1.0,
        "tool_denial_rate": (denied / len(tools)) if tools else 0.0,
        "tool_timeout_rate": (timeout / len(tools)) if tools else 0.0,
        "tool_argument_valid_rate": (argument_valid / len(tools)) if tools else 1.0,
        "evidence_coverage": coverage,
        "evidence_coverage_vs_v0": None if v0_coverage is None else round(coverage - v0_coverage, 4),
        "unsupported_evidence_rate": (unsupported / len(evidence_blocks)) if evidence_blocks else 0.0,
        "missing_critical_evidence_rate": round(len(missing_critical) / max(1, len(requirements)), 4) if requirements else 0.0,
        "missing_critical_evidence": missing_critical,
        "cost_reported": report_tokens,
        "token_usage": tokens if report_tokens else {"note": "rule_backend_tokens_omitted"},
        "latency_ms": trajectory.get("latency_ms") or 0.0,
        "invokes_models": bool(trajectory.get("invokes_models")),
        "invokes_api": bool(trajectory.get("invokes_api")),
        "cache_hit": bool(trajectory.get("cache_hit")),
    }


def trajectory_success(trajectory: dict[str, Any]) -> bool:
    verdict = str(trajectory.get("verdict") or "")
    if verdict not in VALID_VERDICTS:
        return False
    if trajectory.get("fallback"):
        return False
    if trajectory.get("cache_hit"):
        return False
    gate = trajectory.get("gate") if isinstance(trajectory.get("gate"), dict) else {}
    if gate and gate.get("sufficient") is False:
        return False
    runtime_status = str(trajectory.get("runtime_status") or "").lower()
    if runtime_status in {"failed", "error"}:
        return False
    selected = list(trajectory.get("selected_agents") or [])
    report_agents = trajectory.get("agents") if isinstance(trajectory.get("agents"), dict) else {}
    for name in selected:
        state = report_agents.get(name) or {}
        status = str(state.get("status") or "")
        failure = str(state.get("failure_type") or "")
        if failure in PLACEHOLDER_STATUSES:
            continue
        if status in {"failed", "timeout"} or failure in {"failed", "timeout", "exception"}:
            return False
    tools = [item for item in (trajectory.get("tool_observations") or []) if isinstance(item, dict)]
    if any(item.get("status") in {"failed", "timeout"} for item in tools):
        return False
    return True


def _tool_arguments_valid(observation: dict[str, Any]) -> bool:
    if "arguments_valid" in observation:
        return bool(observation.get("arguments_valid"))
    arguments = observation.get("arguments")
    if arguments is None:
        return False
    valid, _errors = validate_tool_arguments(
        str(observation.get("tool_name") or ""),
        str(observation.get("agent") or ""),
        arguments,
    )
    return valid


def _is_placeholder_block(block: dict[str, Any]) -> bool:
    missing = [str(item) for item in (block.get("missing_fields") or [])]
    status = str(block.get("status") or "")
    return "skipped_by_plan" in missing or status in {"skipped", "skipped_by_plan"}


def _unique_evidence_ids(block: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    evidence_id = str(block.get("evidence_id") or "").strip()
    if evidence_id:
        ids.add(evidence_id)
    agent = str(block.get("agent") or "").strip()
    if agent:
        ids.add(agent)
    for item in block.get("evidence_items") or []:
        if not isinstance(item, dict):
            continue
        for key in ("evidence_id", "evidence_type", "tool_name"):
            value = str(item.get(key) or "").strip()
            if value:
                ids.add(value)
    return ids


def _requirement_coverage(blocks: list[dict[str, Any]], requirements: list[str]) -> tuple[float, list[str]]:
    present: set[str] = set()
    for block in blocks:
        if _is_placeholder_block(block):
            continue
        present.update(_unique_evidence_ids(block))
    if not requirements:
        usable = [block for block in blocks if not _is_placeholder_block(block)]
        if not usable:
            return 0.0, []
        covered = sum(1 for block in usable if _unique_evidence_ids(block))
        return round(covered / len(usable), 4), []
    missing = [item for item in requirements if item not in present]
    return round((len(requirements) - len(missing)) / len(requirements), 4), missing


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
        "average_agent_attempts": avg("agent_attempts"),
        "average_agent_retries": avg("agent_retries"),
        "average_replan_agent_calls": avg("replan_agent_calls"),
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
        "cache_hit_rate": avg("cache_hit"),
        "invokes_models_rate": avg("invokes_models"),
        "invokes_api_rate": avg("invokes_api"),
        "notes": [
            "Selected Agent Recall and Unnecessary Agent Rate are omitted without required-agent labels.",
            "Token/P50/P95 are only meaningful on real LLM backends; rule backends omit token claims.",
            "trajectory_success requires a valid verdict, final evidence gate, no planner fallback, no cache hit, and no agent/tool failure.",
            "evidence_coverage uses expected_evidence_requirements or deduplicated evidence IDs; skipped_by_plan placeholders are excluded.",
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
            "average_tool_calls": round(
                float(stats.get("average_tool_calls") or 0) - float(v0.get("average_tool_calls") or 0),
                4,
            ),
            "trajectory_success_rate": round(
                float(stats.get("trajectory_success_rate") or 0) - float(v0.get("trajectory_success_rate") or 0),
                4,
            ),
        }
    return {"variants": summary, "deltas_vs_v0": deltas}


def row_stratum(row: dict[str, Any]) -> str:
    gold = _clean(row.get("_gold_label") or row.get("gold_label")).lower()
    if _has_network_fields(row):
        return "ioc"
    if _has_impersonation_fields(row):
        return "impersonation"
    if _has_ab_conflict(row):
        return "ab_conflict"
    if _has_static_risk(row):
        return "static_risk"
    required = ("package_name", "app_name", "md5")
    if sum(1 for key in required if not _clean(row.get(key))) >= 2:
        return "missing_fields"
    if gold in {"malicious", "1"}:
        return "malicious"
    return "benign"


def row_layers(row: dict[str, Any]) -> list[str]:
    layers = [row_stratum(row)]
    gold = _clean(row.get("_gold_label") or row.get("gold_label")).lower()
    if _has_ab_conflict(row):
        layers.append("ab_conflict")
    if _has_static_risk(row):
        layers.append("static_risk")
    if _has_impersonation_fields(row):
        layers.append("impersonation")
    if _has_network_fields(row):
        layers.append("ioc")
    if gold in {"malicious", "1"}:
        layers.append("malicious")
    elif gold:
        layers.append("benign")
    required = ("package_name", "app_name", "md5")
    if sum(1 for key in required if not _clean(row.get(key))) >= 2:
        layers.append("missing_fields")
    return list(dict.fromkeys(layers))


def _has_network_fields(row: dict[str, Any]) -> bool:
    return any(
        _clean(row.get(key))
        for key in ("control_url", "download_url", "domains", "ips", "threat_intel_records")
    )


def _has_impersonation_fields(row: dict[str, Any]) -> bool:
    fake = _clean(row.get("fake_app")).lower()
    fake_positive = fake in {"1", "true", "yes", "y", "malicious"}
    return fake_positive or any(
        _clean(row.get(key)) for key in ("official_pkg", "official_app_name", "brand_similarity")
    )


def _has_ab_conflict(row: dict[str, Any]) -> bool:
    pairs = (
        ("engine_a_label", "engine_b_label"),
        ("engine_360_type", "engine_cm_type"),
    )
    for left, right in pairs:
        first = _clean(row.get(left))
        second = _clean(row.get(right))
        if first and second and first != second:
            return True
    return False


def _has_static_risk(row: dict[str, Any]) -> bool:
    return any(_clean(row.get(key)) for key in ("packer", "sdk_list", "permissions"))


def freeze_judge_input(row: dict[str, Any]) -> dict[str, Any]:
    blinded: dict[str, Any] = {}
    for key, value in row.items():
        if str(key).startswith("_"):
            continue
        if str(key).strip().lower() in ANSWER_ONLY_FIELDS:
            continue
        if value in ("", None):
            continue
        blinded[key] = value
    return blinded


def input_sha256(sample: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(freeze_judge_input(sample)).encode("utf-8")).hexdigest()


def build_benchmark_manifest(
    rows: list[dict[str, Any]],
    *,
    size: int = 150,
    runtime_snapshot_id: str = "",
    min_size: int = 100,
    max_size: int = 200,
    source: str | Path | None = None,
    source_sha256: str = "",
    allow_stratum_waiver: bool = False,
    fill_missing_strata: bool = True,
    require_runtime_snapshot: bool = True,
    require_all_strata: bool | None = None,
) -> dict[str, Any]:
    size = max(int(min_size), min(int(size), int(max_size)))
    if require_all_strata is None:
        require_all_strata = size >= 100
    source_path = Path(source) if source else DEFAULT_VALIDATION_CSV
    if not source_sha256 and source_path.exists() and source_path.is_file():
        source_sha256 = sha256_file(source_path)
    if require_runtime_snapshot and not str(runtime_snapshot_id or "").strip():
        from malapp.governance.runtime import capture_runtime_snapshot

        runtime_snapshot_id = capture_runtime_snapshot()["snapshot_id"]
    if not str(runtime_snapshot_id or "").strip():
        raise ValueError("runtime_snapshot_id is required to freeze a trajectory benchmark")

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        for layer in row_layers(row):
            buckets[layer].append(row)
    selected: list[dict[str, Any]] = []
    used: set[str] = set()
    waivers: list[dict[str, str]] = []
    quota = max(1, size // max(1, len(STRATA)))
    for stratum in STRATA:
        taken = 0
        for row in buckets.get(stratum, []):
            sample_id = _sample_id(row)
            if not sample_id or sample_id in used:
                continue
            selected.append(
                _manifest_row(row, stratum, runtime_snapshot_id, origin="source")
            )
            used.add(sample_id)
            taken += 1
            if taken >= quota or len(selected) >= size:
                break
        if taken == 0 and fill_missing_strata:
            fixture = _stratum_fixture(stratum)
            selected.append(
                _manifest_row(fixture, stratum, runtime_snapshot_id, origin="fixture")
            )
            used.add(_sample_id(fixture))
            taken = 1
        if taken == 0:
            waiver = {
                "stratum": stratum,
                "reason": "source_has_zero_matching_rows",
            }
            if allow_stratum_waiver:
                waivers.append(waiver)
            else:
                raise ValueError(
                    f"required stratum {stratum!r} is empty; pass fill_missing_strata=True or allow_stratum_waiver=True"
                )
        if len(selected) >= size:
            break
    if len(selected) < size:
        for row in rows:
            sample_id = _sample_id(row)
            if sample_id and sample_id not in used:
                selected.append(_manifest_row(row, row_stratum(row), runtime_snapshot_id, origin="source"))
                used.add(sample_id)
            if len(selected) >= size:
                break
    selected = selected[:size]
    missing = [name for name in STRATA if not any(item["stratum"] == name for item in selected)]
    if missing and require_all_strata and not allow_stratum_waiver:
        raise ValueError(f"frozen benchmark missing required strata: {missing}")
    for name in missing:
        waivers.append({"stratum": name, "reason": "not_represented_in_frozen_subset"})
    payload = {
        "created_at": now_iso(),
        "size": len(selected),
        "target_size": size,
        "runtime_snapshot_id": runtime_snapshot_id,
        "source": str(source_path),
        "source_sha256": source_sha256,
        "debate_mode": DEBATE_MODE,
        "eval_variant": EVAL_VARIANT,
        "rule_trajectory_env": dict(RULE_TRAJECTORY_ENV),
        "orchestration_env": {mode: dict(values) for mode, values in ORCHESTRATION_ENV.items()},
        "samples": selected,
        "strata": {name: sum(1 for item in selected if item["stratum"] == name) for name in STRATA},
        "stratum_waivers": waivers,
    }
    payload["manifest_sha256"] = manifest_digest(payload)
    return payload


def manifest_digest(payload: dict[str, Any]) -> str:
    identity = {
        "size": payload.get("size"),
        "source": payload.get("source"),
        "source_sha256": payload.get("source_sha256"),
        "runtime_snapshot_id": payload.get("runtime_snapshot_id"),
        "debate_mode": payload.get("debate_mode") or DEBATE_MODE,
        "eval_variant": payload.get("eval_variant") or EVAL_VARIANT,
        "rule_trajectory_env": payload.get("rule_trajectory_env") or RULE_TRAJECTORY_ENV,
        "orchestration_env": payload.get("orchestration_env") or ORCHESTRATION_ENV,
        "samples": payload.get("samples") or [],
        "stratum_waivers": payload.get("stratum_waivers") or [],
    }
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


def load_benchmark_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("trajectory manifest must be a JSON object")
    expected = manifest_digest(payload)
    recorded = str(payload.get("manifest_sha256") or "")
    if recorded != expected:
        raise ValueError("trajectory manifest sha256 does not match frozen inputs")
    if not payload.get("runtime_snapshot_id"):
        raise ValueError("trajectory manifest is missing runtime_snapshot_id")
    for item in payload.get("samples") or []:
        blinded = item.get("blinded_input") if isinstance(item, dict) else None
        if not isinstance(blinded, dict):
            raise ValueError(f"manifest sample {item.get('sample_id')} is missing blinded_input")
        digest = str(item.get("input_sha256") or "")
        if digest != input_sha256(blinded):
            raise ValueError(f"manifest sample {item.get('sample_id')} input_sha256 does not match blinded_input")
    return payload


def _sample_id(row: dict[str, Any]) -> str:
    return _clean(row.get("md5") or row.get("sample_id") or row.get("_row_id")).upper()


def _manifest_row(
    row: dict[str, Any],
    stratum: str,
    runtime_snapshot_id: str,
    *,
    origin: str,
) -> dict[str, Any]:
    blinded = freeze_judge_input(row)
    sample_id = _sample_id(row) or _sample_id(blinded)
    return {
        "sample_id": sample_id,
        "stratum": stratum,
        "gold_label": _clean(row.get("_gold_label") or row.get("gold_label")),
        "runtime_snapshot_id": runtime_snapshot_id,
        "expected_evidence_requirements": _expected_evidence(stratum),
        "input_sha256": input_sha256(blinded),
        "blinded_input": blinded,
        "origin": origin,
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


def _stratum_fixture(stratum: str) -> dict[str, Any]:
    fixtures = {
        "ioc": {
            "sample_id": "P9FIXTUREIOC000000000000000001",
            "package_name": "com.malapp.fixture.ioc",
            "app_name": "fixture-ioc",
            "signature_status": "valid",
            "control_url": "https://c2.example.test/gate",
            "_gold_label": "malicious",
        },
        "impersonation": {
            "sample_id": "P9FIXTUREIMPERSONATION00000001",
            "package_name": "com.malapp.fixture.bank",
            "app_name": "fixture-bank",
            "fake_app": "1",
            "official_pkg": "com.official.bank",
            "official_app_name": "Official Bank",
            "_gold_label": "malicious",
        },
        "ab_conflict": {
            "sample_id": "P9FIXTUREABCONFLICT0000000001",
            "package_name": "com.malapp.fixture.conflict",
            "app_name": "fixture-conflict",
            "engine_a_label": "malicious",
            "engine_b_label": "benign",
            "engine_360_type": "研判恶意样本",
            "engine_cm_type": "研判白样本",
            "_gold_label": "malicious",
        },
        "static_risk": {
            "sample_id": "P9FIXTURESTATICRISK0000000001",
            "package_name": "com.malapp.fixture.static",
            "app_name": "fixture-static",
            "packer": "qihoo",
            "sdk_list": "com.unsafe.sdk",
            "permissions": "android.permission.SEND_SMS",
            "_gold_label": "malicious",
        },
        "missing_fields": {
            "sample_id": "P9FIXTUREMISSINGFIELDS0000001",
            "_gold_label": "malicious",
        },
        "malicious": {
            "sample_id": "P9FIXTUREMALICIOUS00000000001",
            "package_name": "com.malapp.fixture.malicious",
            "app_name": "fixture-malicious",
            "signature_status": "invalid",
            "_gold_label": "malicious",
        },
        "benign": {
            "sample_id": "P9FIXTUREBENIGN00000000000001",
            "package_name": "com.android.vending",
            "app_name": "fixture-benign",
            "signature_status": "valid",
            "certificate_fingerprint": "abc",
            "_gold_label": "benign",
        },
    }
    if stratum not in fixtures:
        raise ValueError(f"no fixture for stratum {stratum}")
    return dict(fixtures[stratum])


def score_reports(
    reports: list[dict[str, Any]],
    *,
    requirements_by_sample: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    by_mode: dict[str, list[dict[str, Any]]] = defaultdict(list)
    scored = []
    v0_by_sample = {}
    trajectories = [extract_trajectory(report) for report in reports]
    for item in trajectories:
        if item.get("orchestration_mode") == "v0_fixed":
            v0_by_sample[item.get("sample_id")] = item
    requirements_by_sample = requirements_by_sample or {}
    for item in trajectories:
        requirements = requirements_by_sample.get(str(item.get("sample_id") or ""))
        metrics = score_trajectory(
            item,
            v0_reference=v0_by_sample.get(item.get("sample_id")),
            expected_evidence_requirements=requirements,
        )
        record = {**item, "metrics": metrics}
        scored.append(record)
        by_mode[item.get("orchestration_mode") or "v0_fixed"].append(metrics)
    invokes_models = any(item.get("invokes_models") for item in trajectories)
    invokes_api = any(item.get("invokes_api") for item in trajectories)
    return {
        "created_at": now_iso(),
        "trajectories": scored,
        "comparison": compare_variants(by_mode),
        "invokes_models": invokes_models,
        "invokes_api": invokes_api,
        "cache_hits": sum(1 for item in trajectories if item.get("cache_hit")),
    }


def slim_trajectory_summary(result: dict[str, Any], manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = manifest or {}
    return {
        "created_at": result.get("created_at") or now_iso(),
        "manifest_sha256": manifest.get("manifest_sha256") or result.get("manifest_sha256"),
        "manifest_size": manifest.get("size") or result.get("sample_count"),
        "source": manifest.get("source"),
        "source_sha256": manifest.get("source_sha256"),
        "runtime_snapshot_id": manifest.get("runtime_snapshot_id"),
        "debate_mode": manifest.get("debate_mode") or DEBATE_MODE,
        "eval_variant": manifest.get("eval_variant") or EVAL_VARIANT,
        "sample_count": result.get("sample_count"),
        "backend": result.get("backend"),
        "invokes_models": result.get("invokes_models"),
        "invokes_api": result.get("invokes_api"),
        "cache_hits": result.get("cache_hits"),
        "errors": result.get("errors") or [],
        "strata": manifest.get("strata"),
        "stratum_waivers": manifest.get("stratum_waivers") or [],
        "comparison": result.get("comparison"),
        "isolated": bool(result.get("isolated_data_dir") or result.get("data_dir")),
        "cache_proven_clean": int(result.get("cache_hits") or 0) == 0,
    }


def prepare_rule_trajectory_sample(sample: dict[str, Any]) -> dict[str, Any]:
    prepared = dict(sample)
    prepared.setdefault("force_engine_c", True)
    evaluation_config = dict(prepared.get("evaluation_config") or {})
    evaluation_config.setdefault("debate_mode", DEBATE_MODE)
    evaluation_config.setdefault("xgb_mode", "off")
    prepared["evaluation_config"] = evaluation_config
    return prepared


def rule_trajectory_environment(mode: str, *, data_dir: str = "") -> dict[str, str]:
    if mode not in ORCHESTRATION_ENV:
        raise ValueError(f"unsupported orchestration mode: {mode}")
    env = {**RULE_TRAJECTORY_ENV, **ORCHESTRATION_ENV[mode]}
    if data_dir:
        env["MALAPP_DATA_DIR"] = data_dir
    return env


def _swap_environ(env: dict[str, str]) -> dict[str, str | None]:
    previous: dict[str, str | None] = {}
    for key, value in env.items():
        previous[key] = os.environ.get(key)
        os.environ[key] = value
    return previous


def _restore_environ(previous: dict[str, str | None]) -> None:
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _snapshot_module_paths() -> dict[tuple[str, str], Any]:
    snapshot: dict[tuple[str, str], Any] = {}
    for name, module in list(sys.modules.items()):
        if not name.startswith("malapp"):
            continue
        for attr in _PATH_ATTRS:
            if hasattr(module, attr):
                snapshot[(name, attr)] = getattr(module, attr)
    return snapshot


def _restore_module_paths(snapshot: dict[tuple[str, str], Any]) -> None:
    for (name, attr), value in snapshot.items():
        module = sys.modules.get(name)
        if module is not None:
            setattr(module, attr, value)


def bind_isolated_data_dir(data_dir: str | Path) -> Path:
    target = Path(data_dir).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    os.environ["MALAPP_DATA_DIR"] = str(target)
    from malapp.config.paths import initialize_runtime_files

    initialize_runtime_files(target)
    for name, module in list(sys.modules.items()):
        if not name.startswith("malapp"):
            continue
        for attr, builder in _PATH_ATTRS.items():
            if hasattr(module, attr):
                setattr(module, attr, builder(target))
    return target


def run_rule_trajectory_benchmark(
    samples: list[dict[str, Any]],
    *,
    modes: tuple[str, ...] = ORCHESTRATION_MODES,
    judge_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    data_dir: str | Path | None = None,
    requirements_by_sample: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Run V0/V1/V2 on the same samples using the rule backend. No LLM/API calls."""
    workdir = Path(data_dir) if data_dir else Path(tempfile.mkdtemp(prefix="malapp-traj-"))
    path_snapshot = _snapshot_module_paths()
    previous_env = _swap_environ(rule_trajectory_environment(modes[0], data_dir=str(workdir)))
    reports: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    isolated = ""
    try:
        isolated = str(bind_isolated_data_dir(workdir))
        if judge_fn is None:
            from malapp.application import judgement as judgement_mod

            judgement_mod.init_db()
            judge_fn = judgement_mod.judge
        for mode in modes:
            mode_env = _swap_environ(rule_trajectory_environment(mode, data_dir=isolated))
            try:
                bind_isolated_data_dir(isolated)
                for sample in samples:
                    prepared = prepare_rule_trajectory_sample(sample)
                    try:
                        report = judge_fn(prepared)
                        reports.append(report)
                        if report.get("cache_source") or (report.get("execution") or {}).get("history_reuse_source"):
                            errors.append(
                                {
                                    "sample_id": str(prepared.get("sample_id") or prepared.get("md5") or ""),
                                    "orchestration_mode": mode,
                                    "error": "strict_or_md5_cache_hit",
                                }
                            )
                    except Exception as exc:
                        errors.append(
                            {
                                "sample_id": str(prepared.get("sample_id") or prepared.get("md5") or ""),
                                "orchestration_mode": mode,
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
            finally:
                _restore_environ(mode_env)
                os.environ["MALAPP_DATA_DIR"] = isolated
    finally:
        _restore_environ(previous_env)
        _restore_module_paths(path_snapshot)
    scored = score_reports(reports, requirements_by_sample=requirements_by_sample)
    scored["errors"] = errors
    scored["sample_count"] = len(samples)
    scored["modes"] = list(modes)
    scored["data_dir"] = isolated
    scored["isolated_data_dir"] = isolated
    scored["backend"] = "rule"
    scored["debate_mode"] = DEBATE_MODE
    return scored


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
