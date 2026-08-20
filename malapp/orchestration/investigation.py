"""Planner-driven investigation orchestrator. Reuses AgentRuntime as the execution kernel."""

from __future__ import annotations

from typing import Any

from malapp.agents.base import Agent, AgentResult, EvidenceBlock
from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.orchestration.degradation import evaluate_degradation
from malapp.orchestration.evidence_gate import EvidenceGateResult, evaluate_evidence_gate
from malapp.orchestration.planner import (
    InvestigationPlan,
    build_investigation_plan,
    disabled_agent_names,
    enable_agents,
    extend_tool_allowlist,
    orchestration_mode,
    plan_event,
    planner_enabled,
    skipped_by_plan_result,
    tool_runtime_enabled,
)
from malapp.orchestration.runtime import AgentRegistry, AgentRuntime, append_event, degraded_result


def run_investigation(
    sample: dict[str, Any],
    iocs: list[dict[str, Any]],
    *,
    run_id: str,
    agents: list[Agent],
    expert_provider: Any | None = None,
) -> tuple[list[EvidenceBlock], dict[str, Any], list[AgentResult]]:
    agents_by_name = {agent.name: agent for agent in agents}
    events: list[dict[str, Any]] = []
    plan, plan_events = build_investigation_plan(sample, iocs)
    events.extend(_with_run_id(plan_events, run_id, plan))
    recovery_used = 0
    executed_tools: dict[str, list[str]] = {name: [] for name in AGENT_ORDER}

    if not planner_enabled():
        results, runtime_report = _execute_v0(
            sample,
            iocs,
            run_id=run_id,
            agents_by_name=agents_by_name,
            plan=plan,
        )
        runtime_report = _merge_runtime_report(
            runtime_report, results, plan, events, EvidenceGateResult(), recovery_used, expert_provider
        )
        blocks = [block for result in results for block in result.evidence]
        runtime_report["results"] = [result.to_dict() for result in results]
        if expert_provider is not None:
            runtime_report["expert_runtime"] = expert_provider.manifest()
        return blocks, runtime_report, results

    results, runtime_report = _execute_plan(
        plan,
        sample,
        iocs,
        run_id=run_id,
        agents_by_name=agents_by_name,
        events=events,
        executed_tools=executed_tools,
    )

    gate = evaluate_evidence_gate(
        plan,
        results,
        sample=sample,
        iocs=iocs,
        executed_tools=executed_tools,
    )
    events.append(
        _gate_event(
            "evidence_gate_passed" if gate.sufficient else "evidence_gate_failed",
            gate,
            plan,
            run_id,
        )
    )
    if not gate.sufficient and recovery_used < 1:
        recovery_used += 1
        results, runtime_report, plan = _recover(
            plan,
            gate,
            results,
            runtime_report,
            sample,
            iocs,
            run_id=run_id,
            agents_by_name=agents_by_name,
            events=events,
            executed_tools=executed_tools,
        )
        gate = evaluate_evidence_gate(
            plan,
            results,
            sample=sample,
            iocs=iocs,
            executed_tools=executed_tools,
        )
        events.append(
            _gate_event(
                "evidence_gate_passed" if gate.sufficient else "evidence_gate_failed",
                gate,
                plan,
                run_id,
                message="post-recovery gate",
            )
        )

    results = _ordered_results(results)
    runtime_report = _merge_runtime_report(runtime_report, results, plan, events, gate, recovery_used, expert_provider)
    blocks = [block for result in results for block in result.evidence]
    runtime_report["results"] = [result.to_dict() for result in results]
    if expert_provider is not None:
        runtime_report["expert_runtime"] = expert_provider.manifest()
    return blocks, runtime_report, results


def _execute_v0(
    sample: dict[str, Any],
    iocs: list[dict[str, Any]],
    *,
    run_id: str,
    agents_by_name: dict[str, Agent],
    plan: InvestigationPlan,
) -> tuple[list[AgentResult], dict[str, Any]]:
    ordered = [agents_by_name[name] for name in AGENT_ORDER if name in agents_by_name]
    config = sample.get("agent_runtime_config") if isinstance(sample.get("agent_runtime_config"), dict) else {}
    results, runtime_report = AgentRuntime(AgentRegistry(ordered)).execute(
        sample,
        iocs=iocs,
        config=config,
        metadata=_execution_metadata(plan),
        run_id=run_id,
    )
    return list(results), runtime_report


def _execute_plan(
    plan: InvestigationPlan,
    sample: dict[str, Any],
    iocs: list[dict[str, Any]],
    *,
    run_id: str,
    agents_by_name: dict[str, Agent],
    events: list[dict[str, Any]],
    executed_tools: dict[str, list[str]],
    only: list[str] | None = None,
) -> tuple[list[AgentResult], dict[str, Any]]:
    selected = [
        name
        for name in (only or plan.enabled_agents())
        if name in agents_by_name and name not in disabled_agent_names(sample)
    ]
    metadata = _execution_metadata(plan)
    runtime_report: dict[str, Any] = {
        "run_id": run_id,
        "status": "healthy",
        "scheduler": {"type": "agent_runtime", "concurrent": True},
        "lifecycle": [],
        "agents": {},
    }
    executed: list[AgentResult] = []
    if selected:
        results, runtime_report = AgentRuntime(AgentRegistry([agents_by_name[name] for name in selected])).execute(
            sample,
            iocs=iocs,
            config=_runtime_config_for_selected(sample),
            metadata=metadata,
            run_id=run_id,
        )
        executed = list(results)
        for result in executed:
            _record_executed_tools(result, executed_tools)

    by_name = {item.agent_name: item for item in executed}
    merged: list[AgentResult] = []
    for name in AGENT_ORDER:
        if name in by_name:
            merged.append(by_name[name])
            continue
        if only is not None:
            continue
        if name not in agents_by_name:
            continue
        agent_plan = plan.agents.get(name)
        if agent_plan and not agent_plan.enabled and agent_plan.reason_code == "disabled_agent_override":
            result = degraded_result(name, "agent disabled by runtime config", "disabled", "skipped")
            events.append(
                plan_event(
                    "agent_skipped_by_plan",
                    "disabled",
                    result.error or "",
                    plan=plan,
                    agent_name=name,
                    reason_code="disabled_agent_override",
                    run_id=run_id,
                )
            )
            merged.append(result)
            continue
        reason = agent_plan.reason_code if agent_plan else "skipped_by_plan"
        result = skipped_by_plan_result(name, reason)
        events.append(
            plan_event(
                "agent_skipped_by_plan",
                "skipped",
                result.error or "",
                plan=plan,
                agent_name=name,
                reason_code=reason,
                run_id=run_id,
            )
        )
        merged.append(result)
    runtime_report = _attach_placeholder_traces(runtime_report, merged, run_id)
    return merged, runtime_report


def _recover(
    plan: InvestigationPlan,
    gate: EvidenceGateResult,
    results: list[AgentResult],
    runtime_report: dict[str, Any],
    sample: dict[str, Any],
    iocs: list[dict[str, Any]],
    *,
    run_id: str,
    agents_by_name: dict[str, Agent],
    events: list[dict[str, Any]],
    executed_tools: dict[str, list[str]],
) -> tuple[list[AgentResult], dict[str, Any], InvestigationPlan]:
    mode = orchestration_mode()
    events.append(
        plan_event(
            "replan_started",
            "running",
            f"recovery mode={mode}",
            plan=plan,
            run_id=run_id,
            reason_code=",".join(gate.reason_codes),
        )
    )
    existing = {item.agent_name: item for item in results}
    newly_enabled: list[str] = []
    if mode == "v2_planner_tools" and gate.suggested_tools:
        for agent_name, tools in _tools_by_agent(gate.suggested_tools).items():
            if existing.get(agent_name) and existing[agent_name].status == "completed":
                extend_tool_allowlist(plan, agent_name, tools)
                newly_enabled.append(agent_name)
            elif agent_name in gate.suggested_agents and not _completed(existing.get(agent_name)):
                enable_agents(plan, [agent_name], "evidence_gate_replan")
                newly_enabled.append(agent_name)
    else:
        for name in gate.suggested_agents:
            current = existing.get(name)
            if _completed(current):
                continue
            if current and current.failure_type == "disabled":
                continue
            enable_agents(plan, [name], "evidence_gate_replan")
            newly_enabled.append(name)

    newly_enabled = [name for name in dict.fromkeys(newly_enabled) if name in agents_by_name]
    extra_report: dict[str, Any] = {"run_id": run_id, "agents": {}, "lifecycle": []}
    if newly_enabled:
        extra, extra_report = _execute_plan(
            plan,
            sample,
            iocs,
            run_id=run_id,
            agents_by_name=agents_by_name,
            events=events,
            executed_tools=executed_tools,
            only=newly_enabled,
        )
        for item in extra:
            existing[item.agent_name] = item
        runtime_report = _combine_runtime_reports(runtime_report, extra_report)

    events.append(
        plan_event(
            "replan_finished",
            "completed",
            "recovered agents: " + ",".join(newly_enabled) if newly_enabled else "no additional agents",
            plan=plan,
            run_id=run_id,
        )
    )
    merged = [existing[name] for name in AGENT_ORDER if name in existing]
    runtime_report = _attach_placeholder_traces(runtime_report, merged, run_id)
    return merged, runtime_report, plan


def _completed(result: AgentResult | None) -> bool:
    return bool(result) and result.status == "completed"


def _tools_by_agent(tools: list[str]) -> dict[str, list[str]]:
    from malapp.orchestration.planner import REGISTERED_TOOLS

    mapping: dict[str, list[str]] = {}
    for agent, registered in REGISTERED_TOOLS.items():
        hits = [name for name in tools if name in registered]
        if hits:
            mapping[agent] = hits
    return mapping


def _execution_metadata(plan: InvestigationPlan) -> dict[str, Any]:
    metadata = {
        "plan_id": plan.plan_id,
        "orchestration_mode": orchestration_mode(),
        "tool_allowlist": {name: list(plan.tool_names(name)) for name in AGENT_ORDER},
    }
    if tool_runtime_enabled():
        from malapp.tools.registry import default_registry

        metadata["tool_registry"] = default_registry()
    return metadata


def _record_executed_tools(result: AgentResult, executed_tools: dict[str, list[str]]) -> None:
    observations = result.artifacts.get("tool_observations") if isinstance(result.artifacts, dict) else None
    if not isinstance(observations, list):
        return
    names = [str(item.get("tool_name")) for item in observations if isinstance(item, dict) and item.get("tool_name")]
    current = list(executed_tools.get(result.agent_name, []))
    for name in names:
        if name not in current:
            current.append(name)
    executed_tools[result.agent_name] = current


def _runtime_config_for_selected(sample: dict[str, Any]) -> dict[str, Any]:
    config = sample.get("agent_runtime_config")
    return dict(config) if isinstance(config, dict) else {}


def _combine_runtime_reports(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    combined = dict(first or {})
    extra = second or {}
    combined["lifecycle"] = list(combined.get("lifecycle") or []) + list(extra.get("lifecycle") or [])
    agents = dict(combined.get("agents") if isinstance(combined.get("agents"), dict) else {})
    for name, state in (extra.get("agents") if isinstance(extra.get("agents"), dict) else {}).items():
        previous = agents.get(name)
        if isinstance(previous, dict) and isinstance(state, dict):
            merged_state = dict(state)
            merged_state["trace"] = list(previous.get("trace") or []) + list(state.get("trace") or [])
            agents[name] = merged_state
        else:
            agents[name] = state
    combined["agents"] = agents
    try:
        combined["latency_ms"] = round(float(combined.get("latency_ms") or 0) + float(extra.get("latency_ms") or 0), 3)
    except (TypeError, ValueError):
        pass
    return combined


def _attach_placeholder_traces(
    runtime_report: dict[str, Any],
    results: list[AgentResult],
    run_id: str,
) -> dict[str, Any]:
    report = dict(runtime_report or {})
    agents = dict(report.get("agents") if isinstance(report.get("agents"), dict) else {})
    for result in results:
        current = agents.get(result.agent_name)
        if isinstance(current, dict) and current.get("trace"):
            continue
        agents[result.agent_name] = _placeholder_agent_entry(result, run_id)
    report["agents"] = agents
    return report


def _placeholder_agent_entry(result: AgentResult, run_id: str) -> dict[str, Any]:
    lifecycle: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    append_event(lifecycle, trace, result.agent_name, "registered", "created", "agent registered", run_id)
    if result.failure_type == "disabled":
        append_event(lifecycle, trace, result.agent_name, "skipped", "disabled", result.error or "", run_id)
    elif result.failure_type == "skipped_by_plan":
        append_event(lifecycle, trace, result.agent_name, "skipped", "skipped", result.error or "", run_id)
    else:
        append_event(
            lifecycle,
            trace,
            result.agent_name,
            "completed" if result.status == "completed" else "failed",
            result.status,
            result.error or result.status,
            run_id,
        )
    return {
        "status": result.status,
        "score": result.score,
        "confidence": result.confidence,
        "last_latency_ms": result.latency_ms,
        "last_error": result.error or "",
        "failure_type": result.failure_type,
        "attempts": result.attempts,
        "restart_count": max(0, result.attempts - 1),
        "config": {"enabled": result.failure_type not in {"skipped_by_plan", "disabled"}},
        "trace": trace,
    }


def _ordered_results(results: list[AgentResult]) -> list[AgentResult]:
    by_name = {item.agent_name: item for item in results}
    return [by_name[name] for name in AGENT_ORDER if name in by_name]


def _merge_runtime_report(
    runtime_report: dict[str, Any],
    results: list[AgentResult],
    plan: InvestigationPlan,
    events: list[dict[str, Any]],
    gate: EvidenceGateResult,
    recovery_used: int,
    expert_provider: Any | None,
) -> dict[str, Any]:
    report = dict(runtime_report or {})
    agents_meta = dict(report.get("agents") if isinstance(report.get("agents"), dict) else {})
    for result in results:
        existing = agents_meta.get(result.agent_name)
        if isinstance(existing, dict) and existing.get("trace"):
            continue
        agents_meta[result.agent_name] = _placeholder_agent_entry(result, str(report.get("run_id") or ""))
    report["agents"] = agents_meta
    statuses = {item.status for item in results if item.failure_type != "skipped_by_plan"}
    if any(status in {"failed", "timeout"} for status in statuses):
        report["status"] = "degraded"
    elif statuses and statuses <= {"completed", "skipped"}:
        report["status"] = "healthy" if "completed" in statuses or not statuses else "healthy"
    report["investigation"] = {
        "plan": plan.to_dict(),
        "orchestration_mode": orchestration_mode(),
        "planner_enabled": planner_enabled(),
        "tool_runtime_enabled": tool_runtime_enabled(),
        "lifecycle": events,
        "evidence_gate": gate.to_dict(),
        "recovery_used": recovery_used,
        "degradation": evaluate_degradation(results),
        "tool_observations": [
            item
            for result in results
            if isinstance(result.artifacts, dict)
            for item in result.artifacts.get("tool_observations") or []
            if isinstance(item, dict)
        ],
    }
    if expert_provider is not None:
        report["expert_runtime"] = expert_provider.manifest()
    return report


def _with_run_id(events: list[dict[str, Any]], run_id: str, plan: InvestigationPlan) -> list[dict[str, Any]]:
    updated = []
    for item in events:
        value = dict(item)
        value["run_id"] = run_id
        value["plan_id"] = value.get("plan_id") or plan.plan_id
        value["plan_version"] = value.get("plan_version") or plan.plan_version
        updated.append(value)
    return updated


def _gate_event(
    phase: str,
    gate: EvidenceGateResult,
    plan: InvestigationPlan,
    run_id: str,
    message: str = "",
) -> dict[str, Any]:
    return plan_event(
        phase,
        "completed" if gate.sufficient else "failed",
        message or (",".join(gate.reason_codes) or "evidence sufficient"),
        plan=plan,
        run_id=run_id,
        reason_code=",".join(gate.reason_codes),
    )
