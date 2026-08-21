"""Synchronous deterministic tool executor. No extra thread pool."""

from __future__ import annotations

import time
from typing import Any

from malapp.tools.base import (
    TOOL_PHASE_BY_STATUS,
    ToolCall,
    ToolExecutionResult,
    ToolObservation,
    clone_facts,
    digest_value,
    validate_tool_arguments,
)
from malapp.tools.registry import ToolRegistry


class ToolExecutor:
    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def execute(
        self,
        agent: str,
        allowlist: list[str] | tuple[str, ...],
        sample: dict[str, Any],
        *,
        iocs: list[dict[str, Any]] | None = None,
        requested: list[str] | None = None,
        plan_id: str = "",
        run_id: str = "",
    ) -> ToolExecutionResult:
        result = ToolExecutionResult()
        registered = set(self.registry.registered_names(agent))
        allowed = set(self.registry.effective(agent, allowlist))
        names = list(requested if requested is not None else allowlist)
        input_payload = {"sample": sample, "iocs": list(iocs or [])}
        for name in names:
            call = ToolCall(tool_name=name, agent=agent, arguments=dict(input_payload))
            arguments_valid, argument_errors = validate_tool_arguments(name, agent, call.arguments)
            input_digest = digest_value({"tool": name, "agent": agent, "arguments": call.arguments})
            started = time.monotonic()
            result.events.append(
                {
                    "phase": "tool_call_started",
                    "status": "running",
                    "tool_name": name,
                    "agent": agent,
                    "plan_id": plan_id,
                    "run_id": run_id,
                    "message": f"{name} started",
                }
            )
            if name not in registered or name not in allowed:
                observation = _observation(
                    name,
                    agent,
                    "denied",
                    input_digest,
                    started,
                    error_type="denied",
                    error="tool_call_denied",
                    plan_id=plan_id,
                    run_id=run_id,
                    arguments_valid=arguments_valid,
                    argument_errors=argument_errors,
                )
                result.observations.append(observation)
                result.denied.append(name)
                result.events.append(_event_from_observation(observation))
                continue
            tool = self.registry.get(name)
            try:
                raw = tool.run(sample, iocs=iocs or []) if tool is not None else {}
                facts = clone_facts(raw) if isinstance(raw, dict) else {"value": raw}
                observation = _observation(
                    name,
                    agent,
                    "completed",
                    input_digest,
                    started,
                    facts=facts,
                    output_digest=digest_value(facts),
                    plan_id=plan_id,
                    run_id=run_id,
                    arguments_valid=arguments_valid,
                    argument_errors=argument_errors,
                )
            except TimeoutError as exc:
                observation = _observation(
                    name,
                    agent,
                    "timeout",
                    input_digest,
                    started,
                    error_type="timeout",
                    error=str(exc),
                    plan_id=plan_id,
                    run_id=run_id,
                    arguments_valid=arguments_valid,
                    argument_errors=argument_errors,
                )
            except Exception as exc:
                observation = _observation(
                    name,
                    agent,
                    "failed",
                    input_digest,
                    started,
                    error_type="exception",
                    error=f"{type(exc).__name__}: {exc}",
                    plan_id=plan_id,
                    run_id=run_id,
                    arguments_valid=arguments_valid,
                    argument_errors=argument_errors,
                )
            result.observations.append(observation)
            result.events.append(_event_from_observation(observation))
            if observation.status == "completed":
                result.facts[name] = clone_facts(observation.facts)
        return result


def _observation(
    tool_name: str,
    agent: str,
    status: str,
    input_digest: str,
    started: float,
    *,
    facts: dict[str, Any] | None = None,
    output_digest: str = "",
    error_type: str = "",
    error: str = "",
    plan_id: str = "",
    run_id: str = "",
    arguments_valid: bool = True,
    argument_errors: list[str] | None = None,
) -> ToolObservation:
    copied = clone_facts(facts or {})
    return ToolObservation(
        tool_name=tool_name,
        agent=agent,
        status=status,
        input_digest=input_digest,
        output_digest=output_digest,
        latency_ms=round((time.monotonic() - started) * 1000, 3),
        facts=copied,
        error_type=error_type,
        error=error,
        plan_id=plan_id,
        run_id=run_id,
        phase=TOOL_PHASE_BY_STATUS.get(status, status),
        arguments_valid=bool(arguments_valid),
        argument_errors=list(argument_errors or []),
    )


def _event_from_observation(observation: ToolObservation) -> dict[str, Any]:
    return {
        "phase": observation.phase,
        "status": observation.status,
        "tool_name": observation.tool_name,
        "agent": observation.agent,
        "plan_id": observation.plan_id,
        "run_id": observation.run_id,
        "error_type": observation.error_type,
        "message": observation.error or observation.status,
    }
