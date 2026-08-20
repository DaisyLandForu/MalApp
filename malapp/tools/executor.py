"""Synchronous deterministic tool executor. No extra thread pool."""

from __future__ import annotations

import time
from typing import Any

from malapp.tools.base import ToolCall, ToolExecutionResult, ToolObservation, digest_value
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
        for name in names:
            call = ToolCall(tool_name=name, agent=agent, arguments={"sample_id": sample.get("sample_id")})
            input_digest = digest_value({"tool": name, "agent": agent, "arguments": call.arguments})
            started = time.monotonic()
            if name not in registered or name not in allowed:
                observation = ToolObservation(
                    tool_name=name,
                    agent=agent,
                    status="denied",
                    input_digest=input_digest,
                    output_digest="",
                    latency_ms=round((time.monotonic() - started) * 1000, 3),
                    error_type="denied",
                    error="tool_call_denied",
                    plan_id=plan_id,
                    run_id=run_id,
                )
                result.observations.append(observation)
                result.denied.append(name)
                continue
            tool = self.registry.get(name)
            try:
                facts = tool.run(sample, iocs=iocs or []) if tool is not None else {}
                if not isinstance(facts, dict):
                    facts = {"value": facts}
                observation = ToolObservation(
                    tool_name=name,
                    agent=agent,
                    status="completed",
                    input_digest=input_digest,
                    output_digest=digest_value(facts),
                    latency_ms=round((time.monotonic() - started) * 1000, 3),
                    facts=facts,
                    plan_id=plan_id,
                    run_id=run_id,
                )
            except TimeoutError as exc:
                observation = ToolObservation(
                    tool_name=name,
                    agent=agent,
                    status="timeout",
                    input_digest=input_digest,
                    output_digest="",
                    latency_ms=round((time.monotonic() - started) * 1000, 3),
                    error_type="timeout",
                    error=str(exc),
                    plan_id=plan_id,
                    run_id=run_id,
                )
            except Exception as exc:
                observation = ToolObservation(
                    tool_name=name,
                    agent=agent,
                    status="failed",
                    input_digest=input_digest,
                    output_digest="",
                    latency_ms=round((time.monotonic() - started) * 1000, 3),
                    error_type="exception",
                    error=f"{type(exc).__name__}: {exc}",
                    plan_id=plan_id,
                    run_id=run_id,
                )
            result.observations.append(observation)
            if observation.status == "completed":
                result.facts[name] = observation.facts
        return result
