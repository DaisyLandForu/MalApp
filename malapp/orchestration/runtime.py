"""Single runtime for registration, parallel execution, retry, timeout, and trace."""

from __future__ import annotations

import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from malapp.agents.base import Agent, AgentContext, AgentResult, EvidenceBlock


@dataclass(frozen=True)
class AgentExecutionPolicy:
    timeout_ms: int = 2500
    max_retries: int = 1
    enabled: bool = True


class AgentRegistry:
    def __init__(self, agents: list[Agent] | None = None):
        self._agents: dict[str, Agent] = {}
        for agent in agents or []:
            self.register(agent)

    def register(self, agent: Agent) -> None:
        name = str(agent.name).strip()
        if not name:
            raise ValueError("agent name is required")
        if name in self._agents:
            raise ValueError(f"duplicate agent registration: {name}")
        self._agents[name] = agent

    def all(self) -> list[Agent]:
        return list(self._agents.values())


class AgentRuntime:
    def __init__(self, registry: AgentRegistry):
        self.registry = registry

    def execute(
        self,
        sample: dict[str, Any],
        *,
        iocs: list[dict[str, Any]] | None = None,
        config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[list[AgentResult], dict[str, Any]]:
        request_id = uuid.uuid4().hex[:16]
        runtime_config = config if isinstance(config, dict) else {}
        agents = self.registry.all()
        max_workers = bounded_int(runtime_config.get("max_workers"), len(agents) or 1, 1, len(agents) or 1)
        default_timeout = bounded_int(runtime_config.get("default_timeout_ms"), 2500, 1, 120_000)
        default_retries = bounded_int(runtime_config.get("default_max_retries"), 1, 0, 5)
        overrides = runtime_config.get("agents") if isinstance(runtime_config.get("agents"), dict) else {}
        faults = sample.get("agent_runtime_faults") if isinstance(sample.get("agent_runtime_faults"), dict) else {}
        context = AgentContext(
            sample=sample,
            iocs=tuple(iocs or []),
            request_id=request_id,
            metadata=dict(metadata or {}),
        )
        policies = {
            agent.name: execution_policy(agent.name, overrides, default_timeout, default_retries)
            for agent in agents
        }
        started_wall = time.time()
        started_mono = time.monotonic()
        lifecycle: list[dict[str, Any]] = []
        traces: dict[str, list[dict[str, Any]]] = {agent.name: [] for agent in agents}
        results: dict[str, AgentResult] = {}
        futures: dict[Future[tuple[AgentResult, list[dict[str, Any]]]], Agent] = {}
        future_started: dict[str, float] = {}
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="malapp-agent")
        try:
            for agent in agents:
                policy = policies[agent.name]
                append_event(lifecycle, traces[agent.name], agent.name, "registered", "created", "agent registered")
                if not policy.enabled:
                    result = degraded_result(agent.name, "agent disabled by runtime config", "disabled", "skipped")
                    results[agent.name] = result
                    append_event(lifecycle, traces[agent.name], agent.name, "skipped", "disabled", result.error or "")
                    continue
                future_started[agent.name] = time.monotonic()
                append_event(lifecycle, traces[agent.name], agent.name, "started", "running", "agent execution started")
                futures[executor.submit(run_with_retries, agent, context, policy, faults.get(agent.name))] = agent

            while futures:
                now = time.monotonic()
                for future, agent in list(futures.items()):
                    policy = policies[agent.name]
                    elapsed_ms = round((now - future_started[agent.name]) * 1000, 3)
                    if future.done():
                        result, attempt_events = safe_future_result(future, agent.name)
                        traces[agent.name].extend(attempt_events)
                        result.latency_ms = elapsed_ms
                        results[agent.name] = result
                        phase = "completed" if result.status == "completed" else "failed"
                        append_event(
                            lifecycle,
                            traces[agent.name],
                            agent.name,
                            phase,
                            result.status,
                            result.error or f"completed in {elapsed_ms:.3f} ms",
                        )
                        futures.pop(future)
                    elif elapsed_ms >= policy.timeout_ms:
                        future.cancel()
                        result = degraded_result(
                            agent.name,
                            f"timeout after {policy.timeout_ms} ms",
                            "timeout",
                            "timeout",
                            latency_ms=elapsed_ms,
                        )
                        results[agent.name] = result
                        append_event(lifecycle, traces[agent.name], agent.name, "timeout", "timeout", result.error or "")
                        futures.pop(future)
                if futures:
                    time.sleep(0.005)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        ordered_results = [results[agent.name] for agent in agents]
        runtime_status = "healthy" if all(item.status == "completed" for item in ordered_results) else "degraded"
        report = {
            "request_id": request_id,
            "status": runtime_status,
            "started_at": started_wall,
            "latency_ms": round((time.monotonic() - started_mono) * 1000, 3),
            "scheduler": {
                "type": "agent_runtime",
                "max_workers": max_workers,
                "concurrent": True,
                "default_timeout_ms": default_timeout,
                "default_max_retries": default_retries,
            },
            "lifecycle": lifecycle,
            "agents": {
                item.agent_name: {
                    "status": item.status,
                    "score": item.score,
                    "confidence": item.confidence,
                    "last_latency_ms": item.latency_ms,
                    "last_error": item.error or "",
                    "failure_type": item.failure_type,
                    "attempts": item.attempts,
                    "restart_count": max(0, item.attempts - 1),
                    "config": {
                        "timeout_ms": policies[item.agent_name].timeout_ms,
                        "max_retries": policies[item.agent_name].max_retries,
                        "enabled": policies[item.agent_name].enabled,
                    },
                    "trace": traces[item.agent_name],
                }
                for item in ordered_results
            },
        }
        return ordered_results, report


def execution_policy(
    agent_name: str,
    overrides: dict[str, Any],
    default_timeout: int,
    default_retries: int,
) -> AgentExecutionPolicy:
    override = overrides.get(agent_name) if isinstance(overrides.get(agent_name), dict) else {}
    retries = override.get("max_retries", override.get("max_restarts", default_retries))
    return AgentExecutionPolicy(
        timeout_ms=bounded_int(override.get("timeout_ms"), default_timeout, 1, 120_000),
        max_retries=bounded_int(retries, default_retries, 0, 5),
        enabled=bool(override.get("enabled", True)),
    )


def run_with_retries(
    agent: Agent,
    context: AgentContext,
    policy: AgentExecutionPolicy,
    fault: Any,
) -> tuple[AgentResult, list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    fault_config = fault if isinstance(fault, dict) else {}
    for attempt in range(1, policy.max_retries + 2):
        try:
            inject_fault(agent.name, fault_config)
            result = agent.run(context)
            if result.agent_name != agent.name:
                raise ValueError(f"agent result name mismatch: expected {agent.name}, got {result.agent_name}")
            result.attempts = attempt
            events.append(runtime_event(agent.name, "attempt", "completed", f"attempt {attempt} completed"))
            return result, events
        except Exception as exc:
            events.append(runtime_event(agent.name, "attempt", "failed", f"attempt {attempt}: {exc}"))
            if attempt > policy.max_retries:
                timed_out = isinstance(exc, TimeoutError)
                result = degraded_result(
                    agent.name,
                    str(exc),
                    "timeout" if timed_out else "exception",
                    "timeout" if timed_out else "failed",
                    attempts=attempt,
                )
                return result, events
    raise AssertionError("unreachable agent retry state")


def inject_fault(agent_name: str, fault: dict[str, Any]) -> None:
    sleep_ms = bounded_int(fault.get("sleep_ms"), 0, 0, 120_000)
    if sleep_ms:
        time.sleep(sleep_ms / 1000)
    failures_left = bounded_int(fault.get("failures"), 0, 0, 100)
    if failures_left:
        fault["failures"] = failures_left - 1
        raise RuntimeError(f"simulated {agent_name} failure")


def safe_future_result(
    future: Future[tuple[AgentResult, list[dict[str, Any]]]],
    agent_name: str,
) -> tuple[AgentResult, list[dict[str, Any]]]:
    try:
        return future.result()
    except Exception as exc:
        return degraded_result(agent_name, str(exc), "runtime", "failed"), []


def degraded_result(
    agent_name: str,
    error: str,
    failure_type: str,
    status: str,
    *,
    latency_ms: float = 0.0,
    attempts: int = 1,
) -> AgentResult:
    block = EvidenceBlock(
        agent=agent_name,
        claim=f"{agent_name} 已降级。",
        evidence=[error],
        confidence=0.0,
        missing_fields=["agent_runtime"],
        score=0.0,
        evidence_items=[
            {
                "evidence_type": "agent_runtime_failure",
                "source_fields": [],
                "source_values": [],
                "direction": "insufficient",
                "strength": 0.0,
                "description": error,
            }
        ],
        status="degraded",
        rule_score=0.0,
    )
    return AgentResult(
        agent_name=agent_name,
        status=status,
        score=None,
        evidence=[block],
        confidence=0.0,
        latency_ms=latency_ms,
        error=error,
        failure_type=failure_type,
        attempts=attempts,
    )


def append_event(
    lifecycle: list[dict[str, Any]],
    trace: list[dict[str, Any]],
    agent: str,
    phase: str,
    status: str,
    message: str,
) -> None:
    item = runtime_event(agent, phase, status, message)
    lifecycle.append(item)
    trace.append(dict(item))


def runtime_event(agent: str, phase: str, status: str, message: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "phase": phase,
        "status": status,
        "message": message,
        "ts": time.time(),
    }


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))
