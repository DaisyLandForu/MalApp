from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

AgentCallable = Callable[[], Any]
FallbackCallable = Callable[[str, str], Any]


@dataclass
class AgentSpec:
    name: str
    run: AgentCallable
    fallback: FallbackCallable
    timeout_ms: int = 2500
    enabled: bool = True
    max_restarts: int = 1


@dataclass
class AgentState:
    name: str
    status: str = "created"
    generation: int = 0
    restart_count: int = 0
    last_error: str = ""
    last_latency_ms: int = 0
    config: dict[str, Any] = field(default_factory=dict)


def run_agent_cluster(
    specs: list[AgentSpec],
    runtime_config: dict[str, Any] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Initialize, configure, health-check, and run agents concurrently.

    Python threads cannot be force-killed safely, so timeout熔断 returns a
    fallback block immediately and shuts the executor down with `wait=False`.
    """
    request_id = uuid.uuid4().hex[:12]
    config = runtime_config or {}
    agent_overrides = config.get("agents", {}) if isinstance(config.get("agents"), dict) else {}
    global_timeout = int(config.get("default_timeout_ms", 2500))
    max_workers = max(1, min(int(config.get("max_workers", len(specs) or 1)), len(specs) or 1))

    configured = [apply_config(spec, agent_overrides.get(spec.name, {}), global_timeout) for spec in specs]
    states = {spec.name: initialize_agent(spec) for spec in configured}
    lifecycle_events: list[dict[str, Any]] = []
    results_by_name: dict[str, Any] = {}

    for spec in configured:
        state = states[spec.name]
        lifecycle_events.append(event(spec.name, "initialized", state.status, "agent initialized"))
        if not spec.enabled:
            state.status = "offline"
            results_by_name[spec.name] = spec.fallback(spec.name, "agent disabled by runtime config")
            lifecycle_events.append(event(spec.name, "offline", state.status, "agent disabled"))

    runnable = [spec for spec in configured if spec.enabled]
    for spec in runnable:
        if not health_check(states[spec.name]):
            restarted = restart_agent(states[spec.name], spec)
            lifecycle_events.append(event(spec.name, "restart", states[spec.name].status, "health check failed"))
            if not restarted:
                states[spec.name].status = "degraded"
                results_by_name[spec.name] = spec.fallback(spec.name, "health check failed; agent degraded")
                lifecycle_events.append(event(spec.name, "degraded", states[spec.name].status, "restart failed"))

    runnable = [spec for spec in runnable if spec.name not in results_by_name]
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="agent")
    pending = {}
    started_at = {}
    try:
        for spec in runnable:
            states[spec.name].status = "running"
            states[spec.name].config = {
                "timeout_ms": spec.timeout_ms,
                "enabled": spec.enabled,
                "max_restarts": spec.max_restarts,
            }
            started_at[spec.name] = time.monotonic()
            pending[executor.submit(execute_with_restarts, spec)] = spec
            lifecycle_events.append(event(spec.name, "started", "running", "agent execution started"))

        while pending:
            now = time.monotonic()
            for future, spec in list(pending.items()):
                elapsed_ms = int((now - started_at[spec.name]) * 1000)
                if future.done():
                    ok, result, restart_count, error = future.result()
                    states[spec.name].restart_count = restart_count
                    states[spec.name].generation += restart_count
                    if ok:
                        results_by_name[spec.name] = result
                        states[spec.name].status = "healthy"
                        states[spec.name].last_latency_ms = elapsed_ms
                        if restart_count:
                            lifecycle_events.append(
                                event(spec.name, "restart", "restarted", f"agent recovered after {restart_count} restart(s)")
                            )
                        lifecycle_events.append(event(spec.name, "completed", "healthy", f"completed in {elapsed_ms} ms"))
                    else:
                        states[spec.name].last_error = error
                        states[spec.name].status = "degraded"
                        states[spec.name].last_latency_ms = elapsed_ms
                        results_by_name[spec.name] = spec.fallback(spec.name, f"agent failed after restart: {error}")
                        lifecycle_events.append(event(spec.name, "degraded", "degraded", error))
                    pending.pop(future)
                elif elapsed_ms >= spec.timeout_ms:
                    cancelled = future.cancel()
                    states[spec.name].status = "timeout"
                    states[spec.name].last_latency_ms = elapsed_ms
                    states[spec.name].last_error = "timeout"
                    results_by_name[spec.name] = spec.fallback(spec.name, f"timeout after {spec.timeout_ms} ms")
                    lifecycle_events.append(
                        event(spec.name, "timeout", "timeout", f"timeout after {spec.timeout_ms} ms; cancelled={cancelled}")
                    )
                    pending.pop(future)
            if pending:
                time.sleep(0.01)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    ordered_results = [results_by_name[spec.name] for spec in configured if spec.name in results_by_name]
    runtime_report = {
        "request_id": request_id,
        "scheduler": {
            "type": "thread_pool",
            "max_workers": max_workers,
            "default_timeout_ms": global_timeout,
            "concurrent": True,
        },
        "lifecycle": lifecycle_events,
        "agents": {
            name: {
                "status": state.status,
                "generation": state.generation,
                "restart_count": state.restart_count,
                "last_error": state.last_error,
                "last_latency_ms": state.last_latency_ms,
                "config": state.config,
            }
            for name, state in states.items()
        },
    }
    return ordered_results, runtime_report


def apply_config(spec: AgentSpec, override: Any, default_timeout_ms: int) -> AgentSpec:
    override = override if isinstance(override, dict) else {}
    return AgentSpec(
        name=spec.name,
        run=spec.run,
        fallback=spec.fallback,
        timeout_ms=int(override.get("timeout_ms", spec.timeout_ms or default_timeout_ms)),
        enabled=bool(override.get("enabled", spec.enabled)),
        max_restarts=int(override.get("max_restarts", spec.max_restarts)),
    )


def initialize_agent(spec: AgentSpec) -> AgentState:
    return AgentState(name=spec.name, status="initialized", generation=1)


def health_check(state: AgentState) -> bool:
    return state.status in {"initialized", "healthy", "running"}


def restart_agent(state: AgentState, spec: AgentSpec) -> bool:
    if state.restart_count >= spec.max_restarts:
        return False
    state.restart_count += 1
    state.generation += 1
    state.status = "restarted"
    return True


def execute_with_restarts(spec: AgentSpec) -> tuple[bool, Any, int, str]:
    restart_count = 0
    while True:
        try:
            return True, spec.run(), restart_count, ""
        except Exception as exc:
            if restart_count >= spec.max_restarts:
                return False, None, restart_count, str(exc)
            restart_count += 1


def event(agent: str, phase: str, status: str, message: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "phase": phase,
        "status": status,
        "message": message,
        "ts": time.time(),
    }
