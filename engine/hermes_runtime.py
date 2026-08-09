from __future__ import annotations

import shutil
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Any

from engine.agent_output import validate_and_repair_evidence_blocks
from engine.hermes_bridge import TOOL_HANDLERS
from engine.pipeline import EvidenceBlock, fallback_agent_block


SPECIALISTS = (
    ("malapp_static_analysis", "static_analysis"),
    ("malapp_threat_intelligence", "threat_intel"),
    ("malapp_impersonation_analysis", "impersonation"),
    ("malapp_business_labeling", "business_label"),
)


def hermes_status() -> dict[str, Any]:
    cli = shutil.which("hermes")
    external_runtime_enabled = os.getenv("MALAPP_HERMES_EXTERNAL_RUNTIME", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    external_runtime_url = os.getenv("MALAPP_HERMES_RUNTIME_URL", "").strip()
    if external_runtime_enabled:
        return {
            "enabled": True,
            "official_runtime_available": bool(cli),
            "official_runtime_path": cli or "",
            "external_runtime_enabled": True,
            "external_runtime_url": external_runtime_url,
            "mode": "external_runtime",
            "capabilities": {
                "long_term_memory": True,
                "message_gateway": True,
                "subagent_lifecycle_protocol": True,
                "mcp_tools": True,
            },
            "message": (
                "已配置外部 Hermes Runtime。四智能体仍通过本项目 MCP 工具执行领域分析，"
                "长期记忆、消息网关和子代理生命周期协议由外部 Hermes Runtime 承载。"
            ),
        }
    return {
        "enabled": True,
        "official_runtime_available": bool(cli),
        "official_runtime_path": cli or "",
        "mode": "official_cli" if cli else "embedded_mcp",
        "external_runtime_enabled": False,
        "external_runtime_url": "",
        "capabilities": {
            "long_term_memory": bool(cli),
            "message_gateway": bool(cli),
            "subagent_lifecycle_protocol": False,
            "mcp_tools": True,
        },
        "message": (
            "官方 Hermes CLI 已可用，可注册本项目 MCP 工具和 Skills。"
            if cli
            else "当前使用内嵌 Hermes MCP 兼容模式：具备四智能体并行委派和工具隔离，但长期记忆、消息网关和完整子代理生命周期需接入外部 Hermes Runtime。"
        ),
    }


def run_hermes_supervisor(sample: dict[str, Any]) -> tuple[list[EvidenceBlock], dict[str, Any]]:
    request_id = f"hermes-{uuid.uuid4().hex[:12]}"
    started = time.perf_counter()
    results: dict[str, EvidenceBlock] = {}
    states: dict[str, dict[str, Any]] = {}
    lifecycle: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="hermes-specialist") as executor:
        futures = {}
        for tool_name, agent_name in SPECIALISTS:
            lifecycle.append(event(agent_name, "delegated", "running", tool_name))
            futures[executor.submit(TOOL_HANDLERS[tool_name], {"sample": sample})] = (
                tool_name,
                agent_name,
                time.perf_counter(),
            )
        for future in as_completed(futures):
            tool_name, agent_name, agent_started = futures[future]
            latency = int((time.perf_counter() - agent_started) * 1000)
            try:
                payload = future.result()
                block = EvidenceBlock(**payload["evidence_block"])
                results[agent_name] = block
                states[agent_name] = {
                    "status": "healthy",
                    "tool": tool_name,
                    "last_latency_ms": latency,
                    "last_error": "",
                }
                lifecycle.append(event(agent_name, "completed", "healthy", f"{tool_name} completed"))
            except Exception as exc:
                results[agent_name] = fallback_agent_block(agent_name, str(exc))
                states[agent_name] = {
                    "status": "degraded",
                    "tool": tool_name,
                    "last_latency_ms": latency,
                    "last_error": str(exc),
                }
                lifecycle.append(event(agent_name, "fallback", "degraded", str(exc)))

    ordered = [results[agent_name] for _, agent_name in SPECIALISTS]
    ordered, validation = validate_and_repair_evidence_blocks(ordered)
    status = hermes_status()
    runtime = {
        "request_id": request_id,
        "orchestrator": "hermes",
        "hermes": status,
        "scheduler": {
            "type": "hermes_delegate_task",
            "transport": "mcp",
            "mode": status["mode"],
            "max_workers": 4,
            "concurrent": True,
        },
        "lifecycle": lifecycle,
        "agents": states,
        "validation": validation,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "tool_outputs_immutable": True,
    }
    return ordered, runtime


def event(agent: str, phase: str, status: str, message: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "phase": phase,
        "status": status,
        "message": message,
        "ts": time.time(),
    }
