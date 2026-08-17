"""Thin MCP adapter; all business execution stays in JudgementService."""

from __future__ import annotations

import os
import shutil
from typing import Any

from malapp.application.contracts import JudgementRequest
from malapp.application.service import JudgementService, get_judgement_service


class HermesAdapter:
    def __init__(self, service: JudgementService | None = None):
        self.service = service or get_judgement_service()

    def judge(self, arguments: dict[str, Any]) -> dict[str, Any]:
        sample = arguments.get("sample", arguments)
        request = JudgementRequest.from_payload(sample, source="hermes_mcp")
        return self.service.judge(request)


def hermes_status() -> dict[str, Any]:
    cli = shutil.which("hermes")
    external_runtime_url = os.getenv("MALAPP_HERMES_RUNTIME_URL", "").strip()
    return {
        "enabled": True,
        "official_runtime_available": bool(cli),
        "official_runtime_path": cli or "",
        "external_runtime_url_configured": bool(external_runtime_url),
        "mode": "judgement_service_adapter",
        "business_pipeline": JudgementService.pipeline,
        "capabilities": {
            "mcp_tools": True,
            "agent_orchestration": False,
            "authoritative_judgement_adapter": True,
        },
        "message": "Hermes 仅转换 MCP 请求；Agent 调度、降级和决策统一由 JudgementService 执行。",
    }
