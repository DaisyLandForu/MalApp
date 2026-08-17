"""MCP tool declaration mapped to the thin Hermes adapter."""

from __future__ import annotations

from typing import Any, Callable

from integrations.hermes.adapter import HermesAdapter

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]

_ADAPTER = HermesAdapter()


def run_full_judgement(arguments: dict[str, Any]) -> dict[str, Any]:
    return _ADAPTER.judge(arguments)


TOOL_HANDLERS: dict[str, ToolHandler] = {
    "malapp_full_judgement": run_full_judgement,
}

TOOL_DEFINITIONS = [
    {
        "name": "malapp_full_judgement",
        "description": (
            "Submit one malicious-APP sample to the authoritative MalApp JudgementService. "
            "The service owns normalization, four-agent runtime, RAG, XGBoost, debate, "
            "degradation policy, final decision, trace, and persistence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sample": {
                    "type": "object",
                    "description": "Complete malicious-APP sample JSON.",
                    "additionalProperties": True,
                }
            },
            "required": ["sample"],
            "additionalProperties": False,
        },
    }
]
