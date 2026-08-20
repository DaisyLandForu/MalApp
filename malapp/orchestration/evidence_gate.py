"""Deterministic evidence sufficiency gate. No LLM judge in V1."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from malapp.agents.base import AgentResult
from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.orchestration.planner import InvestigationPlan

IOC_MISSING_MARKERS = (
    "threat_intel_records",
    "control_url",
    "download_url",
    "domains",
    "ips",
    "ioc",
)
IMPERSONATION_MISSING_MARKERS = (
    "official_app_assets",
    "official_pkg",
    "official_app_name",
    "icon_path",
    "icon_base64",
    "icon_hash",
    "icon_text",
)


@dataclass
class EvidenceGateResult:
    sufficient: bool = True
    missing_fields: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    suggested_agents: list[str] = field(default_factory=list)
    suggested_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sufficient": self.sufficient,
            "missing_fields": list(self.missing_fields),
            "reason_codes": list(self.reason_codes),
            "suggested_agents": list(self.suggested_agents),
            "suggested_tools": list(self.suggested_tools),
        }


def _result_map(results: list[AgentResult]) -> dict[str, AgentResult]:
    return {item.agent_name: item for item in results}


def _missing_fields(result: AgentResult | None) -> list[str]:
    if result is None:
        return ["agent_result"]
    fields: list[str] = []
    for block in result.evidence:
        fields.extend(str(item) for item in (block.missing_fields or []) if str(item).strip())
    return fields


def _ran(result: AgentResult | None) -> bool:
    return bool(result) and result.status == "completed" and result.failure_type != "skipped_by_plan"


def evaluate_evidence_gate(
    plan: InvestigationPlan,
    results: list[AgentResult],
    *,
    executed_tools: dict[str, list[str]] | None = None,
) -> EvidenceGateResult:
    by_agent = _result_map(results)
    executed_tools = executed_tools or {}
    missing: list[str] = []
    reasons: list[str] = []
    suggested_agents: list[str] = []
    suggested_tools: list[str] = []
    focus = set(plan.risk_focus)

    static = by_agent.get("static_analysis")
    if not _ran(static):
        missing.append("static_analysis")
        reasons.append("static_evidence_missing")
        suggested_agents.append("static_analysis")

    if "network_ioc" in focus:
        threat = by_agent.get("threat_intel")
        threat_missing = _missing_fields(threat)
        ioc_missing = [item for item in threat_missing if any(marker in item for marker in IOC_MISSING_MARKERS)]
        if not _ran(threat):
            missing.append("threat_intel")
            reasons.append("network_ioc_agent_skipped")
            suggested_agents.append("threat_intel")
        elif ioc_missing:
            missing.extend(ioc_missing)
            reasons.append("network_ioc_fields_missing")
            for tool in ("ioc_lookup", "network_indicator"):
                if tool not in executed_tools.get("threat_intel", []):
                    suggested_tools.append(tool)
                    suggested_agents.append("threat_intel")

    if "impersonation" in focus:
        impersonation = by_agent.get("impersonation")
        impersonation_missing = _missing_fields(impersonation)
        asset_missing = [
            item
            for item in impersonation_missing
            if any(marker in item for marker in IMPERSONATION_MISSING_MARKERS)
        ]
        if not _ran(impersonation):
            missing.append("impersonation")
            reasons.append("impersonation_agent_skipped")
            suggested_agents.append("impersonation")
        elif asset_missing:
            missing.extend(asset_missing)
            reasons.append("impersonation_fields_missing")
            for tool in ("official_asset_match", "package_similarity", "certificate_comparison"):
                if tool not in executed_tools.get("impersonation", []):
                    suggested_tools.append(tool)
                    suggested_agents.append("impersonation")

    unique_agents = [name for name in AGENT_ORDER if name in dict.fromkeys(suggested_agents)]
    unique_tools = list(dict.fromkeys(suggested_tools))
    unique_missing = list(dict.fromkeys(missing))
    unique_reasons = list(dict.fromkeys(reasons))
    return EvidenceGateResult(
        sufficient=not unique_reasons,
        missing_fields=unique_missing,
        reason_codes=unique_reasons,
        suggested_agents=unique_agents,
        suggested_tools=unique_tools,
    )
