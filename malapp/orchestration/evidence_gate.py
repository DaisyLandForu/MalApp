"""Deterministic evidence sufficiency gate. No LLM judge in V1.

Sufficiency means existing evidence can support a judgement. Missing fields are
either remediable (another Agent/Tool could still obtain them) or unavailable.
Only remediable gaps fail the gate and may trigger one Re-plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from malapp.agents.base import AgentResult
from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.orchestration.planner import (
    InvestigationPlan,
    has_business_signal,
    has_impersonation_signal,
    has_network_signal,
    tool_runtime_enabled,
)

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
IOC_REMEDIATION_TOOLS = ("ioc_lookup", "network_indicator")
IMPERSONATION_REMEDIATION_TOOLS = (
    "official_asset_match",
    "package_similarity",
    "certificate_comparison",
)


@dataclass
class EvidenceGateResult:
    sufficient: bool = True
    missing_fields: list[str] = field(default_factory=list)
    unavailable_fields: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    unavailable_reason_codes: list[str] = field(default_factory=list)
    suggested_agents: list[str] = field(default_factory=list)
    suggested_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sufficient": self.sufficient,
            "missing_fields": list(self.missing_fields),
            "unavailable_fields": list(self.unavailable_fields),
            "reason_codes": list(self.reason_codes),
            "unavailable_reason_codes": list(self.unavailable_reason_codes),
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


def _ops_disabled(plan: InvestigationPlan, results: dict[str, AgentResult], name: str) -> bool:
    result = results.get(name)
    if result is not None and result.failure_type == "disabled":
        return True
    agent_plan = plan.agents.get(name)
    return bool(agent_plan and agent_plan.reason_code == "disabled_agent_override")


def _matching_fields(fields: list[str], markers: tuple[str, ...]) -> list[str]:
    return [item for item in fields if any(marker in item for marker in markers)]


def _unused_tools(agent: str, executed_tools: dict[str, list[str]], candidates: tuple[str, ...]) -> list[str]:
    ran = {str(name) for name in (executed_tools.get(agent) or [])}
    return [name for name in candidates if name not in ran]


def evaluate_evidence_gate(
    plan: InvestigationPlan,
    results: list[AgentResult],
    *,
    sample: dict[str, Any] | None = None,
    iocs: list[dict[str, Any]] | None = None,
    executed_tools: dict[str, list[str]] | None = None,
) -> EvidenceGateResult:
    by_agent = _result_map(results)
    sample = sample or {}
    iocs = iocs or []
    executed_tools = executed_tools or {}
    tools_live = tool_runtime_enabled()
    remediable: list[str] = []
    unavailable: list[str] = []
    reasons: list[str] = []
    unavailable_reasons: list[str] = []
    suggested_agents: list[str] = []
    suggested_tools: list[str] = []
    focus = set(plan.risk_focus)

    static = by_agent.get("static_analysis")
    if not _ran(static) and not _ops_disabled(plan, by_agent, "static_analysis"):
        remediable.append("static_analysis")
        reasons.append("static_evidence_missing")
        suggested_agents.append("static_analysis")

    threat_needed = "network_ioc" in focus or has_network_signal(sample, iocs)
    if threat_needed and not _ops_disabled(plan, by_agent, "threat_intel"):
        threat = by_agent.get("threat_intel")
        ioc_missing = _matching_fields(_missing_fields(threat), IOC_MISSING_MARKERS)
        if not _ran(threat):
            remediable.append("threat_intel")
            reasons.append("network_ioc_agent_skipped")
            suggested_agents.append("threat_intel")
        elif ioc_missing:
            pending = _unused_tools("threat_intel", executed_tools, IOC_REMEDIATION_TOOLS) if tools_live else []
            if pending:
                remediable.extend(ioc_missing)
                reasons.append("network_ioc_tools_pending")
                suggested_tools.extend(pending)
                suggested_agents.append("threat_intel")
            else:
                unavailable.extend(ioc_missing)
                unavailable_reasons.append("network_ioc_fields_unavailable")

    impersonation_needed = "impersonation" in focus or has_impersonation_signal(sample)
    if impersonation_needed and not _ops_disabled(plan, by_agent, "impersonation"):
        impersonation = by_agent.get("impersonation")
        asset_missing = _matching_fields(_missing_fields(impersonation), IMPERSONATION_MISSING_MARKERS)
        if not _ran(impersonation):
            remediable.append("impersonation")
            reasons.append("impersonation_agent_skipped")
            suggested_agents.append("impersonation")
        elif asset_missing:
            pending = (
                _unused_tools("impersonation", executed_tools, IMPERSONATION_REMEDIATION_TOOLS) if tools_live else []
            )
            if pending:
                remediable.extend(asset_missing)
                reasons.append("impersonation_tools_pending")
                suggested_tools.extend(pending)
                suggested_agents.append("impersonation")
            else:
                unavailable.extend(asset_missing)
                unavailable_reasons.append("impersonation_fields_unavailable")

    business_needed = "business_label" in focus or has_business_signal(sample)
    if business_needed and not _ops_disabled(plan, by_agent, "business_label"):
        business = by_agent.get("business_label")
        if not _ran(business):
            remediable.append("business_label")
            reasons.append("business_agent_skipped")
            suggested_agents.append("business_label")

    unique_agents = [name for name in AGENT_ORDER if name in dict.fromkeys(suggested_agents)]
    unique_tools = list(dict.fromkeys(suggested_tools))
    unique_remediable = list(dict.fromkeys(remediable))
    unique_unavailable = list(dict.fromkeys(unavailable))
    unique_reasons = list(dict.fromkeys(reasons))
    unique_unavailable_reasons = list(dict.fromkeys(unavailable_reasons))
    return EvidenceGateResult(
        sufficient=not unique_reasons,
        missing_fields=unique_remediable,
        unavailable_fields=unique_unavailable,
        reason_codes=unique_reasons,
        unavailable_reason_codes=unique_unavailable_reasons,
        suggested_agents=unique_agents,
        suggested_tools=unique_tools,
    )
