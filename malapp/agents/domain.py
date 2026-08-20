"""Protocol adapters for the four deterministic domain analyzers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from malapp.agents import business_label as business_label_analysis
from malapp.agents import impersonation as impersonation_analysis
from malapp.agents import threat_intelligence as threat_intelligence_analysis
from malapp.agents.base import AgentContext, AgentResult, EvidenceBlock
from malapp.inference.expert import ExpertModelProvider
from malapp.orchestration.planner import REGISTERED_TOOLS

SampleAnalyzer = Callable[[dict[str, Any]], EvidenceBlock]
ThreatAnalyzer = Callable[[dict[str, Any], list[dict[str, Any]]], EvidenceBlock]


def completed_result(
    block: EvidenceBlock,
    *,
    artifacts: dict[str, Any] | None = None,
    expert_provider: ExpertModelProvider | None = None,
    context: AgentContext | None = None,
) -> AgentResult:
    values = dict(artifacts or {})
    if expert_provider is not None and context is not None:
        block, review = expert_provider.review(
            block.agent,
            context.sample,
            block,
            extra={"iocs": list(context.iocs)} if block.agent == "threat_intel" else None,
        )
        values["expert_review"] = review
    return AgentResult(
        agent_name=block.agent,
        status="completed",
        score=block.score,
        evidence=[block],
        confidence=block.confidence,
        artifacts=values,
    )


def _tool_bundle(context: AgentContext, agent: str) -> tuple[Any, list[dict[str, Any]], dict[str, dict[str, Any]], list[str]]:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    registry = metadata.get("tool_registry")
    planned = list((metadata.get("tool_allowlist") or {}).get(agent) or REGISTERED_TOOLS.get(agent, ()))
    if registry is None:
        return None, [], {}, planned
    from malapp.tools.executor import ToolExecutor

    execution = ToolExecutor(registry).execute(
        agent,
        planned,
        dict(context.sample),
        iocs=list(context.iocs),
        plan_id=str(metadata.get("plan_id") or ""),
        run_id=context.request_id,
    )
    return execution, [item.to_dict() for item in execution.observations], execution.facts, planned


def _analysis_from_tools(
    agent: str,
    facts: dict[str, dict[str, Any]],
    planned: list[str],
    assemble,
    fallback,
    sample: dict[str, Any],
):
    registered = REGISTERED_TOOLS.get(agent, ())
    if facts and all(name in facts for name in registered):
        return assemble(facts, sample)
    if facts and planned and set(planned) != set(registered):
        return assemble(facts, sample)
    return fallback(sample)


class StaticAnalysisAgent:
    name = "static_analysis"

    def __init__(self, analyzer: SampleAnalyzer, expert_provider: ExpertModelProvider | None = None):
        self._analyzer = analyzer
        self._expert_provider = expert_provider

    def run(self, context: AgentContext) -> AgentResult:
        execution, observations, _facts, _planned = _tool_bundle(context, self.name)
        artifacts: dict[str, Any] = {}
        if observations:
            artifacts["tool_observations"] = observations
            artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
        return completed_result(
            self._analyzer(context.sample),
            artifacts=artifacts,
            expert_provider=self._expert_provider,
            context=context,
        )


class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(self, analyzer: ThreatAnalyzer, expert_provider: ExpertModelProvider | None = None):
        self._analyzer = analyzer
        self._expert_provider = expert_provider

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        execution, observations, facts, planned = _tool_bundle(context, self.name)
        from malapp.tools.threat import assemble_threat_analysis

        analysis = _analysis_from_tools(
            self.name,
            facts,
            planned,
            assemble_threat_analysis,
            threat_intelligence_analysis.analyze_threat_intelligence,
            sample,
        )
        sample["threat_intelligence"] = analysis
        artifacts: dict[str, Any] = {"threat_intelligence": analysis}
        if observations:
            artifacts["tool_observations"] = observations
            artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
        return completed_result(
            self._analyzer(sample, list(context.iocs)),
            artifacts=artifacts,
            expert_provider=self._expert_provider,
            context=context,
        )


class ImpersonationAgent:
    name = "impersonation"

    def __init__(self, analyzer: SampleAnalyzer, expert_provider: ExpertModelProvider | None = None):
        self._analyzer = analyzer
        self._expert_provider = expert_provider

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        execution, observations, facts, planned = _tool_bundle(context, self.name)
        from malapp.tools.impersonation import assemble_impersonation_analysis

        analysis = _analysis_from_tools(
            self.name,
            facts,
            planned,
            assemble_impersonation_analysis,
            impersonation_analysis.analyze_impersonation,
            sample,
        )
        sample["impersonation_analysis"] = analysis
        artifacts: dict[str, Any] = {"impersonation_analysis": analysis}
        if observations:
            artifacts["tool_observations"] = observations
            artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
        return completed_result(
            self._analyzer(sample),
            artifacts=artifacts,
            expert_provider=self._expert_provider,
            context=context,
        )


class BusinessLabelAgent:
    name = "business_label"

    def __init__(self, analyzer: SampleAnalyzer, expert_provider: ExpertModelProvider | None = None):
        self._analyzer = analyzer
        self._expert_provider = expert_provider

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        execution, observations, facts, planned = _tool_bundle(context, self.name)
        from malapp.tools.business import assemble_business_analysis

        analysis = _analysis_from_tools(
            self.name,
            facts,
            planned,
            assemble_business_analysis,
            business_label_analysis.analyze_business_label,
            sample,
        )
        sample["business_label_analysis"] = analysis
        artifacts: dict[str, Any] = {"business_label_analysis": analysis}
        if observations:
            artifacts["tool_observations"] = observations
            artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
        return completed_result(
            self._analyzer(sample),
            artifacts=artifacts,
            expert_provider=self._expert_provider,
            context=context,
        )
