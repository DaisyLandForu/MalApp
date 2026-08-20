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
    status: str = "completed",
    failure_type: str | None = None,
    error: str | None = None,
) -> AgentResult:
    values = dict(artifacts or {})
    if expert_provider is not None and context is not None and failure_type is None:
        block, review = expert_provider.review(
            block.agent,
            context.sample,
            block,
            extra={"iocs": list(context.iocs)} if block.agent == "threat_intel" else None,
        )
        values["expert_review"] = review
    return AgentResult(
        agent_name=block.agent,
        status=status,
        score=block.score,
        evidence=[block],
        confidence=block.confidence,
        error=error,
        failure_type=failure_type,
        artifacts=values,
    )


def _planned_tools(metadata: dict[str, Any], agent: str) -> list[str]:
    allowlist = metadata.get("tool_allowlist") if isinstance(metadata.get("tool_allowlist"), dict) else {}
    if agent in allowlist:
        return [str(item) for item in allowlist[agent]]
    return list(REGISTERED_TOOLS.get(agent, ()))


def _tool_bundle(context: AgentContext, agent: str) -> tuple[Any, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    metadata = context.metadata if isinstance(context.metadata, dict) else {}
    registry = metadata.get("tool_registry")
    planned = _planned_tools(metadata, agent)
    if registry is None:
        return None, [], {}
    from malapp.tools.executor import ToolExecutor

    execution = ToolExecutor(registry).execute(
        agent,
        planned,
        dict(context.sample),
        iocs=list(context.iocs),
        plan_id=str(metadata.get("plan_id") or ""),
        run_id=context.request_id,
    )
    return execution, [item.to_dict() for item in execution.observations], execution.facts


def _block_from_analysis(agent: str, analysis: dict[str, Any]) -> EvidenceBlock:
    raw = analysis.get("evidence_block") if isinstance(analysis, dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    missing = [str(item) for item in (raw.get("missing_fields") or [])]
    score = float(raw.get("score") or 0.0)
    return EvidenceBlock(
        agent=agent,
        claim=str(raw.get("claim") or ""),
        evidence=[str(item) for item in (raw.get("evidence") or [])],
        confidence=float(raw.get("confidence") or 0.0),
        missing_fields=missing,
        score=score,
        status="insufficient_evidence" if missing else "ok",
        rule_score=score,
    )


def _tool_failure(observations: list[dict[str, Any]]) -> tuple[str, str] | None:
    for item in observations:
        if item.get("status") == "timeout":
            return "timeout", str(item.get("error") or "tool timeout")
    for item in observations:
        if item.get("status") == "failed":
            return "exception", str(item.get("error") or "tool failed")
    return None


def _finish_from_tools(
    agent: str,
    analysis: dict[str, Any],
    artifact_key: str,
    observations: list[dict[str, Any]],
    execution: Any,
    *,
    expert_provider: ExpertModelProvider | None,
    context: AgentContext,
) -> AgentResult:
    artifacts: dict[str, Any] = {artifact_key: analysis}
    if observations:
        artifacts["tool_observations"] = observations
        artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
    failure = _tool_failure(observations)
    if failure:
        failure_type, error = failure
        return completed_result(
            _block_from_analysis(agent, analysis),
            artifacts=artifacts,
            status="timeout" if failure_type == "timeout" else "failed",
            failure_type=failure_type,
            error=error,
        )
    return completed_result(
        _block_from_analysis(agent, analysis),
        artifacts=artifacts,
        expert_provider=expert_provider,
        context=context,
    )


class StaticAnalysisAgent:
    name = "static_analysis"

    def __init__(self, analyzer: SampleAnalyzer, expert_provider: ExpertModelProvider | None = None):
        self._analyzer = analyzer
        self._expert_provider = expert_provider

    def run(self, context: AgentContext) -> AgentResult:
        execution, observations, _facts = _tool_bundle(context, self.name)
        artifacts: dict[str, Any] = {}
        if observations:
            artifacts["tool_observations"] = observations
            artifacts["tool_execution"] = execution.to_dict() if execution is not None else {}
        failure = _tool_failure(observations)
        if failure:
            failure_type, error = failure
            return completed_result(
                self._analyzer(context.sample),
                artifacts=artifacts,
                status="timeout" if failure_type == "timeout" else "failed",
                failure_type=failure_type,
                error=error,
            )
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
        execution, observations, facts = _tool_bundle(context, self.name)
        if execution is None:
            analysis = threat_intelligence_analysis.analyze_threat_intelligence(sample)
            sample["threat_intelligence"] = analysis
            return completed_result(
                self._analyzer(sample, list(context.iocs)),
                artifacts={"threat_intelligence": analysis},
                expert_provider=self._expert_provider,
                context=context,
            )
        from malapp.tools.threat import assemble_threat_analysis

        analysis = assemble_threat_analysis(facts, sample)
        sample["threat_intelligence"] = analysis
        return _finish_from_tools(
            self.name,
            analysis,
            "threat_intelligence",
            observations,
            execution,
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
        execution, observations, facts = _tool_bundle(context, self.name)
        if execution is None:
            analysis = impersonation_analysis.analyze_impersonation(sample)
            sample["impersonation_analysis"] = analysis
            return completed_result(
                self._analyzer(sample),
                artifacts={"impersonation_analysis": analysis},
                expert_provider=self._expert_provider,
                context=context,
            )
        from malapp.tools.impersonation import assemble_impersonation_analysis

        analysis = assemble_impersonation_analysis(facts, sample)
        sample["impersonation_analysis"] = analysis
        return _finish_from_tools(
            self.name,
            analysis,
            "impersonation_analysis",
            observations,
            execution,
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
        execution, observations, facts = _tool_bundle(context, self.name)
        if execution is None:
            analysis = business_label_analysis.analyze_business_label(sample)
            sample["business_label_analysis"] = analysis
            return completed_result(
                self._analyzer(sample),
                artifacts={"business_label_analysis": analysis},
                expert_provider=self._expert_provider,
                context=context,
            )
        from malapp.tools.business import assemble_business_analysis

        analysis = assemble_business_analysis(facts, sample)
        sample["business_label_analysis"] = analysis
        return _finish_from_tools(
            self.name,
            analysis,
            "business_label_analysis",
            observations,
            execution,
            expert_provider=self._expert_provider,
            context=context,
        )
