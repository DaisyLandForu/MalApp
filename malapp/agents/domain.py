"""Protocol adapters for the four deterministic domain analyzers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from malapp.agents import business_label as business_label_analysis
from malapp.agents import impersonation as impersonation_analysis
from malapp.agents import threat_intelligence as threat_intelligence_analysis
from malapp.agents.base import AgentContext, AgentResult, EvidenceBlock

SampleAnalyzer = Callable[[dict[str, Any]], EvidenceBlock]
ThreatAnalyzer = Callable[[dict[str, Any], list[dict[str, Any]]], EvidenceBlock]


def completed_result(
    block: EvidenceBlock,
    *,
    artifacts: dict[str, Any] | None = None,
) -> AgentResult:
    return AgentResult(
        agent_name=block.agent,
        status="completed",
        score=block.score,
        evidence=[block],
        confidence=block.confidence,
        artifacts=dict(artifacts or {}),
    )


class StaticAnalysisAgent:
    name = "static_analysis"

    def __init__(self, analyzer: SampleAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        return completed_result(self._analyzer(context.sample))

class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(self, analyzer: ThreatAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        analysis = threat_intelligence_analysis.analyze_threat_intelligence(sample)
        sample["threat_intelligence"] = analysis
        block = self._analyzer(sample, list(context.iocs))
        return completed_result(block, artifacts={"threat_intelligence": analysis})


class ImpersonationAgent:
    name = "impersonation"

    def __init__(self, analyzer: SampleAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        analysis = impersonation_analysis.analyze_impersonation(sample)
        sample["impersonation_analysis"] = analysis
        block = self._analyzer(sample)
        return completed_result(block, artifacts={"impersonation_analysis": analysis})


class BusinessLabelAgent:
    name = "business_label"

    def __init__(self, analyzer: SampleAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        sample = dict(context.sample)
        analysis = business_label_analysis.analyze_business_label(sample)
        sample["business_label_analysis"] = analysis
        block = self._analyzer(sample)
        return completed_result(block, artifacts={"business_label_analysis": analysis})
