"""Protocol adapters for the four deterministic domain analyzers."""

from __future__ import annotations

from collections.abc import Callable

from malapp.agents.base import AgentContext, AgentResult, EvidenceBlock

SampleAnalyzer = Callable[[dict], EvidenceBlock]
ThreatAnalyzer = Callable[[dict, list[dict]], EvidenceBlock]


def completed_result(block: EvidenceBlock) -> AgentResult:
    return AgentResult(
        agent_name=block.agent,
        status="completed",
        score=block.score,
        evidence=[block],
        confidence=block.confidence,
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
        return completed_result(self._analyzer(context.sample, list(context.iocs)))


class ImpersonationAgent:
    name = "impersonation"

    def __init__(self, analyzer: SampleAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        return completed_result(self._analyzer(context.sample))


class BusinessLabelAgent:
    name = "business_label"

    def __init__(self, analyzer: SampleAnalyzer):
        self._analyzer = analyzer

    def run(self, context: AgentContext) -> AgentResult:
        return completed_result(self._analyzer(context.sample))
