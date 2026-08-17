"""Stable contracts shared by every domain agent and orchestrator."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class EvidenceBlock:
    agent: str
    claim: str
    evidence: list[str]
    confidence: float
    missing_fields: list[str] = field(default_factory=list)
    score: float = 0.0
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    rule_score: float | None = None
    ml_prior: float | None = None
    evidence_id: str = ""
    expert_review: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentContext:
    """Request-scoped, read-only-by-convention input for all agents."""

    sample: dict[str, Any]
    iocs: tuple[dict[str, Any], ...] = ()
    request_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    agent_name: str
    status: str
    score: float | None
    evidence: list[EvidenceBlock]
    confidence: float
    latency_ms: float = 0.0
    error: str | None = None
    failure_type: str | None = None
    attempts: int = 1
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = [asdict(block) for block in self.evidence]
        payload["artifact_keys"] = sorted(payload.pop("artifacts"))
        return payload


@runtime_checkable
class Agent(Protocol):
    name: str

    def run(self, context: AgentContext) -> AgentResult:
        """Analyze one request without managing retries, timeouts, or fallbacks."""
        ...
