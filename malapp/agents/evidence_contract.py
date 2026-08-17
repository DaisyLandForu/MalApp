"""Canonical, immutable-by-convention evidence handoff to the debate models."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from malapp.governance.artifacts import canonical_json, now_iso, sha256_text

EVIDENCE_SCHEMA_VERSION = "canonical-evidence-v1"
AGENT_ORDER = ("static_analysis", "threat_intel", "impersonation", "business_label")


@dataclass(frozen=True)
class CanonicalEvidenceEnvelope:
    sample_id: str
    evidence_blocks: tuple[dict[str, Any], ...]
    agent_results: tuple[dict[str, Any], ...]
    evidence_ids: tuple[str, ...]
    schema_version: str
    created_at: str
    sha256: str
    evidence_snapshot_id: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("evidence_blocks", "agent_results", "evidence_ids"):
            payload[key] = list(payload[key])
        return payload

    def canonical_json(self) -> str:
        return canonical_json(self.to_dict())


def build_evidence_envelope(
    sample_id: str,
    evidence_blocks: list[Any],
    agent_results: list[Any] | None = None,
    *,
    created_at: str | None = None,
) -> CanonicalEvidenceEnvelope:
    blocks = [asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item) for item in evidence_blocks]
    order = {name: index for index, name in enumerate(AGENT_ORDER)}
    blocks = sorted(
        enumerate(blocks),
        key=lambda pair: (order.get(str(pair[1].get("agent")), len(order)), str(pair[1].get("agent")), pair[0]),
    )
    seen: dict[str, int] = {}
    canonical_blocks: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    for _, block in blocks:
        agent = str(block.get("agent") or "unknown")
        seen[agent] = seen.get(agent, 0) + 1
        evidence_id = agent if seen[agent] == 1 else f"{agent}:{seen[agent]}"
        value = dict(block)
        value["evidence_id"] = evidence_id
        canonical_blocks.append(value)
        evidence_ids.append(evidence_id)

    results = []
    for item in agent_results or []:
        value = item.to_dict() if hasattr(item, "to_dict") else dict(item)
        results.append(value)
    results.sort(key=lambda item: (order.get(str(item.get("agent_name")), len(order)), str(item.get("agent_name"))))
    identity = {
        "sample_id": str(sample_id),
        "evidence_blocks": canonical_blocks,
        "agent_results": results,
        "evidence_ids": evidence_ids,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }
    digest = sha256_text(canonical_json(identity))
    return CanonicalEvidenceEnvelope(
        sample_id=str(sample_id),
        evidence_blocks=tuple(canonical_blocks),
        agent_results=tuple(results),
        evidence_ids=tuple(evidence_ids),
        schema_version=EVIDENCE_SCHEMA_VERSION,
        created_at=created_at or now_iso(),
        sha256=digest,
        evidence_snapshot_id=f"evidence-{digest[:16]}",
    )


def validate_evidence_references(result: dict[str, Any], evidence_ids: list[str] | tuple[str, ...]) -> None:
    valid = set(evidence_ids)
    refs = result.get("evidence_refs") or []
    invalid = sorted({str(item) for item in refs if str(item) not in valid})
    if invalid:
        raise ValueError("invalid_evidence_reference: " + ", ".join(invalid))
