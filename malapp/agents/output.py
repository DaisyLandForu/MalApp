from __future__ import annotations

from dataclasses import replace
from typing import Any

REQUIRED_FIELDS = ("agent", "claim", "evidence", "confidence")
KNOWN_AGENTS = {"static_analysis", "threat_intel", "impersonation", "business_label"}


def validate_and_repair_evidence_blocks(blocks: list[Any]) -> tuple[list[Any], dict[str, Any]]:
    repaired = []
    items = []
    for block in blocks:
        fixed, issues, repaired_fields = validate_and_repair_block(block)
        repaired.append(fixed)
        items.append(
            {
                "agent": fixed.agent,
                "valid": not issues,
                "issues": issues,
                "repaired_fields": repaired_fields,
            }
        )
    return repaired, {
        "schema": {
            "required": list(REQUIRED_FIELDS),
            "properties": {
                "agent": sorted(KNOWN_AGENTS),
                "claim": "non-empty string",
                "evidence": "non-empty string array",
                "confidence": "number in [0, 1]",
                "missing_fields": "string array",
                "score": "number in [0, 1]",
                "evidence_items": "structured evidence array",
                "status": "ok | insufficient_evidence | degraded",
                "rule_score": "observable-evidence malicious probability",
                "ml_prior": "optional learned prior kept separate from evidence",
            },
        },
        "valid": all(item["valid"] for item in items),
        "items": items,
        "auto_repair": True,
    }


def validate_and_repair_block(block: Any) -> tuple[Any, list[str], list[str]]:
    issues = []
    repaired_fields = []
    agent = str(block.agent or "").strip()
    if agent not in KNOWN_AGENTS:
        issues.append("agent is unknown")
    claim = str(block.claim or "").strip()
    if not claim:
        issues.append("claim is empty")
        claim = f"{agent or 'agent'} 未输出明确结论。"
        repaired_fields.append("claim")
    evidence = block.evidence
    if not isinstance(evidence, list):
        issues.append("evidence is not an array")
        evidence = [str(evidence)]
        repaired_fields.append("evidence")
    evidence = [str(item).strip() for item in evidence if str(item).strip()]
    if not evidence:
        issues.append("evidence is empty")
        evidence = ["智能体未提供证据，已自动补充占位证据。"]
        repaired_fields.append("evidence")
    confidence = safe_float(block.confidence)
    if confidence is None:
        issues.append("confidence is not numeric")
        confidence = 0.0
        repaired_fields.append("confidence")
    confidence = clamp(confidence)
    score = safe_float(block.score)
    if score is None:
        issues.append("score is not numeric")
        score = confidence
        repaired_fields.append("score")
    score = clamp(score)
    missing_fields = block.missing_fields if isinstance(block.missing_fields, list) else [str(block.missing_fields)]
    missing_fields = [str(item).strip() for item in missing_fields if str(item).strip()]
    evidence_items = block.evidence_items if isinstance(getattr(block, "evidence_items", []), list) else []
    evidence_items = [item for item in evidence_items if isinstance(item, dict)]
    status = str(getattr(block, "status", "ok") or "ok").strip().lower()
    if missing_fields and not evidence_items:
        status = "insufficient_evidence"
    if status not in {"ok", "insufficient_evidence", "degraded"}:
        issues.append("status is invalid")
        status = "degraded"
        repaired_fields.append("status")
    rule_score = safe_float(getattr(block, "rule_score", None))
    if rule_score is None:
        rule_score = score
    rule_score = clamp(rule_score)
    ml_prior = safe_float(getattr(block, "ml_prior", None))
    if ml_prior is not None:
        ml_prior = clamp(ml_prior)
    return (
        replace(
            block,
            agent=agent,
            claim=claim,
            evidence=evidence,
            confidence=confidence,
            missing_fields=missing_fields,
            score=score,
            evidence_items=evidence_items,
            status=status,
            rule_score=rule_score,
            ml_prior=ml_prior,
        ),
        issues,
        repaired_fields,
    )


def safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))
