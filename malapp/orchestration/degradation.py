"""Explicit, reportable policy for partial Agent Runtime failures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from malapp.agents.base import AgentResult


@dataclass(frozen=True)
class DegradationReason:
    code: str
    agent: str
    failure_type: str
    severity: str
    confidence_penalty: float
    action: str
    message: str


def evaluate_degradation(results: list[AgentResult]) -> dict[str, Any]:
    reasons: list[DegradationReason] = []
    for result in results:
        if result.status == "completed":
            continue
        failure_type = str(result.failure_type or result.status or "unknown")
        if result.agent_name == "static_analysis":
            penalty, severity, action = 0.25, "critical", "force_human_review"
        elif result.agent_name == "threat_intel":
            penalty, severity, action = 0.12, "warning", "continue_with_penalty"
        else:
            penalty, severity, action = 0.08, "warning", "continue_with_penalty"
        reasons.append(
            DegradationReason(
                code=f"{result.agent_name}_{failure_type}",
                agent=result.agent_name,
                failure_type=failure_type,
                severity=severity,
                confidence_penalty=penalty,
                action=action,
                message=result.error or f"{result.agent_name} did not complete",
            )
        )
    penalty = round(min(0.5, sum(item.confidence_penalty for item in reasons)), 4)
    critical = any(item.severity == "critical" for item in reasons)
    return {
        "status": "degraded" if reasons else "healthy",
        "confidence_penalty": penalty,
        "force_human_review": critical,
        "force_suspicious_if_benign": critical,
        "reasons": [asdict(item) for item in reasons],
    }


def apply_degradation_policy(decision: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    original_verdict = str(decision.get("verdict") or "")
    fusion = decision.get("fusion") if isinstance(decision.get("fusion"), dict) else {}
    confidence_inputs = [
        float(value)
        for value in (fusion.get("llm_confidence"), fusion.get("evidence_confidence"))
        if isinstance(value, (int, float))
    ]
    base_confidence = sum(confidence_inputs) / len(confidence_inputs) if confidence_inputs else 0.5
    penalty = float(policy.get("confidence_penalty") or 0.0)
    final_confidence = round(max(0.0, min(1.0, base_confidence - penalty)), 4)
    decision["confidence"] = final_confidence
    decision["degradation"] = {
        **policy,
        "base_confidence": round(base_confidence, 4),
        "final_confidence": final_confidence,
    }

    reason_codes = [str(item.get("code")) for item in policy.get("reasons", []) if isinstance(item, dict)]
    if policy.get("force_human_review"):
        decision["review_required"] = True
        decision["review_reasons"] = sorted(set(list(decision.get("review_reasons", [])) + reason_codes))
    if policy.get("force_suspicious_if_benign") and decision.get("verdict") == "benign":
        decision.update(
            {
                "verdict": "suspicious",
                "verdict_label": "可疑",
                "risk_level": "medium",
                "risk_level_label": "中风险",
                "policy_override": "critical_agent_degradation",
            }
        )
    trace = decision.get("decision_trace") if isinstance(decision.get("decision_trace"), list) else []
    final_step = next(
        (item for item in reversed(trace) if isinstance(item, dict) and item.get("step") == "final_decision"),
        None,
    )
    if final_step is not None:
        data = final_step.setdefault("data", {})
        data.update(
            {
                "pre_degradation_verdict": original_verdict,
                "verdict": decision.get("verdict"),
                "confidence": final_confidence,
                "degradation_reasons": reason_codes,
                "policy_override": decision.get("policy_override"),
            }
        )
    return decision
