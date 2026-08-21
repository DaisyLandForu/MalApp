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


LOW_CONFIDENCE_THRESHOLD = 0.4
BOUNDARY_MARGIN = 0.05
ENGINE_CONFLICT_SPREAD = 0.25
MATERIAL_UNAVAILABLE_MARKERS = (
    "threat_intel_records",
    "control_url",
    "download_url",
    "domains",
    "ips",
    "ioc",
    "official_app_assets",
    "official_pkg",
    "official_app_name",
    "icon_path",
    "icon_base64",
    "icon_hash",
    "icon_text",
)


def evaluate_degradation(results: list[AgentResult]) -> dict[str, Any]:
    reasons: list[DegradationReason] = []
    for result in results:
        if result.status == "completed":
            continue
        failure_type = str(result.failure_type or result.status or "unknown")
        if failure_type == "skipped_by_plan":
            continue
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


def merge_unavailable_evidence(policy: dict[str, Any], gate: dict[str, Any] | None) -> dict[str, Any]:
    """Keep unobtainable fields auditable without failing the run or auto-reviewing."""
    merged = dict(policy or {})
    gate = gate if isinstance(gate, dict) else {}
    unavailable = [str(item) for item in (gate.get("unavailable_fields") or []) if str(item).strip()]
    merged["unavailable_fields"] = unavailable
    merged.setdefault("review_recommended", False)
    merged["review_recommend_reasons"] = list(merged.get("review_recommend_reasons") or [])
    if not unavailable:
        return merged
    extra = [
        {
            "code": "unavailable_evidence",
            "agent": "",
            "failure_type": "unavailable",
            "severity": "info",
            "confidence_penalty": 0.04,
            "action": "continue_with_penalty",
            "message": field,
        }
        for field in unavailable
    ]
    penalty = round(
        min(0.5, float(merged.get("confidence_penalty") or 0.0) + min(0.16, 0.04 * len(unavailable))),
        4,
    )
    merged["unavailable_confidence_penalty"] = round(min(0.16, 0.04 * len(unavailable)), 4)
    merged["confidence_penalty"] = penalty
    merged["confidence_penalty"] = penalty
    merged["unavailable_reasons"] = extra
    return merged


def recommend_review(decision: dict[str, Any], policy: dict[str, Any], *, final_confidence: float) -> tuple[bool, list[str]]:
    """Recommend review only when missing evidence could still change the call.

    Unavailable fields stay on the policy for audit. Review is recommended when
    those gaps coincide with a near-threshold score, engine conflict, or low
    final confidence, or when a critical agent already forced review.
    """
    if policy.get("force_human_review"):
        return True, ["force_human_review"]
    unavailable = [str(item) for item in (policy.get("unavailable_fields") or []) if str(item).strip()]
    if not unavailable:
        return False, []
    params = decision.get("parameters") if isinstance(decision.get("parameters"), dict) else {}
    score = _decision_score(decision)
    verdict = str(decision.get("verdict") or "")
    reasons: list[str] = []
    if _near_decision_boundary(score, params, verdict):
        reasons.append("near_decision_boundary")
    if _has_engine_conflict(decision):
        reasons.append("engine_conflict")
    if str(policy.get("status") or "") == "degraded" and final_confidence < LOW_CONFIDENCE_THRESHOLD:
        reasons.append("low_final_confidence")
    if _unavailable_may_change_verdict(decision, unavailable, score, params) and reasons:
        reasons.append("unavailable_may_change_verdict")
    return bool(reasons), reasons


def _decision_score(decision: dict[str, Any]) -> float:
    value = decision.get("final_score")
    if not isinstance(value, (int, float)):
        value = decision.get("score")
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.5


def _near_decision_boundary(score: float, params: dict[str, Any], verdict: str) -> bool:
    suspicious = float(params.get("suspicious_threshold") or 0.6)
    malicious = float(params.get("malicious_threshold") or 0.85)
    if verdict == "benign":
        return score >= suspicious - BOUNDARY_MARGIN
    if verdict == "malicious":
        return score <= malicious + BOUNDARY_MARGIN
    if verdict == "suspicious":
        return score <= suspicious + BOUNDARY_MARGIN or score >= malicious - BOUNDARY_MARGIN
    return abs(score - suspicious) <= BOUNDARY_MARGIN or abs(score - malicious) <= BOUNDARY_MARGIN


def _has_engine_conflict(decision: dict[str, Any]) -> bool:
    reasons = {str(item) for item in (decision.get("review_reasons") or []) if str(item).strip()}
    if "component_disagreement" in reasons:
        return True
    consensus = decision.get("consensus") if isinstance(decision.get("consensus"), dict) else {}
    spread = consensus.get("engine_score_spread")
    if isinstance(spread, (int, float)) and float(spread) >= ENGINE_CONFLICT_SPREAD:
        return True
    scores = decision.get("engine_scores") if isinstance(decision.get("engine_scores"), dict) else {}
    values = [float(scores[name]) for name in ("engine_a", "engine_b") if isinstance(scores.get(name), (int, float))]
    return len(values) == 2 and abs(values[0] - values[1]) >= ENGINE_CONFLICT_SPREAD


def _unavailable_may_change_verdict(
    decision: dict[str, Any],
    unavailable: list[str],
    score: float,
    params: dict[str, Any],
) -> bool:
    if not any(any(marker in field for marker in MATERIAL_UNAVAILABLE_MARKERS) for field in unavailable):
        return False
    verdict = str(decision.get("verdict") or "")
    malicious_threshold = float(params.get("malicious_threshold") or 0.85)
    if verdict == "malicious":
        return score < malicious_threshold + BOUNDARY_MARGIN
    return verdict in {"benign", "suspicious"}


def apply_degradation_policy(decision: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    original_verdict = str(decision.get("verdict") or "")
    fusion = decision.get("fusion") if isinstance(decision.get("fusion"), dict) else {}
    evidence_confidence = fusion.get("evidence_confidence")
    llm_confidence = fusion.get("llm_confidence")
    confidence_inputs = []
    if isinstance(evidence_confidence, (int, float)):
        confidence_inputs.append(float(evidence_confidence))
    if isinstance(llm_confidence, (int, float)) and (float(llm_confidence) > 0 or not confidence_inputs):
        confidence_inputs.append(float(llm_confidence))
    base_confidence = sum(confidence_inputs) / len(confidence_inputs) if confidence_inputs else 0.5
    penalty = float(policy.get("confidence_penalty") or 0.0)
    final_confidence = round(max(0.0, min(1.0, base_confidence - penalty)), 4)
    decision["confidence"] = final_confidence
    recommended, recommend_reasons = recommend_review(decision, policy, final_confidence=final_confidence)
    decision["review_recommended"] = recommended
    decision["review_recommend_reasons"] = recommend_reasons
    decision["degradation"] = {
        **policy,
        "base_confidence": round(base_confidence, 4),
        "final_confidence": final_confidence,
        "review_recommended": recommended,
        "review_recommend_reasons": recommend_reasons,
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
                "review_recommended": recommended,
                "policy_override": decision.get("policy_override"),
            }
        )
    return decision
