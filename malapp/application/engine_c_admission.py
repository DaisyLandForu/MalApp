"""Admission policy that keeps Engine C behind the original A/B boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

ADMISSION_POLICY_ID = "engine-c-admission"
ADMISSION_POLICY_VERSION = "1.0.0"


class AdmissionReason(StrEnum):
    CONFLICT = "CONFLICT"
    AMBIGUOUS_HIGH_RISK = "AMBIGUOUS_HIGH_RISK"
    CLEAR_CONSENSUS = "CLEAR_CONSENSUS"
    MANUAL_FORCE = "MANUAL_FORCE"


class EngineInputError(ValueError):
    """Structured rejection for required upstream Engine A/B inputs."""

    def __init__(self, missing_fields: list[str]):
        self.code = "missing_upstream_engine_input"
        self.missing_fields = sorted(missing_fields)
        super().__init__(
            f"{self.code}: production requires explicit " + ", ".join(self.missing_fields)
        )


@dataclass(frozen=True)
class EngineCAdmissionDecision:
    execute: bool
    reason: AdmissionReason
    policy_id: str
    policy_version: str
    parameters: dict[str, Any]
    engine_a: dict[str, Any]
    engine_b: dict[str, Any]
    details: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["reason"] = self.reason.value
        return payload


class EngineCAdmissionPolicy:
    """Versioned, configurable engineering interpretation of the source spec."""

    def __init__(self, parameters: dict[str, Any]):
        self.parameters = {
            "clear_consensus_confidence": float(
                parameters.get("admission_clear_consensus_confidence", 0.8)
            ),
            "high_risk_threshold": float(
                parameters.get("admission_high_risk_threshold", 0.7)
            ),
            "ambiguity_score_gap": float(
                parameters.get("admission_ambiguity_score_gap", 0.15)
            ),
        }

    def decide(self, sample: dict[str, Any]) -> EngineCAdmissionDecision:
        engine_a = _engine_view(sample, "a")
        engine_b = _engine_view(sample, "b")
        force = _truthy(sample.get("force_engine_c") or sample.get("engine_c_force"))
        if force:
            return self._decision(
                True, AdmissionReason.MANUAL_FORCE, engine_a, engine_b, "manual override requested"
            )
        if engine_a["label"] != engine_b["label"]:
            return self._decision(
                True, AdmissionReason.CONFLICT, engine_a, engine_b, "A/B verdict labels conflict"
            )

        minimum_confidence = min(engine_a["confidence"], engine_b["confidence"])
        score_gap = abs(engine_a["score"] - engine_b["score"])
        clear = (
            minimum_confidence >= self.parameters["clear_consensus_confidence"]
            and score_gap <= self.parameters["ambiguity_score_gap"]
        )
        if clear:
            return self._decision(
                False,
                AdmissionReason.CLEAR_CONSENSUS,
                engine_a,
                engine_b,
                "A/B labels agree with sufficient confidence and bounded score spread",
            )
        high_risk = max(engine_a["score"], engine_b["score"]) >= self.parameters["high_risk_threshold"]
        detail = "same-label result is high-risk or insufficiently certain"
        if not high_risk:
            detail = "same-label result does not satisfy the clear-consensus confidence boundary"
        return self._decision(
            True, AdmissionReason.AMBIGUOUS_HIGH_RISK, engine_a, engine_b, detail
        )

    def _decision(
        self,
        execute: bool,
        reason: AdmissionReason,
        engine_a: dict[str, Any],
        engine_b: dict[str, Any],
        details: str,
    ) -> EngineCAdmissionDecision:
        return EngineCAdmissionDecision(
            execute=execute,
            reason=reason,
            policy_id=ADMISSION_POLICY_ID,
            policy_version=ADMISSION_POLICY_VERSION,
            parameters=dict(self.parameters),
            engine_a=engine_a,
            engine_b=engine_b,
            details=details,
        )


def ensure_ab_inputs(sample: dict[str, Any], *, production: bool) -> str:
    required = ("engine_a_score", "engine_b_score")
    missing = [name for name in required if sample.get(name) in (None, "")]
    if missing and production:
        raise EngineInputError(missing)
    if missing:
        for name in missing:
            sample[name] = 50
        return "synthetic"
    return "provided"


def direct_ab_consensus_decision(
    sample: dict[str, Any],
    admission: EngineCAdmissionDecision,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return the upstream A/B result without manufacturing a Score C."""
    scores = {
        "engine_a": admission.engine_a["score"],
        "engine_b": admission.engine_b["score"],
    }
    configured = parameters.get("initial_weights") or {}
    weights = {
        "engine_a": float(configured.get("engine_a", 1.0)),
        "engine_b": float(configured.get("engine_b", 1.0)),
    }
    terms = {name: round(scores[name] * weights[name], 6) for name in scores}
    score = max(0.0, min(sum(terms.values()) / (sum(weights.values()) or 1.0), 1.0))
    verdict = _label(score)
    risk = {"malicious": "high", "suspicious": "medium", "benign": "low"}[verdict]
    return {
        "final_score": score,
        "raw_weighted_score": score,
        "verdict": verdict,
        "verdict_label": {"malicious": "恶意", "suspicious": "可疑", "benign": "良性"}[verdict],
        "risk_level": risk,
        "risk_level_label": {"high": "高风险", "medium": "中风险", "low": "低风险"}[risk],
        "weights": weights,
        "engine_scores": scores,
        "weighted_terms": terms,
        "parameters": parameters,
        "review_required": False,
        "review_reasons": [],
        "fusion": {
            "mode": "ab_clear_consensus",
            "formula": "(A*Weight_A + B*Weight_B) / (Weight_A + Weight_B)",
            "engine_c_score": None,
        },
        "decision_trace": [
            {
                "step": "engine_c_admission",
                "reason": admission.reason.value,
                "result": "use_upstream_ab_consensus",
            }
        ],
    }


def _engine_view(sample: dict[str, Any], suffix: str) -> dict[str, Any]:
    raw_score = float(sample[f"engine_{suffix}_score"])
    score = max(0.0, min(raw_score / 100.0 if raw_score > 1 else raw_score, 1.0))
    label = _canonical_label(sample.get(f"engine_{suffix}_label"), score)
    raw_confidence = sample.get(f"engine_{suffix}_confidence")
    if raw_confidence in (None, ""):
        confidence = abs(score - 0.5) * 2
    else:
        confidence = float(raw_confidence)
        confidence = confidence / 100.0 if confidence > 1 else confidence
    return {
        "score": round(score, 6),
        "label": label,
        "confidence": round(max(0.0, min(confidence, 1.0)), 6),
    }


def _label(score: float) -> str:
    if score >= 0.7:
        return "malicious"
    if score >= 0.45:
        return "suspicious"
    return "benign"


def _canonical_label(value: Any, score: float) -> str:
    text = str(value or "").strip().lower()
    if any(term in text for term in ("恶意", "病毒", "木马", "malicious")):
        return "malicious"
    if any(term in text for term in ("可疑", "风险", "suspicious")):
        return "suspicious"
    if any(term in text for term in ("良性", "安全", "白", "benign")):
        return "benign"
    return _label(score)


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "force"}
