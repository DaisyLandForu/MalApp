from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
BEST_PARAMS_PATH = DATA_DIR / "eval" / "best_params.json"
DECISION_PARAMS_PATH = DATA_DIR / "decision_params.json"

DEFAULT_PARAMS = {
    "initial_weights": {"engine_a": 1.0, "engine_b": 1.0, "engine_c": 1.0},
    "weight_min": 0.35,
    "weight_max": 2.25,
    "evidence_gain": 0.65,
    "conflict_gain": 0.3,
    "signature_gain": 0.35,
    "threat_intel_gain": 0.5,
    "impersonation_gain": 0.35,
    "business_gain": 0.3,
    "static_gain": 0.25,
    "pipeline_fusion_weight": 0.45,
    "xgb_fusion_weight": 0.35,
    "score_c_xgb_calibration_weight": 0.35,
    "evidence_fusion_weight": 0.20,
    "admission_clear_consensus_confidence": 0.8,
    "admission_high_risk_threshold": 0.7,
    "admission_ambiguity_score_gap": 0.15,
    # Kept for compatibility with existing decision_params.json files.  The
    # arbiter is already part of pipeline_fusion_weight and must not be counted
    # a second time.
    "llm_fusion_weight": 0.45,
    "engine_disagreement_decay": 0.22,
    "missing_evidence_decay": 0.12,
    "malicious_threshold": 0.85,
    "suspicious_threshold": 0.6,
}


def collaborative_decision(
    sample: dict[str, Any],
    debate_report: dict[str, Any],
    evidence_blocks: list[Any],
    runtime_params: dict[str, Any] | None = None,
    xgb_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    params = load_decision_params()
    if runtime_params:
        params = merge_params(params, runtime_params)

    blocks = [asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item) for item in evidence_blocks]
    missing = [name for name in ("engine_a_score", "engine_b_score") if sample.get(name) in (None, "")]
    if missing:
        raise ValueError("missing upstream engine scores: " + ", ".join(missing))
    score_c_raw = normalize_engine_score(debate_report.get("arbiter", {}).get("score", 0.5))
    if xgb_result is None:
        try:
            from malapp.inference.xgboost import predict as predict_xgb

            xgb_result = predict_xgb(sample)
        except Exception:
            xgb_result = None
    calibration_weight = 0.0
    score_c = score_c_raw
    if xgb_result is not None:
        calibration_weight = clamp(float(params.get("score_c_xgb_calibration_weight", 0.35)))
        score_c = clamp(
            score_c_raw * (1.0 - calibration_weight)
            + clamp(float(xgb_result["probability"])) * calibration_weight
        )
    engine_scores = {
        "engine_a": normalize_engine_score(sample["engine_a_score"]),
        "engine_b": normalize_engine_score(sample["engine_b_score"]),
        "engine_c": score_c,
    }
    key_evidence = extract_key_evidence(sample, debate_report, blocks)
    weights, adjustments = allocate_dynamic_weights(engine_scores, key_evidence, blocks, params)
    weighted_terms = {
        name: round(engine_scores[name] * weights[name], 6)
        for name in ("engine_a", "engine_b", "engine_c")
    }
    weight_sum = sum(weights.values()) or 1.0
    raw_score = round(
        max(0.0, min(sum(weighted_terms.values()) / weight_sum, 1.0)),
        6,
    )
    evidence_consensus = evidence_consensus_score(blocks)
    consensus_bonus = 0.0
    final_score = raw_score
    verdict = verdict_from_score(final_score, params)
    llm_confidence = debate_confidence(debate_report)
    evidence_probability, evidence_confidence = evidence_probability_score(blocks)
    fusion = {
        "mode": "engine_c_internal_calibration_then_abc_wec",
        "xgb_probability": clamp(float(xgb_result["probability"])) if xgb_result is not None else None,
        "llm_probability": score_c_raw,
        "llm_confidence": llm_confidence,
        "xgb_weight": calibration_weight,
        "pipeline_probability": score_c,
        "pipeline_weight": 1.0 - calibration_weight,
        "evidence_probability": evidence_probability,
        "evidence_confidence": evidence_confidence,
        "evidence_weight": 0.0,
        "formula": "Score C = Debate*(1-calibration_weight) + XGBoost*calibration_weight",
    }
    verdict, policy = guarded_verdict(
        final_score,
        params=params,
        debate_report=debate_report,
        xgb_result=xgb_result,
        evidence_probability=evidence_probability,
        key_evidence=key_evidence,
    )
    fusion["component_thresholds"] = {
        "final": {
            "suspicious": float(params["suspicious_threshold"]),
            "malicious": float(params["malicious_threshold"]),
        },
        "xgboost": dict((xgb_result or {}).get("thresholds") or {}),
    }
    fusion["policy"] = policy
    risk = {"malicious": "high", "suspicious": "medium", "benign": "low"}[verdict]

    return {
        "final_score": final_score,
        "raw_weighted_score": raw_score,
        "consensus_bonus": consensus_bonus,
        "verdict": verdict,
        "verdict_label": {"malicious": "恶意", "suspicious": "可疑", "benign": "良性"}[verdict],
        "risk_level": risk,
        "risk_level_label": {"high": "高风险", "medium": "中风险", "low": "低风险"}[risk],
        "weights": weights,
        "engine_scores": engine_scores,
        "weighted_terms": weighted_terms,
        "key_evidence": key_evidence,
        "weight_adjustments": adjustments,
        "triggered_rules": sorted({item["source"] for item in key_evidence if item["strength"] >= 0.7}),
        "consensus": {
            "evidence_consensus_score": evidence_consensus,
            "engine_score_spread": round(max(engine_scores.values()) - min(engine_scores.values()), 4),
            "formula": "(A*Weight_A + B*Weight_B + C*Weight_C) / sum(weights)",
        },
        "parameters": params,
        "xgb": xgb_result,
        "fusion": fusion,
        "wec": {
            "policy_id": "dynamic-three-engine-wec",
            "version": "1.0.0",
            "formula": "(A*Wa+B*Wb+C*Wc)/(Wa+Wb+Wc)",
            "score_c_source": "engine_c_pipeline",
            "score_c_raw": score_c_raw,
            "score_c_calibrated": score_c,
        },
        "review_required": verdict == "suspicious" or bool(policy["review_reasons"]),
        "review_reasons": policy["review_reasons"],
        "decision_trace": build_decision_trace(engine_scores, weights, key_evidence, adjustments, final_score, verdict),
    }


def extract_key_evidence(
    sample: dict[str, Any],
    debate_report: dict[str, Any],
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence = []
    for block in blocks:
        status = str(block.get("status") or "ok").strip().lower()
        score = clamp(float(block.get("rule_score") if block.get("rule_score") is not None else block.get("score", 0)))
        confidence = clamp(float(block.get("confidence", score)))
        usable = status not in {"insufficient_evidence", "degraded"}
        strength = clamp(score * 0.65 + confidence * 0.35) if usable else 0.0
        tags = evidence_tags(block.get("agent", ""), block.get("evidence", []), sample)
        evidence.append(
            {
                "source": str(block.get("agent", "unknown")),
                "label": str(block.get("claim", "")),
                "strength": strength,
                "score": score,
                "confidence": confidence,
                "status": status,
                "ml_prior": block.get("ml_prior"),
                "tags": tags,
                "evidence": list(block.get("evidence", []))[:5],
                "decisive": usable and strength >= 0.78,
            }
        )

    arbiter = debate_report.get("arbiter", {})
    arbiter_strength = clamp(float(arbiter.get("score", 0.5)))
    evidence.append(
        {
            "source": "debate_arbiter",
            "label": str(arbiter.get("rationale", "双模型辩论仲裁")),
            "strength": arbiter_strength,
            "score": arbiter_strength,
            "confidence": convergence_confidence(debate_report),
            "tags": ["debate_consensus", "engine_c"],
            "evidence": [str(arbiter.get("final_summary") or arbiter.get("rationale") or "")],
            "decisive": arbiter_strength >= 0.78,
        }
    )

    if str(sample.get("signature_status", "")).lower() in {"tampered", "mismatch", "invalid", "missing"}:
        evidence.append(
            evidence_item("signature_anomaly", "签名异常", 0.9, ["signature", "static"], ["签名状态异常"])
        )
    if sample.get("packer"):
        evidence.append(evidence_item("packer", "加固壳/混淆", 0.68, ["packer", "static"], ["检测到加固或壳"]))
    return sorted(evidence, key=lambda item: item["strength"], reverse=True)


def evidence_item(source: str, label: str, strength: float, tags: list[str], evidence: list[str]) -> dict[str, Any]:
    return {
        "source": source,
        "label": label,
        "strength": strength,
        "score": strength,
        "confidence": strength,
        "tags": tags,
        "evidence": evidence,
        "decisive": strength >= 0.78,
    }


def evidence_tags(agent: str, lines: Any, sample: dict[str, Any]) -> list[str]:
    text = " ".join(str(item) for item in lines).lower()
    tags = [agent]
    checks = {
        "signature": ("签名", "signature"),
        "packer": ("加固", "壳", "packer"),
        "ioc": ("ioc", "c2", "域名", "ip"),
        "impersonation": ("仿冒", "图标", "品牌"),
        "business_harm": ("诈骗", "贷款", "危害", "业务"),
        "sensitive_permission": ("sms", "联系人", "权限", "accessibility"),
    }
    for tag, terms in checks.items():
        if any(term in text for term in terms):
            tags.append(tag)
    if sample.get("fake_app") and "impersonation" not in tags:
        tags.append("impersonation")
    return sorted(set(tags))


def allocate_dynamic_weights(
    scores: dict[str, float],
    key_evidence: list[dict[str, Any]],
    blocks: list[dict[str, Any]],
    params: dict[str, Any],
) -> tuple[dict[str, float], list[dict[str, Any]]]:
    weights = {key: float(value) for key, value in params["initial_weights"].items()}
    adjustments = []

    def adjust(engine: str, delta: float, reason: str) -> None:
        before = weights[engine]
        weights[engine] = clamp_weight(before + delta, params)
        adjustments.append(
            {
                "engine": engine,
                "before": round(before, 4),
                "delta": round(weights[engine] - before, 4),
                "after": round(weights[engine], 4),
                "reason": reason,
            }
        )

    by_source = {item["source"]: item for item in key_evidence}
    gains = {
        "static_analysis": "static_gain",
        "threat_intel": "threat_intel_gain",
        "impersonation": "impersonation_gain",
        "business_label": "business_gain",
    }
    for source, gain_key in gains.items():
        item = by_source.get(source)
        if item and item["strength"] >= 0.55:
            adjust("engine_c", float(params[gain_key]) * item["strength"], f"{source} evidence strength")

    signature = by_source.get("signature_anomaly")
    if signature:
        adjust("engine_c", float(params["signature_gain"]) * signature["strength"], "signature anomaly")

    spread_ab = abs(scores["engine_a"] - scores["engine_b"])
    if spread_ab >= 0.35:
        adjust("engine_c", float(params["conflict_gain"]) * spread_ab, "A/B engine conflict")
        decay = float(params["engine_disagreement_decay"]) * spread_ab
        adjust("engine_a", -decay, "A/B disagreement decay")
        adjust("engine_b", -decay, "A/B disagreement decay")

    block_by_agent = {str(item.get("agent")): item for item in blocks}
    for engine, agent in (("engine_a", "static_analysis"), ("engine_b", "threat_intel")):
        missing = len(block_by_agent.get(agent, {}).get("missing_fields", []))
        if missing:
            adjust(engine, -float(params["missing_evidence_decay"]) * min(missing, 3), f"{agent} missing evidence")

    decisive = [item for item in key_evidence if item["decisive"]]
    if decisive:
        average_strength = sum(item["strength"] for item in decisive) / len(decisive)
        adjust("engine_c", float(params["evidence_gain"]) * average_strength, "decisive Engine C evidence")

    return {key: round(value, 4) for key, value in weights.items()}, adjustments


def evidence_consensus_score(blocks: list[dict[str, Any]]) -> float:
    scores = [
        clamp(float(item.get("rule_score") if item.get("rule_score") is not None else item.get("score", 0)))
        for item in blocks
        if str(item.get("status") or "ok").lower()
        not in {"insufficient_evidence", "degraded"}
    ]
    if not scores:
        return 0.5
    spread = max(scores) - min(scores)
    return clamp(1.0 - spread)


def evidence_consensus_adjustment(blocks: list[dict[str, Any]]) -> float:
    """Return a signed adjustment; agreement alone must not always add risk."""
    scores = [
        clamp(float(item.get("rule_score") if item.get("rule_score") is not None else item.get("score", 0)))
        for item in blocks
        if str(item.get("status") or "ok").lower()
        not in {"insufficient_evidence", "degraded"}
    ]
    if not scores:
        return 0.0
    average = sum(scores) / len(scores)
    agreement = 1.0 - (max(scores) - min(scores))
    return round((average - 0.5) * 0.08 * agreement, 6)


def evidence_probability_score(
    blocks: list[dict[str, Any]],
) -> tuple[float | None, float]:
    weighted = 0.0
    weight_sum = 0.0
    for block in blocks:
        if str(block.get("status") or "ok").lower() in {
            "insufficient_evidence",
            "degraded",
        }:
            continue
        score = clamp(float(block.get("rule_score") if block.get("rule_score") is not None else block.get("score", 0)))
        confidence = clamp(float(block.get("confidence", 0)))
        evidence_count = len(block.get("evidence_items") or block.get("evidence") or [])
        missing_count = len(block.get("missing_fields") or [])
        coverage = evidence_count / max(1, evidence_count + missing_count)
        weight = confidence * max(0.2, coverage)
        if weight <= 0:
            continue
        weighted += score * weight
        weight_sum += weight
    if weight_sum <= 0:
        return None, 0.0
    return clamp(weighted / weight_sum), clamp(min(1.0, weight_sum / max(1, len(blocks))))


def xgb_native_verdict(xgb_result: dict[str, Any] | None) -> str:
    if not xgb_result:
        return "unavailable"
    verdict = str(xgb_result.get("verdict") or "").strip().lower()
    if verdict in {"malicious", "suspicious", "benign"}:
        return verdict
    score = clamp(float(xgb_result.get("probability", 0.5)))
    thresholds = xgb_result.get("thresholds") or {}
    benign = float(thresholds.get("benign_threshold", 0.16))
    malicious = float(thresholds.get("malicious_threshold", 0.82))
    if score < benign:
        return "benign"
    if score >= malicious:
        return "malicious"
    return "suspicious"


def guarded_verdict(
    score: float,
    *,
    params: dict[str, Any],
    debate_report: dict[str, Any],
    xgb_result: dict[str, Any] | None,
    evidence_probability: float | None,
    key_evidence: list[dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Preserve the WEC verdict and route component conflicts to review.

    The WEC score and its configured thresholds are authoritative. Component
    verdicts retain their native thresholds only to explain disagreement and
    require human review; they never replace the WEC-derived verdict.
    """
    score_verdict = verdict_from_score(score, params)
    arbiter = debate_report.get("arbiter") or {}
    llm_verdict = str(arbiter.get("verdict") or "").strip().lower()
    if llm_verdict not in {"malicious", "suspicious", "benign"}:
        llm_verdict = verdict_from_score(
            normalize_engine_score(arbiter.get("score", 0.5)), params
        )
    xgb_verdict = xgb_native_verdict(xgb_result)
    credible_malicious_evidence = any(
        item.get("decisive")
        and item.get("source") != "debate_arbiter"
        and item.get("status") not in {"insufficient_evidence", "degraded"}
        for item in key_evidence
    )
    review_reasons: list[str] = []
    if score_verdict == "benign":
        if xgb_verdict in {"suspicious", "malicious"}:
            review_reasons.append(f"xgboost_native_{xgb_verdict}")
        if llm_verdict in {"suspicious", "malicious"}:
            review_reasons.append(f"arbiter_{llm_verdict}")
        if credible_malicious_evidence:
            review_reasons.append("credible_agent_malicious_evidence")
    component_verdicts = [
        value
        for value in (xgb_verdict, llm_verdict, score_verdict)
        if value != "unavailable"
    ]
    if len(set(component_verdicts)) > 1:
        review_reasons.append("component_disagreement")
    return score_verdict, {
        "score_verdict": score_verdict,
        "xgboost_verdict": xgb_verdict,
        "arbiter_verdict": llm_verdict,
        "credible_malicious_evidence": credible_malicious_evidence,
        "evidence_probability": evidence_probability,
        "override_applied": False,
        "review_reasons": sorted(set(review_reasons)),
    }


def convergence_confidence(debate_report: dict[str, Any]) -> float:
    history = debate_report.get("convergence", {}).get("history", [])
    if not history:
        return 0.5
    latest = history[-1]
    return clamp(
        (1.0 - float(latest.get("score_distance", 1.0))) * 0.6
        + float(latest.get("argument_similarity", 0.0)) * 0.4
    )


def debate_confidence(debate_report: dict[str, Any]) -> float:
    turn_backends = [
        str(turn.get("backend") or "")
        for stage in debate_report.get("stages", [])
        for turn in stage.get("turns", [])
    ]
    valid_model_backends = {"local_qwen", "openai_compatible"}
    if turn_backends and not any(backend in valid_model_backends for backend in turn_backends):
        return 0.0

    values = []
    for key in ("model_a", "model_b"):
        try:
            values.append(float(debate_report.get(key, {}).get("confidence", 0.5)))
        except (TypeError, ValueError):
            pass
    if values:
        return clamp(sum(values) / len(values))
    return convergence_confidence(debate_report)


def build_decision_trace(
    scores: dict[str, float],
    weights: dict[str, float],
    evidence: list[dict[str, Any]],
    adjustments: list[dict[str, Any]],
    final_score: float,
    verdict: str,
) -> list[dict[str, Any]]:
    return [
        {"step": "engine_scores", "data": scores},
        {"step": "key_evidence_extraction", "data": evidence[:8]},
        {"step": "dynamic_weight_adjustment", "data": adjustments},
        {"step": "final_weights", "data": weights},
        {"step": "final_decision", "data": {"score": final_score, "verdict": verdict}},
    ]


def load_decision_params() -> dict[str, Any]:
    params = json.loads(json.dumps(DEFAULT_PARAMS))
    try:
        best = json.loads(BEST_PARAMS_PATH.read_text(encoding="utf-8")).get("params", {})
        params["malicious_threshold"] = float(best.get("malicious_threshold", params["malicious_threshold"]))
        params["suspicious_threshold"] = float(best.get("suspicious_threshold", params["suspicious_threshold"]))
        params["initial_weights"]["engine_c"] = float(best.get("engine_c_weight", 1.0))
        params["conflict_gain"] = float(best.get("conflict_boost", params["conflict_gain"]))
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    try:
        custom = json.loads(DECISION_PARAMS_PATH.read_text(encoding="utf-8"))
        params = merge_params(params, custom)
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return validate_params(params)


def update_decision_params(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_decision_params()
    updated = validate_params(merge_params(current, payload))
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DECISION_PARAMS_PATH.write_text(json.dumps(updated, ensure_ascii=False, indent=2), encoding="utf-8")
    return updated


def merge_params(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in override.items():
        if key == "initial_weights" and isinstance(value, dict):
            result["initial_weights"].update(value)
        elif key in result:
            result[key] = value
    return result


def validate_params(params: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(DEFAULT_PARAMS))
    result = merge_params(result, params)
    result["weight_min"] = max(0.0, float(result["weight_min"]))
    result["weight_max"] = max(result["weight_min"], float(result["weight_max"]))
    for key in result:
        if key in {"initial_weights", "weight_min", "weight_max"}:
            continue
        result[key] = max(0.0, float(result[key]))
    for engine, value in result["initial_weights"].items():
        result["initial_weights"][engine] = max(result["weight_min"], min(result["weight_max"], float(value)))
    if result["suspicious_threshold"] >= result["malicious_threshold"]:
        raise ValueError("suspicious_threshold must be lower than malicious_threshold")
    return result


def normalize_engine_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = 0.5
    return clamp(score / 100 if score > 1 else score)


def verdict_from_score(score: float, params: dict[str, Any]) -> str:
    if score >= float(params["malicious_threshold"]):
        return "malicious"
    if score >= float(params["suspicious_threshold"]):
        return "suspicious"
    return "benign"


def clamp_weight(value: float, params: dict[str, Any]) -> float:
    return max(float(params["weight_min"]), min(float(params["weight_max"]), value))


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))
