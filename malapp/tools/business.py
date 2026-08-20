"""Business-label tools wrapping existing taxonomy analyzers."""

from __future__ import annotations

from typing import Any

from malapp.agents import business_label as business
from malapp.tools.registry import FunctionTool


def business_taxonomy(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"technical_scene_translation": business.translate_technical_features(sample)}


def harm_chain(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"harm_chain": business.build_harm_chain(sample)}


def variant_mapping(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"variant_assessment": business.determine_variant(sample)}


def assemble_business_analysis(facts: dict[str, dict[str, Any]], sample: dict[str, Any]) -> dict[str, Any]:
    if facts.get("business_taxonomy") and facts.get("harm_chain") and facts.get("variant_mapping"):
        return business.analyze_business_label(sample)
    scene = (facts.get("business_taxonomy") or {}).get("technical_scene_translation") or {
        "labels": [],
        "matched_rules": [],
        "risk_score": 0.0,
    }
    chain = (facts.get("harm_chain") or {}).get("harm_chain") or {
        "stages": [],
        "business_harm_labels": [],
        "risk_score": 0.0,
        "complete_chain": False,
    }
    variant = (facts.get("variant_mapping") or {}).get("variant_assessment") or {
        "variant_label": "unknown",
        "labels": [],
        "evidence": [],
        "risk_score": 0.0,
    }
    score = max(float(scene.get("risk_score") or 0), float(chain.get("risk_score") or 0), float(variant.get("risk_score") or 0))
    assembled = {
        "technical_scene_translation": scene,
        "harm_chain": chain,
        "variant_assessment": variant,
    }
    full = business.analyze_business_label(sample)
    # Keep claim/evidence construction identical when all slices exist; otherwise reuse summary helpers via full missing mix.
    assembled["summary"] = {
        "risk_score": round(score, 4),
        "business_labels": sorted(
            set(
                list(scene.get("labels") or [])
                + list(chain.get("business_harm_labels") or [])
                + list(variant.get("labels") or [])
            )
        ),
        "claim": full["summary"]["claim"] if facts.keys() >= {"business_taxonomy", "harm_chain", "variant_mapping"} else (
            "业务语义风险较高" if score >= 0.75 else "业务语义风险中等" if score >= 0.45 else "业务语义风险较低"
        ),
        "evidence": full["summary"]["evidence"] if len(facts) == 3 else [
            "仅执行了部分业务分析 Tool，证据不完整。"
        ],
        "confidence": round(min(0.9, 0.3 + 0.2 * len(facts)), 4),
    }
    assembled["evidence_block"] = {
        "agent": "business_label",
        "claim": assembled["summary"]["claim"],
        "evidence": assembled["summary"]["evidence"],
        "confidence": assembled["summary"]["confidence"],
        "score": assembled["summary"]["risk_score"],
        "missing_fields": business.missing_fields(sample),
    }
    return assembled


def business_tools() -> list[FunctionTool]:
    return [
        FunctionTool("business_taxonomy", "business_label", business_taxonomy, "Technical-to-business taxonomy"),
        FunctionTool("harm_chain", "business_label", harm_chain, "Harm chain stages"),
        FunctionTool("variant_mapping", "business_label", variant_mapping, "Variant mapping"),
    ]
