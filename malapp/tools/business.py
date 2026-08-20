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
    return business.compose_business_analysis(scene, chain, variant, business.missing_fields(sample))


def business_tools() -> list[FunctionTool]:
    return [
        FunctionTool("business_taxonomy", "business_label", business_taxonomy, "Technical-to-business taxonomy"),
        FunctionTool("harm_chain", "business_label", harm_chain, "Harm chain stages"),
        FunctionTool("variant_mapping", "business_label", variant_mapping, "Variant mapping"),
    ]
