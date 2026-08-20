"""Business-label tools wrapping existing taxonomy analyzers."""

from __future__ import annotations

from typing import Any

from malapp.agents import business_label as business
from malapp.tools.base import merge_observed_fields, snapshot_fields
from malapp.tools.registry import FunctionTool

BUSINESS_OBSERVED_KEYS = frozenset(
    {
        "virus_name",
        "virus",
        "malware_name",
        "risk_score",
        "score",
        "engine_score",
        "source_risk_score",
        "fraud_family",
        "family",
        "black_family",
        "fraud_name",
        "fraud_category_big",
        "fraud_big",
        "app_type",
        "fraud_category_small",
        "fraud_small",
        "app_subtype",
        "app_thirdtype",
        "harm_type",
        "risk_type",
        "damage_type",
        "version_status",
        "variant_status",
        "rebuild_type",
        "app_version",
        "app_name",
        "appname",
        "appname_unify",
        "name",
        "fake_app",
        "fakeApp",
        "impersonation_flag",
        "is_fake_app",
        "permissions",
        "permission_list",
        "android_permissions",
        "control_url",
        "controlUrl",
        "c2_url",
        "download_url",
        "downloadUrl",
        "version_name",
        "release_history",
        "observed_versions",
        "certificate_valid_to",
    }
)


def _business_observation(sample: dict[str, Any]) -> dict[str, Any]:
    return {"observed_fields": snapshot_fields(sample, BUSINESS_OBSERVED_KEYS)}


def business_taxonomy(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"technical_scene_translation": business.translate_technical_features(sample), **_business_observation(sample)}


def harm_chain(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"harm_chain": business.build_harm_chain(sample), **_business_observation(sample)}


def variant_mapping(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"variant_assessment": business.determine_variant(sample), **_business_observation(sample)}


def assemble_business_analysis(facts: dict[str, dict[str, Any]], sample: dict[str, Any] | None = None) -> dict[str, Any]:
    del sample
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
    observed = merge_observed_fields(facts)
    analysis = business.compose_business_analysis(scene, chain, variant, business.missing_fields(observed))
    analysis["observed_fields"] = observed
    return analysis


def business_tools() -> list[FunctionTool]:
    return [
        FunctionTool("business_taxonomy", "business_label", business_taxonomy, "Technical-to-business taxonomy"),
        FunctionTool("harm_chain", "business_label", harm_chain, "Harm chain stages"),
        FunctionTool("variant_mapping", "business_label", variant_mapping, "Variant mapping"),
    ]
