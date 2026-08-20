"""Impersonation tools wrapping existing official-asset analyzers."""

from __future__ import annotations

from typing import Any

from malapp.agents import impersonation as impersonation_analysis
from malapp.tools.registry import FunctionTool


def _assets(sample: dict[str, Any]) -> list[dict[str, Any]]:
    assets = impersonation_analysis.load_asset_library()
    inline = sample.get("official_app_assets") or sample.get("official_asset_library") or []
    assets.extend(impersonation_analysis.normalize_assets(inline))
    return assets


def official_asset_match(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    assets = _assets(sample)
    visual = impersonation_analysis.visual_similarity(sample, assets)
    semantic = impersonation_analysis.semantic_distance(sample, assets)
    return {
        "visual_similarity": visual,
        "official_asset_match": impersonation_analysis.match_official_assets(sample, assets, visual, semantic),
    }


def package_similarity(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    assets = _assets(sample)
    return {"semantic_distance": impersonation_analysis.semantic_distance(sample, assets)}


def certificate_comparison(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    assets = _assets(sample)
    sample_signature = str(
        sample.get("developer_signature") or sample.get("signature") or sample.get("cert_sha256") or ""
    )
    matches = []
    for asset in assets:
        official = str(asset.get("developer_signature") or "")
        if sample_signature and official and sample_signature == official:
            matches.append(
                {
                    "brand": asset.get("brand", ""),
                    "package_name": asset.get("package_name", ""),
                    "developer_signature_match": True,
                }
            )
    return {
        "sample_signature": sample_signature,
        "certificate_matches": matches,
        "match_count": len(matches),
    }


def assemble_impersonation_analysis(facts: dict[str, dict[str, Any]], sample: dict[str, Any]) -> dict[str, Any]:
    official = facts.get("official_asset_match") or {}
    visual = official.get("visual_similarity") or {"matches": [], "best_match": None, "sample_icon_available": False}
    semantic = (facts.get("package_similarity") or {}).get("semantic_distance") or {
        "matches": [],
        "best_match": None,
    }
    asset_match = official.get("official_asset_match") or {"asset_count": 0, "candidates": [], "best_match": None}
    assessment = impersonation_analysis.assess_impersonation(sample, visual, semantic, asset_match)
    return {
        "visual_similarity": visual,
        "semantic_distance": semantic,
        "official_asset_match": asset_match,
        "certificate_comparison": facts.get("certificate_comparison") or {},
        "assessment": assessment,
        "evidence_block": {
            "agent": "impersonation",
            "claim": assessment["claim"],
            "confidence": assessment["confidence"],
            "score": assessment["impersonation_probability"],
            "evidence": assessment["evidence"],
            "missing_fields": assessment["missing_fields"],
        },
    }


def impersonation_tools() -> list[FunctionTool]:
    return [
        FunctionTool("official_asset_match", "impersonation", official_asset_match, "Official asset matching"),
        FunctionTool("package_similarity", "impersonation", package_similarity, "Package/name similarity"),
        FunctionTool("certificate_comparison", "impersonation", certificate_comparison, "Developer certificate comparison"),
    ]
