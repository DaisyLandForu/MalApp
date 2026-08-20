"""Threat intelligence tools wrapping existing deterministic analyzers."""

from __future__ import annotations

from typing import Any

from malapp.agents import threat_intelligence as threat
from malapp.tools.registry import FunctionTool


def network_indicator(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"indicators": threat.extract_network_indicators(sample)}


def ioc_lookup(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    indicators = threat.extract_network_indicators(sample)
    records = threat.normalize_intelligence_records(
        sample.get("threat_intel_records") or sample.get("intelligence_records") or []
    )
    reputation = threat.evaluate_reputation(indicators, records)
    graph = threat.build_social_graph(sample, indicators, records)
    return {"indicators": indicators, "records": records, "reputation": reputation, "social_graph": graph}


def family_correlation(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    return {"family_attribution": threat.match_family_features(sample)}


def assemble_threat_analysis(facts: dict[str, dict[str, Any]], sample: dict[str, Any]) -> dict[str, Any]:
    del sample
    indicators = (facts.get("network_indicator") or facts.get("ioc_lookup") or {}).get("indicators")
    if not isinstance(indicators, dict):
        indicators = {"urls": [], "domains": [], "ips": [], "emails": [], "phones": []}
    ioc = facts.get("ioc_lookup") or {}
    records = ioc.get("records") or []
    reputation = ioc.get("reputation") or {
        "items": [],
        "aggregate_risk": 0.0,
        "queried_layers": [],
        "notice": "ioc_lookup not executed",
    }
    graph = ioc.get("social_graph") or {
        "nodes": [],
        "edges": [],
        "clusters": [],
        "shared_entities": [],
        "team_signals": {"shared_entity_count": 0, "multi_app_cluster": False, "suspicious": False},
    }
    family = (facts.get("family_correlation") or {}).get("family_attribution") or {
        "matches": [],
        "best_match": None,
    }
    summary = threat.summarize_intelligence(reputation, graph, family)
    return {
        "indicators": indicators,
        "reputation": reputation,
        "social_graph": graph,
        "family_attribution": family,
        "summary": summary,
        "evidence_block": {
            "agent": "threat_intel",
            "claim": summary["claim"],
            "confidence": summary["confidence"],
            "score": summary["risk_score"],
            "evidence": summary["evidence"],
            "sources": summary["sources"],
            "missing_fields": summary["missing_fields"],
        },
        "records_count": len(records) if isinstance(records, list) else 0,
    }


def threat_tools() -> list[FunctionTool]:
    return [
        FunctionTool("network_indicator", "threat_intel", network_indicator, "Extract network IOC"),
        FunctionTool("ioc_lookup", "threat_intel", ioc_lookup, "Local intelligence reputation lookup"),
        FunctionTool("family_correlation", "threat_intel", family_correlation, "Malware family correlation"),
    ]
