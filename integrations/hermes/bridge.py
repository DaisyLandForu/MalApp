from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable

from malapp.agents.business_label import analyze_business_label
from malapp.agents.impersonation import analyze_impersonation
from malapp.agents.output import validate_and_repair_evidence_blocks
from malapp.agents.static_features import analyze_apk_from_sample, public_static_feedback
from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.application.judgement import (
    business_label_agent,
    extract_iocs,
    impersonation_agent,
    judge,
    normalize_sample,
    run_agents,
    static_analysis_agent,
    threat_intel_agent,
)

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def run_static_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = prepare_static_sample(require_sample(arguments))
    normalized, unmapped = normalize_sample(sample)
    block = static_analysis_agent(normalized)
    return tool_result("static_analysis", normalized, block, unmapped_fields=unmapped)


def run_threat_intelligence(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = require_sample(arguments)
    analysis = analyze_threat_intelligence(sample)
    enriched = {**sample, "threat_intelligence": analysis}
    normalized, unmapped = normalize_sample(enriched)
    block = threat_intel_agent(normalized, extract_iocs(normalized))
    return tool_result(
        "threat_intel",
        normalized,
        block,
        unmapped_fields=unmapped,
        analysis=analysis,
    )


def run_impersonation_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = require_sample(arguments)
    analysis = analyze_impersonation(sample)
    enriched = {**sample, "impersonation_analysis": analysis}
    normalized, unmapped = normalize_sample(enriched)
    block = impersonation_agent(normalized)
    return tool_result(
        "impersonation",
        normalized,
        block,
        unmapped_fields=unmapped,
        analysis=analysis,
    )


def run_business_labeling(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = require_sample(arguments)
    analysis = analyze_business_label(sample)
    enriched = {**sample, "business_label_analysis": analysis}
    normalized, unmapped = normalize_sample(enriched)
    block = business_label_agent(normalized)
    return tool_result(
        "business_label",
        normalized,
        block,
        unmapped_fields=unmapped,
        analysis=analysis,
    )


def run_all_domain_agents(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = prepare_static_sample(require_sample(arguments))
    threat = analyze_threat_intelligence(sample)
    impersonation = analyze_impersonation(sample)
    business = analyze_business_label(sample)
    enriched = {
        **sample,
        "threat_intelligence": threat,
        "impersonation_analysis": impersonation,
        "business_label_analysis": business,
    }
    normalized, unmapped = normalize_sample(enriched)
    blocks, runtime = run_agents(normalized, extract_iocs(normalized))
    blocks, validation = validate_and_repair_evidence_blocks(blocks)
    return {
        "tool": "run_all_domain_agents",
        "sample_id": normalized["sample_id"],
        "unmapped_fields": unmapped,
        "evidence_blocks": [asdict(block) for block in blocks],
        "runtime": runtime,
        "validation": validation,
        "analysis": {
            "threat_intelligence": threat,
            "impersonation": impersonation,
            "business_label": business,
        },
    }


def run_full_judgement(arguments: dict[str, Any]) -> dict[str, Any]:
    return judge(require_sample(arguments))


def prepare_static_sample(sample: dict[str, Any]) -> dict[str, Any]:
    extracted, full_report = analyze_apk_from_sample(sample)
    if not full_report:
        return sample
    merged = {
        **extracted,
        "apk_analysis": public_static_feedback(full_report),
    }
    merged.update(
        {
            key: value
            for key, value in sample.items()
            if key not in {"apk_base64", "apk_path", "apk_file"}
            and value not in ("", None)
            and value != []
        }
    )
    return merged


def require_sample(arguments: dict[str, Any]) -> dict[str, Any]:
    sample = arguments.get("sample", arguments)
    if not isinstance(sample, dict) or not sample:
        raise ValueError("sample must be a non-empty JSON object")
    return dict(sample)


def tool_result(
    name: str,
    sample: dict[str, Any],
    block: Any,
    **details: Any,
) -> dict[str, Any]:
    return {
        "tool": name,
        "sample_id": sample["sample_id"],
        "evidence_block": asdict(block),
        **details,
    }


TOOL_HANDLERS: dict[str, ToolHandler] = {
    "malapp_static_analysis": run_static_analysis,
    "malapp_threat_intelligence": run_threat_intelligence,
    "malapp_impersonation_analysis": run_impersonation_analysis,
    "malapp_business_labeling": run_business_labeling,
    "malapp_run_all_agents": run_all_domain_agents,
    "malapp_full_judgement": run_full_judgement,
}


def sample_schema(description: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "sample": {
                "type": "object",
                "description": description,
                "additionalProperties": True,
            }
        },
        "required": ["sample"],
        "additionalProperties": False,
    }


TOOL_DEFINITIONS = [
    {
        "name": "malapp_static_analysis",
        "description": (
            "Statically analyze an Android APK or normalized sample and return one "
            "traceable static-analysis EvidenceBlock. Never executes the APK."
        ),
        "inputSchema": sample_schema(
            "Sample fields. apk_path must point to a file inside the project workspace; "
            "apk_base64 is also supported."
        ),
    },
    {
        "name": "malapp_threat_intelligence",
        "description": (
            "Extract IOCs, evaluate supplied/local intelligence, build a relationship "
            "graph, match malware-family features, and return one EvidenceBlock."
        ),
        "inputSchema": sample_schema(
            "Sample fields and optional threat_intel_records/family_feature_library."
        ),
    },
    {
        "name": "malapp_impersonation_analysis",
        "description": (
            "Compare app name, package, icon/OCR text and developer signature with the "
            "official application asset library and return one EvidenceBlock."
        ),
        "inputSchema": sample_schema(
            "Sample fields and optional icon_path/icon_base64/official_app_assets."
        ),
    },
    {
        "name": "malapp_business_labeling",
        "description": (
            "Translate technical evidence into anti-fraud business labels, build the "
            "harm chain, assess variants, and return one EvidenceBlock."
        ),
        "inputSchema": sample_schema(
            "Sample fields including permissions, URLs, family and version metadata."
        ),
    },
    {
        "name": "malapp_run_all_agents",
        "description": (
            "Run all four deterministic domain analyzers concurrently. Use only for "
            "fallback or verification; the Hermes supervisor should normally delegate "
            "the four specialist tasks independently."
        ),
        "inputSchema": sample_schema("Complete malicious-APP sample JSON."),
    },
    {
        "name": "malapp_full_judgement",
        "description": (
            "Run the authoritative end-to-end pipeline: preprocessing, four domain "
            "agents, evidence validation, model-A/model-B debate and A/B/C decision. "
            "Use this tool for the final report after specialist review."
        ),
        "inputSchema": sample_schema("Complete malicious-APP sample JSON."),
    },
]
