from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status

from apps.server.auth import require_admin, require_authenticated
from apps.server.limits import payload_object
from integrations.hermes.adapter import hermes_status
from malapp.agents.business_label import analyze_business_label
from malapp.agents.impersonation import analyze_impersonation, load_asset_library, update_asset_library
from malapp.agents.static_features import analyze_apk_from_sample, public_static_feedback
from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.application.judgement import DATA_DIR, load_json

router = APIRouter(dependencies=[Depends(require_authenticated)])


@router.get("/api/schema")
def schema() -> Any:
    return load_json(DATA_DIR / "schema.json")


@router.get("/api/sample")
def sample() -> Any:
    return load_json(DATA_DIR / "sample_conflict.json")


@router.get("/api/xgb/status")
def xgb_status() -> dict[str, Any]:
    from malapp.inference.xgboost import runtime_status

    return runtime_status()


@router.get("/api/hermes/status")
def get_hermes_status() -> dict[str, Any]:
    return hermes_status()


@router.post("/api/static-analysis", status_code=status.HTTP_201_CREATED)
def static_analysis(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    _, full_report = analyze_apk_from_sample(payload_object(payload))
    if not full_report:
        raise HTTPException(400, "apk_path or apk_base64 is required")
    return public_static_feedback(full_report)


@router.post("/api/threat-intelligence", status_code=status.HTTP_201_CREATED)
def threat_intelligence(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return analyze_threat_intelligence(payload_object(payload))


@router.post("/api/impersonation", status_code=status.HTTP_201_CREATED)
def impersonation(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return analyze_impersonation(payload_object(payload))


@router.post("/api/business-label", status_code=status.HTTP_201_CREATED)
def business_label(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return analyze_business_label(payload_object(payload))


@router.get("/api/impersonation/assets")
def impersonation_assets() -> dict[str, Any]:
    return {"items": load_asset_library()}


@router.post(
    "/api/impersonation/assets",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def replace_impersonation_assets(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    records = payload if isinstance(payload, list) else payload_object(payload).get("items", [])
    if not isinstance(records, list):
        raise ValueError("items must be an array")
    return update_asset_library(records)
