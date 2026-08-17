from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, status

from apps.server.auth import require_admin
from apps.server.limits import payload_object
from malapp.orchestration.decision import load_decision_params, update_decision_params

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/api/decision/params")
def decision_params() -> dict[str, Any]:
    return load_decision_params()


@router.post("/api/decision/params", status_code=status.HTTP_201_CREATED)
def save_decision_params(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return update_decision_params(payload_object(payload))
