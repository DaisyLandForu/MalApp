from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, status

from apps.server.auth import require_admin
from apps.server.limits import payload_object
from malapp.inference.settings import model_runtime_status, update_model_settings

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/api/model/settings")
def model_settings() -> dict[str, Any]:
    return model_runtime_status(check_remote=False)


@router.post("/api/model/settings", status_code=status.HTTP_201_CREATED)
def save_model_settings(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return update_model_settings(payload_object(payload))
