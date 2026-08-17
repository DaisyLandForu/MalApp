from __future__ import annotations

from fastapi import APIRouter, Request

from malapp.application.judgement import DATA_DIR
from malapp.version import APP_VERSION, BUILD_DATE

router = APIRouter()


@router.get("/api/health")
def health(request: Request) -> dict[str, object]:
    return {
        "status": "ok",
        "service": "malicious-app-judgement",
        "version": APP_VERSION,
        "build_date": BUILD_DATE,
        "profile": request.app.state.config.profile,
        "data_dir": str(DATA_DIR),
    }
