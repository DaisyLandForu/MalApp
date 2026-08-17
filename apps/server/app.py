"""FastAPI application factory for the MalApp HTTP surface."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from apps.server.config import ServerConfig, load_server_config
from apps.server.middleware import RequestSizeLimitMiddleware
from apps.server.routes import admin, agents, batches, datasets, evaluation, health, judgement, models, rag
from malapp.application.batch import recover_interrupted_jobs
from malapp.application.judgement import ROOT, init_db
from malapp.config.paths import initialize_runtime_files
from malapp.data_import.preprocess import reset_runtime_state
from malapp.inference.settings import load_model_settings
from malapp.inference.url_policy import validate_model_pair
from malapp.version import APP_VERSION

LOGGER = logging.getLogger(__name__)
WEB_DIR = ROOT / "apps" / "web"


def initialize_application(config: ServerConfig) -> None:
    os.environ["MALAPP_PROFILE"] = config.profile
    if config.profile == "production":
        os.environ.setdefault("MALAPP_DISABLE_LLM_RULE_FALLBACK", "1")
    initialize_runtime_files()
    model_settings = load_model_settings()
    validate_model_pair(model_settings, profile=config.profile)
    init_db()
    reset_on_start = os.getenv("MALAPP_RESET_RUNTIME_ON_START", "0").strip().lower()
    if reset_on_start not in {"0", "false", "no", "off"}:
        reset_runtime_state()
    recover_interrupted_jobs()


def create_app(
    config: ServerConfig | None = None,
    *,
    initialize_runtime: bool = True,
) -> FastAPI:
    active_config = config or load_server_config()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if initialize_runtime:
            initialize_application(active_config)
        yield

    application = FastAPI(
        title="MalApp Agent API",
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.config = active_config
    application.add_middleware(RequestSizeLimitMiddleware, config=active_config)

    @application.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {"error": str(exc.detail)},
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": "invalid request", "details": exc.errors()}, status_code=400)

    @application.exception_handler(ValueError)
    @application.exception_handler(json.JSONDecodeError)
    async def bad_request(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    @application.exception_handler(RuntimeError)
    async def runtime_error(_: Request, exc: RuntimeError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    @application.exception_handler(Exception)
    async def internal_error(_: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("Unhandled API error: %s", type(exc).__name__)
        return JSONResponse({"error": "internal server error"}, status_code=500)

    application.include_router(health.router)
    application.include_router(judgement.router)
    application.include_router(agents.router)
    application.include_router(rag.router)
    application.include_router(models.router)
    application.include_router(datasets.router)
    application.include_router(batches.router)
    application.include_router(evaluation.router)
    application.include_router(admin.router)
    application.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return application


app = create_app()
