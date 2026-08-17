"""FastAPI dependencies for authenticated and administrator routes."""

from __future__ import annotations

from fastapi import HTTPException, Request

from apps.server.config import ServerConfig
from apps.server.security import AuthenticationError, authorize


def server_config(request: Request) -> ServerConfig:
    return request.app.state.config


def _authorize_request(request: Request, *, admin: bool) -> str:
    try:
        return authorize(
            request.headers.get("Authorization", ""),
            server_config(request),
            admin=admin,
        )
    except AuthenticationError as exc:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        raise HTTPException(exc.status_code, exc.message, headers=headers) from exc


def require_authenticated(request: Request) -> str:
    return _authorize_request(request, admin=False)


def require_admin(request: Request) -> str:
    return _authorize_request(request, admin=True)
