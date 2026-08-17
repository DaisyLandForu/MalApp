"""Authentication primitives independent from the HTTP framework."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from apps.server.config import ServerConfig


@dataclass(frozen=True, slots=True)
class AuthenticationError(Exception):
    status_code: int
    message: str


def _bearer_token(authorization: str) -> str:
    scheme, separator, credentials = authorization.strip().partition(" ")
    if not separator or scheme.lower() != "bearer" or not credentials.strip():
        raise AuthenticationError(401, "Bearer authentication is required")
    return credentials.strip()


def authenticate(authorization: str, config: ServerConfig) -> str:
    """Return ``authenticated`` or ``admin`` for a valid bearer credential."""
    if not config.authentication_enabled and config.profile != "production":
        return "admin"
    token = _bearer_token(authorization)
    if config.admin_api_key and secrets.compare_digest(token, config.admin_api_key):
        return "admin"
    if config.api_key and secrets.compare_digest(token, config.api_key):
        return "authenticated"
    raise AuthenticationError(401, "Invalid bearer token")


def authorize(authorization: str, config: ServerConfig, *, admin: bool = False) -> str:
    role = authenticate(authorization, config)
    if admin and role != "admin":
        raise AuthenticationError(403, "Administrator credential is required")
    return role
