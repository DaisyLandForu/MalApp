"""Validation policy for outbound OpenAI-compatible model endpoints."""

from __future__ import annotations

import os
from collections.abc import Iterable
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})


def configured_allowed_hosts() -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            item.strip().lower().rstrip(".")
            for item in os.getenv("MALAPP_MODEL_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        )
    )


def validate_model_endpoint(
    value: str,
    *,
    profile: str | None = None,
    allowed_hosts: Iterable[str] | None = None,
) -> str:
    """Validate and normalize a model base URL before any network access."""
    url = str(value or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("model endpoint scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("model endpoint must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("model endpoint must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("model endpoint must not contain a query or fragment")

    hostname = parsed.hostname.lower().rstrip(".")
    active_profile = (profile or os.getenv("MALAPP_PROFILE", "demo")).strip().lower()
    configured = tuple(
        item.strip().lower().rstrip(".")
        for item in (configured_allowed_hosts() if allowed_hosts is None else allowed_hosts)
        if item.strip()
    )
    if active_profile == "production":
        if not configured:
            raise ValueError("MALAPP_MODEL_ALLOWED_HOSTS is required for production model endpoints")
        if hostname not in configured:
            raise ValueError(f"model endpoint host is not allowed: {hostname}")
    elif configured and hostname not in configured:
        raise ValueError(f"model endpoint host is not allowed: {hostname}")
    return url


def validate_model_pair(settings: dict[str, object], *, profile: str | None = None) -> None:
    active_profile = (profile or os.getenv("MALAPP_PROFILE", "demo")).strip().lower()
    enabled = bool(settings.get("server_models_enabled"))
    for label in ("a", "b"):
        url = str(settings.get(f"model_{label}_api_url") or "")
        model = str(settings.get(f"model_{label}_model") or "").strip()
        if enabled and active_profile == "production" and (not url or not model):
            raise ValueError(f"model {label.upper()} endpoint and model id are required in production")
        if url:
            validate_model_endpoint(url, profile=active_profile)
    if active_profile == "production" and enabled:
        model_a = str(settings.get("model_a_model") or "").strip()
        model_b = str(settings.get("model_b_model") or "").strip()
        if model_a == model_b:
            raise ValueError(
                "production requires heterogeneous model identities; model A and model B ids must differ"
            )
