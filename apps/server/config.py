"""Environment-backed server configuration and production startup validation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

VALID_PROFILES = frozenset({"demo", "offline", "production"})


def _positive_int(environ: Mapping[str, str], name: str, default: int) -> int:
    raw = str(environ.get(name, default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _allowed_hosts(raw: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            item.strip().lower().rstrip(".")
            for item in raw.split(",")
            if item.strip()
        )
    )


@dataclass(frozen=True, slots=True)
class ServerConfig:
    profile: str = "demo"
    host: str = "127.0.0.1"
    port: int = 8765
    api_key: str = ""
    admin_api_key: str = ""
    max_json_bytes: int = 2 * 1024 * 1024
    max_upload_bytes: int = 64 * 1024 * 1024
    max_query_limit: int = 1000
    max_batch_items: int = 1000
    max_rag_top_k: int = 50
    max_graph_hops: int = 3
    max_excel_rows: int = 5000
    model_allowed_hosts: tuple[str, ...] = ()

    @property
    def authentication_enabled(self) -> bool:
        return bool(self.api_key or self.admin_api_key)


def load_server_config(environ: Mapping[str, str] | None = None) -> ServerConfig:
    values = os.environ if environ is None else environ
    profile = str(values.get("MALAPP_PROFILE", "demo")).strip().lower()
    if profile not in VALID_PROFILES:
        raise ValueError("MALAPP_PROFILE must be demo, offline, or production")

    api_key = str(values.get("MALAPP_API_KEY", "")).strip()
    configured_admin_key = str(values.get("MALAPP_ADMIN_API_KEY", "")).strip()
    if profile == "production" and not api_key:
        raise ValueError("MALAPP_API_KEY is required in production")
    # One key remains a valid secure production setup. Deployments that need
    # least-privilege API clients can provide a distinct admin key.
    admin_api_key = configured_admin_key or api_key

    config = ServerConfig(
        profile=profile,
        host=str(values.get("MALAPP_HOST", "127.0.0.1")).strip() or "127.0.0.1",
        port=_positive_int(values, "MALAPP_PORT", 8765),
        api_key=api_key,
        admin_api_key=admin_api_key,
        max_json_bytes=_positive_int(values, "MALAPP_MAX_JSON_BYTES", 2 * 1024 * 1024),
        max_upload_bytes=_positive_int(values, "MALAPP_MAX_UPLOAD_BYTES", 64 * 1024 * 1024),
        max_query_limit=_positive_int(values, "MALAPP_MAX_QUERY_LIMIT", 1000),
        max_batch_items=_positive_int(values, "MALAPP_MAX_BATCH_ITEMS", 1000),
        max_rag_top_k=_positive_int(values, "MALAPP_MAX_RAG_TOP_K", 50),
        max_graph_hops=_positive_int(values, "MALAPP_MAX_GRAPH_HOPS", 3),
        max_excel_rows=_positive_int(values, "MALAPP_MAX_EXCEL_ROWS", 5000),
        model_allowed_hosts=_allowed_hosts(
            str(values.get("MALAPP_MODEL_ALLOWED_HOSTS", ""))
        ),
    )
    if config.max_upload_bytes < config.max_json_bytes:
        raise ValueError("MALAPP_MAX_UPLOAD_BYTES must be at least MALAPP_MAX_JSON_BYTES")
    return config
