from __future__ import annotations

import importlib.util
import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from malapp.application.judgement import DATA_DIR

SETTINGS_PATH = DATA_DIR / "model_settings.json"
DEFAULT_LOCAL_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"
DEFAULT_SERVER_A_URL = ""
DEFAULT_SERVER_A_MODEL = ""
DEFAULT_SERVER_A_API_KEY = ""
DEFAULT_SERVER_B_URL = ""
DEFAULT_SERVER_B_MODEL = ""


def _env_enabled(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes", "y"}


def default_model_settings() -> dict[str, Any]:
    return {
        "server_models_enabled": _env_enabled("MALAPP_USE_SERVER_MODELS", "0"),
        "model_a_api_url": os.getenv("MALAPP_MODEL_A_API_URL", DEFAULT_SERVER_A_URL),
        "model_a_api_key": os.getenv("MALAPP_MODEL_A_API_KEY", DEFAULT_SERVER_A_API_KEY),
        "model_a_model": os.getenv("MALAPP_MODEL_A_MODEL", DEFAULT_SERVER_A_MODEL),
        "model_b_api_url": os.getenv("MALAPP_MODEL_B_API_URL", DEFAULT_SERVER_B_URL),
        "model_b_api_key": os.getenv("MALAPP_MODEL_B_API_KEY", ""),
        "model_b_model": os.getenv("MALAPP_MODEL_B_MODEL", DEFAULT_SERVER_B_MODEL),
        "local_qwen_enabled": _env_enabled("MALAPP_USE_LOCAL_QWEN", "0"),
        "model": os.getenv("MALAPP_QWEN_MODEL", DEFAULT_LOCAL_MODEL),
    }


def load_model_settings() -> dict[str, Any]:
    settings = load_model_settings_without_apply()
    apply_model_settings(settings)
    return settings


def load_model_settings_without_apply() -> dict[str, Any]:
    settings = default_model_settings()
    try:
        saved = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        saved = {}
    if isinstance(saved, dict):
        for key in settings:
            if key in saved and saved[key] not in (None, ""):
                settings[key] = saved[key]
        settings["server_models_enabled"] = bool(settings.get("server_models_enabled"))
        settings["local_qwen_enabled"] = bool(settings.get("local_qwen_enabled"))
    return settings


def update_model_settings(payload: dict[str, Any]) -> dict[str, Any]:
    current = load_model_settings_without_apply()
    updated = dict(current)
    for key in (
        "server_models_enabled",
        "model_a_api_url",
        "model_a_api_key",
        "model_a_model",
        "model_b_api_url",
        "model_b_api_key",
        "model_b_model",
        "local_qwen_enabled",
        "model",
    ):
        if key in payload:
            value = payload[key]
            if key in {"model_a_api_key", "model_b_api_key"} and value in (None, ""):
                continue
            updated[key] = bool(value) if key.endswith("_enabled") else str(value or "")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(
        json.dumps(updated, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    apply_model_settings(updated)
    return model_runtime_status(check_remote=True)


def apply_model_settings(settings: dict[str, Any]) -> None:
    server_enabled = bool(settings.get("server_models_enabled"))
    os.environ["MALAPP_USE_SERVER_MODELS"] = "1" if server_enabled else "0"
    if server_enabled:
        os.environ["MALAPP_MODEL_A_API_URL"] = str(settings.get("model_a_api_url") or "")
        os.environ["MALAPP_MODEL_A_API_KEY"] = str(settings.get("model_a_api_key") or "")
        os.environ["MALAPP_MODEL_A_MODEL"] = str(settings.get("model_a_model") or DEFAULT_SERVER_A_MODEL)
        os.environ["MALAPP_MODEL_B_API_URL"] = str(settings.get("model_b_api_url") or "")
        os.environ["MALAPP_MODEL_B_API_KEY"] = str(settings.get("model_b_api_key") or "")
        os.environ["MALAPP_MODEL_B_MODEL"] = str(settings.get("model_b_model") or DEFAULT_SERVER_B_MODEL)
    else:
        for key in (
            "MALAPP_MODEL_A_API_URL",
            "MALAPP_MODEL_A_API_KEY",
            "MALAPP_MODEL_A_MODEL",
            "MALAPP_MODEL_B_API_URL",
            "MALAPP_MODEL_B_API_KEY",
            "MALAPP_MODEL_B_MODEL",
        ):
            os.environ.pop(key, None)

    os.environ["MALAPP_USE_LOCAL_QWEN"] = "1" if settings.get("local_qwen_enabled") else "0"
    os.environ["MALAPP_QWEN_MODEL"] = str(settings.get("model") or DEFAULT_LOCAL_MODEL)


def model_runtime_status(check_remote: bool = True) -> dict[str, Any]:
    settings = load_model_settings_without_apply()
    apply_model_settings(settings)
    profile = os.getenv("MALAPP_PROFILE", "demo").strip().lower()

    server_enabled = bool(settings.get("server_models_enabled"))
    if check_remote:
        model_a = server_model_status(
            str(settings.get("model_a_api_url") or ""),
            str(settings.get("model_a_model") or ""),
            str(settings.get("model_a_api_key") or ""),
        )
        model_b = server_model_status(
            str(settings.get("model_b_api_url") or ""),
            str(settings.get("model_b_model") or ""),
            str(settings.get("model_b_api_key") or ""),
        )
    else:
        model_a = unchecked_server_model_status(
            str(settings.get("model_a_api_url") or ""),
            str(settings.get("model_a_model") or ""),
        )
        model_b = unchecked_server_model_status(
            str(settings.get("model_b_api_url") or ""),
            str(settings.get("model_b_model") or ""),
        )
    server_ready = server_enabled and model_a["ready"] and model_b["ready"]

    dependencies = {
        name: importlib.util.find_spec(name) is not None
        for name in ("torch", "transformers", "accelerate")
    }
    model_available = model_is_cached(str(settings.get("model") or DEFAULT_LOCAL_MODEL))
    worker_ready = qwen_worker_ready()
    local_ready = (
        bool(settings.get("local_qwen_enabled"))
        and (worker_ready or all(dependencies.values()))
        and model_available
    )

    if server_ready:
        mode = "server_models"
        ready = True
        message = (
            f"服务器双模型已可用：模型甲 {settings['model_a_model']}，"
            f"模型乙 {settings['model_b_model']}。新研判将调用真实服务器模型。"
        )
    elif server_enabled and not check_remote:
        mode = "server_models_configured"
        ready = False
        message = "服务器双模型已配置，尚未检测；保存设置或开始研判时会调用真实模型。"
    elif server_enabled:
        mode = "server_models_unavailable"
        ready = False
        message = "服务器双模型已启用但不可用；规则模式已禁用，研判会停止。"
    elif local_ready:
        mode = "local_qwen"
        ready = True
        message = "本地 Qwen 已启用并可用；新研判将调用真实本地模型。"
    elif settings.get("local_qwen_enabled"):
        mode = "local_qwen_unavailable"
        ready = False
        missing = [name for name, available in dependencies.items() if not available]
        reasons = []
        if missing:
            reasons.append("缺少依赖：" + "、".join(missing))
        if not model_available:
            reasons.append("未找到本地模型缓存")
        message = "本地 Qwen 已启用但不可用；规则模式已禁用，研判会停止。" + "；".join(reasons)
    elif profile in {"demo", "offline"}:
        mode = "deterministic_evidence"
        ready = True
        message = "当前使用确定性证据链；未启用大模型推理。"
    else:
        mode = "model_required"
        ready = False
        message = "未启用可用模型；规则模式已禁用，请启用服务器双模型或本地 Qwen。"

    public_settings = {
        **settings,
        "model_a_api_key": "",
        "model_b_api_key": "",
        "model_a_api_key_configured": bool(settings.get("model_a_api_key")),
        "model_b_api_key_configured": bool(settings.get("model_b_api_key")),
    }
    return {
        **public_settings,
        "ready": ready,
        "mode": mode,
        "profile": profile,
        "message": message,
        "server_models": {"model_a": model_a, "model_b": model_b},
        "dependencies": dependencies,
        "model_available": model_available,
        "worker_ready": worker_ready,
    }


def ensure_runtime_ready_for_judgement() -> dict[str, Any]:
    """Stop judgement early when no real model endpoint is reachable."""
    status = model_runtime_status(check_remote=True)
    if status.get("ready"):
        return status

    mode = str(status.get("mode") or "")
    if mode == "server_models_unavailable":
        model_a = status.get("server_models", {}).get("model_a", {})
        model_b = status.get("server_models", {}).get("model_b", {})
        raise RuntimeError(
            "服务器双模型接口不可用，已停止研判。"
            f"模型甲 {model_a.get('api_url')}：{model_a.get('message')}; "
            f"模型乙 {model_b.get('api_url')}：{model_b.get('message')}。"
            "请确认 OpenAI-compatible 服务已启动且可访问，"
            "模型名与 API 密钥和应用配置一致。"
        )
    if mode == "local_qwen_unavailable":
        raise RuntimeError(
            f"本地 Qwen 不可用，已停止研判。{status.get('message')}"
        )
    raise RuntimeError(
        "没有可用的大模型接口，已停止研判。请启用并检测服务器双模型，"
        "或启用可用的本地 Qwen。"
    )


def unchecked_server_model_status(api_url: str, model: str) -> dict[str, Any]:
    if not api_url or not model:
        return {"ready": False, "api_url": api_url, "model": model, "available_models": [], "message": "API 地址或模型名为空"}
    return {
        "ready": False,
        "api_url": api_url,
        "model": model,
        "available_models": [],
        "message": "未检测",
    }


def server_model_status(api_url: str, model: str, api_key: str = "") -> dict[str, Any]:
    if not api_url or not model:
        return {"ready": False, "message": "API 地址或模型名为空"}
    request = urllib.request.Request(
        api_url.rstrip("/") + "/models",
        headers={**({"Authorization": f"Bearer {api_key}"} if api_key else {})},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            data = json.loads(response.read().decode("utf-8"))
        ids = [str(item.get("id")) for item in data.get("data", []) if isinstance(item, dict)]
        ready = response.status == 200 and (not ids or model in ids)
        return {
            "ready": ready,
            "api_url": api_url,
            "model": model,
            "available_models": ids,
            "message": "可用" if ready else f"接口可访问，但未发现模型 {model}",
        }
    except Exception as exc:
        return {
            "ready": False,
            "api_url": api_url,
            "model": model,
            "available_models": [],
            "message": f"{type(exc).__name__}: {exc}",
        }


def model_is_cached(model_id: str) -> bool:
    path = Path(model_id).expanduser()
    if path.exists():
        return True
    cache_root = Path(
        os.getenv(
            "HF_HUB_CACHE",
            str(Path.home() / ".cache" / "huggingface" / "hub"),
        )
    )
    model_dir = cache_root / ("models--" + model_id.replace("/", "--"))
    snapshots = model_dir / "snapshots"
    return snapshots.exists() and any(snapshots.iterdir())


def model_cache_signature() -> str:
    settings = load_model_settings_without_apply()
    if settings.get("server_models_enabled"):
        return (
            f"server:{settings.get('model_a_api_url')}:{settings.get('model_a_model')}"
            f"|{settings.get('model_b_api_url')}:{settings.get('model_b_model')}"
        )
    mode = "local_qwen" if settings.get("local_qwen_enabled") else "model_required"
    return f"{mode}:{settings.get('model')}"


def qwen_worker_ready() -> bool:
    worker_url = os.getenv("MALAPP_QWEN_WORKER_URL", "").strip()
    if not worker_url:
        return False
    try:
        with urllib.request.urlopen(worker_url.rstrip("/") + "/health", timeout=2) as response:
            data = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and data.get("status") == "ok"
    except (OSError, ValueError, json.JSONDecodeError):
        return False
