"""Static analysis tools wrapping existing sample/APK features."""

from __future__ import annotations

from typing import Any

from malapp.tools.registry import FunctionTool


def _text(sample: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = sample.get(key)
        if value not in ("", None, [], {}):
            return str(value)
    return ""


def apk_metadata(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    apk = sample.get("apk_analysis") if isinstance(sample.get("apk_analysis"), dict) else {}
    app_info = apk.get("app_info") if isinstance(apk.get("app_info"), dict) else {}
    packer = sample.get("packer")
    return {
        "package_name": _text(sample, "package_name") or str(app_info.get("package_name") or ""),
        "app_name": _text(sample, "app_name") or str(app_info.get("app_name") or ""),
        "permissions": sample.get("permissions") or app_info.get("permissions") or [],
        "packer": packer,
        "file_size": sample.get("file_size") or sample.get("apk_file_size"),
    }


def certificate(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    apk = sample.get("apk_analysis") if isinstance(sample.get("apk_analysis"), dict) else {}
    signature = apk.get("signature") if isinstance(apk.get("signature"), dict) else {}
    return {
        "signature_status": _text(sample, "signature_status") or str(signature.get("status") or ""),
        "certificate_fingerprint": _text(sample, "certificate_fingerprint", "cert_sha256", "cert_sha1"),
        "cert_sha1": _text(sample, "cert_sha1"),
        "cert_sha256": _text(sample, "cert_sha256"),
        "developer_signature": _text(sample, "developer_signature", "signature"),
    }


def sdk_inventory(sample: dict[str, Any], **_: Any) -> dict[str, Any]:
    apk = sample.get("apk_analysis") if isinstance(sample.get("apk_analysis"), dict) else {}
    return {
        "sdk_list": sample.get("sdk_list") or [],
        "sdk_risk": sample.get("sdk_risk") or apk.get("sdk_risk") or {},
    }


def static_tools() -> list[FunctionTool]:
    return [
        FunctionTool("apk_metadata", "static_analysis", apk_metadata, "APK package metadata"),
        FunctionTool("certificate", "static_analysis", certificate, "Certificate and signature facts"),
        FunctionTool("sdk_inventory", "static_analysis", sdk_inventory, "SDK inventory and risk"),
    ]
