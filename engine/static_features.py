from __future__ import annotations

import base64
import hashlib
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = Path(os.getenv("MALAPP_WORKSPACE_ROOT", str(ROOT.parent))).expanduser().resolve()

ANDROID_PERMISSION_RE = re.compile(r"android\.permission\.[A-Z0-9_]+")
JAVA_PACKAGE_RE = re.compile(r"(?:[a-zA-Z_][\w$]*\.){2,}[A-Za-z_][\w$]*")

PACKER_SIGNATURES = [
    {"name": "360 Jiagu", "patterns": ["libjiagu", "qihoo", "stubapp"]},
    {"name": "Bangcle", "patterns": ["libsecexe", "libsecmain", "bangcle", "secneo"]},
    {"name": "Tencent Legu", "patterns": ["libshell", "legu", "tencent/stub"]},
    {"name": "Baidu Protect", "patterns": ["baiduprotect", "libbaiduprotect"]},
    {"name": "Ali Protect", "patterns": ["aliprotect", "libsgmain", "libsgsecuritybody"]},
    {"name": "Ijiami", "patterns": ["ijiami", "libexec", "ijiami.dat"]},
    {"name": "DexProtector", "patterns": ["dexprotector", "libdexprotector"]},
    {"name": "AppSealing", "patterns": ["appsealing", "libappsealing"]},
]

SDK_SIGNATURES = [
    {
        "name": "Google Play Services",
        "patterns": ["com.google.android.gms", "com.google.firebase"],
        "risk": "low",
        "data_permissions": [],
    },
    {
        "name": "Facebook SDK",
        "patterns": ["com.facebook"],
        "risk": "medium",
        "data_permissions": ["android.permission.GET_ACCOUNTS"],
    },
    {
        "name": "Umeng Analytics",
        "patterns": ["com.umeng", "com.umeng.analytics"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE", "android.permission.ACCESS_FINE_LOCATION"],
    },
    {
        "name": "JPush",
        "patterns": ["cn.jpush", "cn.jiguang"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE", "android.permission.ACCESS_FINE_LOCATION"],
    },
    {
        "name": "Tencent SDK",
        "patterns": ["com.tencent", "com.qq"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE", "android.permission.GET_ACCOUNTS"],
    },
    {
        "name": "Baidu SDK",
        "patterns": ["com.baidu", "com.baidu.mobstat"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE", "android.permission.ACCESS_FINE_LOCATION"],
    },
    {
        "name": "AppsFlyer",
        "patterns": ["com.appsflyer"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE"],
    },
    {
        "name": "Adjust",
        "patterns": ["com.adjust.sdk"],
        "risk": "medium",
        "data_permissions": [],
    },
    {
        "name": "AdMob",
        "patterns": ["com.google.android.gms.ads"],
        "risk": "medium",
        "data_permissions": ["android.permission.ACCESS_FINE_LOCATION"],
    },
    {
        "name": "ByteDance/Pangle",
        "patterns": ["com.bytedance", "com.pangle"],
        "risk": "medium",
        "data_permissions": ["android.permission.READ_PHONE_STATE"],
    },
]


def analyze_apk_from_sample(sample: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return APK-derived fields and a detailed static analysis report.

    The caller can provide either `apk_path` or `apk_base64`. The implementation
    intentionally uses only the Python standard library so the local MVP remains
    runnable without apktool/androguard.
    """
    apk_path = sample.get("apk_path") or sample.get("apk_file")
    apk_base64 = sample.get("apk_base64")
    if not apk_path and not apk_base64:
        return {}, {}

    temp_path: Path | None = None
    try:
        if apk_base64:
            raw = base64.b64decode(str(apk_base64), validate=False)
            handle = tempfile.NamedTemporaryFile(prefix="malapp_", suffix=".apk", delete=False)
            handle.write(raw)
            handle.close()
            temp_path = Path(handle.name)
            path = temp_path
        else:
            path = resolve_user_path(str(apk_path))
        report = analyze_apk(path)
    finally:
        if temp_path:
            try:
                temp_path.unlink()
            except OSError:
                pass

    extracted = flatten_apk_report(report)
    return extracted, report


def resolve_user_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    else:
        path = path.resolve()
    if not str(path).startswith(str(WORKSPACE_ROOT.resolve())):
        raise ValueError("apk_path must stay inside the workspace")
    if not path.exists() or not path.is_file():
        raise ValueError(f"apk_path does not exist: {path}")
    return path


def analyze_apk(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    file_hashes = {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        lower_names = [name.lower() for name in names]
        manifest_bytes = read_zip_member(apk, "AndroidManifest.xml")
        dex_members = [name for name in names if re.fullmatch(r"classes(?:\d*)\.dex", Path(name).name)]
        so_members = [name for name in names if name.lower().endswith(".so")]
        cert_members = [
            name
            for name in names
            if name.upper().startswith("META-INF/")
            and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF", "MANIFEST.MF"))
        ]
        dex_reports = [analyze_dex(apk.read(name), name) for name in dex_members]
        searchable_text = "\n".join(
            [extract_text(manifest_bytes or b""), *[report["string_preview"] for report in dex_reports], "\n".join(names)]
        )
        permissions = sorted(set(ANDROID_PERMISSION_RE.findall(searchable_text)))
        package_name = infer_package_name(searchable_text)
        signatures = analyze_signatures(apk, cert_members, raw)
        packers = detect_packers(lower_names, searchable_text)
        sdks = detect_sdks(searchable_text, permissions)

    return {
        "file": {
            "name": path.name,
            "size": len(raw),
            **file_hashes,
        },
        "app_info": {
            "package_name": package_name,
            "permissions": permissions,
            "file_count": len(names),
            "dex_count": len(dex_members),
            "native_library_count": len(so_members),
            "certificate_file_count": len([item for item in cert_members if item.upper().endswith((".RSA", ".DSA", ".EC"))]),
        },
        "signature": signatures,
        "structure": {
            "dex_files": dex_reports,
            "native_libraries": summarize_native_libs(so_members),
            "suspicious_entries": find_suspicious_entries(lower_names),
        },
        "packer": {
            "detected": bool(packers),
            "matches": packers,
            "hidden_feature_risk": "high" if packers else "low",
        },
        "sdk_risk": sdks,
        "static_trust": compute_static_trust(signatures, packers, sdks, permissions),
    }


def read_zip_member(apk: zipfile.ZipFile, name: str) -> bytes | None:
    try:
        return apk.read(name)
    except KeyError:
        return None


def analyze_dex(data: bytes, name: str) -> dict[str, Any]:
    header = {
        "magic": data[:8].decode("latin1", errors="replace"),
        "sha1": hashlib.sha1(data).hexdigest(),
        "size": len(data),
    }
    fields = {}
    if data.startswith(b"dex\n") and len(data) >= 112:
        fields = {
            "file_size": int.from_bytes(data[32:36], "little"),
            "string_ids_size": int.from_bytes(data[56:60], "little"),
            "type_ids_size": int.from_bytes(data[64:68], "little"),
            "method_ids_size": int.from_bytes(data[88:92], "little"),
            "class_defs_size": int.from_bytes(data[96:100], "little"),
        }
    text = extract_text(data)
    return {
        "name": name,
        **header,
        **fields,
        "string_preview": text[:200000],
        "suspicious_markers": find_suspicious_markers(text),
    }


def extract_text(data: bytes) -> str:
    chunks = []
    chunks.extend(match.decode("latin1", errors="ignore") for match in re.findall(rb"[\x20-\x7e]{4,}", data))
    try:
        chunks.append(data.decode("utf-16le", errors="ignore"))
    except UnicodeDecodeError:
        pass
    return "\n".join(chunks)


def infer_package_name(text: str) -> str:
    candidates = [item for item in JAVA_PACKAGE_RE.findall(text) if not item.startswith("android.permission.")]
    for item in candidates:
        if item.startswith(("com.", "cn.", "org.", "net.")):
            return item.strip(".")
    return ""


def analyze_signatures(apk: zipfile.ZipFile, members: list[str], apk_bytes: bytes) -> dict[str, Any]:
    cert_files = [name for name in members if name.upper().endswith((".RSA", ".DSA", ".EC"))]
    sf_files = [name for name in members if name.upper().endswith(".SF")]
    manifest = read_zip_member(apk, "META-INF/MANIFEST.MF") or b""
    certificate_blobs = []
    for name in cert_files:
        blob = apk.read(name)
        certificate_blobs.append({"name": name, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    has_apk_signing_block = b"APK Sig Block 42" in apk_bytes
    return {
        "status": "present" if cert_files or has_apk_signing_block else "missing",
        "schemes": {
            "v1_jar_signature": bool(cert_files),
            "v2_or_newer_signing_block": has_apk_signing_block,
        },
        "cert_files": cert_files,
        "certificate_blobs": certificate_blobs,
        "sf_files": sf_files,
        "manifest_digest": hashlib.sha256(manifest).hexdigest() if manifest else "",
        "manifest_entries": manifest.decode("utf-8", errors="ignore").count("\nName: ") if manifest else 0,
        "abnormal": not cert_files and not has_apk_signing_block,
    }


def detect_packers(lower_names: list[str], text: str) -> list[dict[str, str]]:
    haystack = "\n".join(lower_names) + "\n" + text.lower()
    matches = []
    for signature in PACKER_SIGNATURES:
        matched = [pattern for pattern in signature["patterns"] if pattern.lower() in haystack]
        if matched:
            matches.append({"name": signature["name"], "matched_patterns": ", ".join(sorted(set(matched)))})
    return matches


def detect_sdks(text: str, permissions: list[str]) -> dict[str, Any]:
    lower_text = text.lower()
    detected = []
    requested = set(permissions)
    for sdk in SDK_SIGNATURES:
        matched = [pattern for pattern in sdk["patterns"] if pattern.lower() in lower_text]
        if not matched:
            continue
        risky_permissions = sorted(requested.intersection(sdk["data_permissions"]))
        risk = sdk["risk"]
        if risky_permissions and risk == "medium":
            risk = "high"
        detected.append(
            {
                "name": sdk["name"],
                "matched_patterns": matched,
                "risk": risk,
                "risky_permission_combo": risky_permissions,
            }
        )
    return {
        "detected_sdks": detected,
        "risk_summary": {
            "high": sum(1 for item in detected if item["risk"] == "high"),
            "medium": sum(1 for item in detected if item["risk"] == "medium"),
            "low": sum(1 for item in detected if item["risk"] == "low"),
        },
    }


def summarize_native_libs(members: list[str]) -> list[dict[str, str]]:
    result = []
    for name in members[:200]:
        parts = Path(name).parts
        abi = parts[-2] if len(parts) >= 2 else ""
        result.append({"name": Path(name).name, "abi": abi, "path": name})
    return result


def find_suspicious_entries(lower_names: list[str]) -> list[str]:
    markers = ("assets/classes", ".dex.jar", "payload", "shell", "stub", "encrypt", "protect")
    return sorted({name for name in lower_names if any(marker in name for marker in markers)})[:100]


def find_suspicious_markers(text: str) -> list[str]:
    markers = []
    checks = {
        "dynamic_dex_loading": ["dalvik.system.DexClassLoader", "loadDex", "PathClassLoader"],
        "reflection": ["java.lang.reflect.Method", "Class.forName", "getDeclaredMethod"],
        "native_loading": ["System.loadLibrary", "System.load("],
        "overlay_or_accessibility": ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
    }
    for name, patterns in checks.items():
        if any(pattern in text for pattern in patterns):
            markers.append(name)
    return markers


def compute_static_trust(
    signatures: dict[str, Any],
    packers: list[dict[str, str]],
    sdk_risk: dict[str, Any],
    permissions: list[str],
) -> dict[str, Any]:
    score = 100
    anomalies = []
    if signatures.get("abnormal"):
        score -= 25
        anomalies.append("signature_missing")
    if packers:
        score -= 25
        anomalies.append("packer_detected")
    high_risk_sdks = sdk_risk["risk_summary"]["high"]
    medium_risk_sdks = sdk_risk["risk_summary"]["medium"]
    score -= min(25, high_risk_sdks * 12 + medium_risk_sdks * 6)
    risky_permissions = [
        item
        for item in permissions
        if any(term in item for term in ("SMS", "CONTACTS", "LOCATION", "PHONE_STATE", "SYSTEM_ALERT_WINDOW"))
    ]
    if risky_permissions:
        score -= min(20, len(risky_permissions) * 4)
        anomalies.append("risky_permissions")
    score = max(0, min(100, score))
    return {
        "score": score,
        "level": "high" if score >= 80 else "medium" if score >= 55 else "low",
        "anomalies": anomalies,
        "risk_deductions": {
            "signature": "signature_missing" in anomalies,
            "packer": bool(packers),
            "sdk_high": high_risk_sdks,
            "sdk_medium": medium_risk_sdks,
            "risky_permission_count": len(risky_permissions),
        },
    }


def flatten_apk_report(report: dict[str, Any]) -> dict[str, Any]:
    app_info = report.get("app_info", {})
    signature = report.get("signature", {})
    packer = report.get("packer", {})
    sdk_risk = report.get("sdk_risk", {})
    static_trust = report.get("static_trust", {})
    result = {
        "md5": report["file"]["md5"],
        "sha1": report["file"]["sha1"],
        "sha256": report["file"]["sha256"],
        "apk_file_name": report["file"]["name"],
        "apk_file_size": report["file"]["size"],
        "signature_status": "valid" if signature.get("status") == "present" else "missing",
        "packer": bool(packer.get("detected")),
        "packer_matches": packer.get("matches", []),
        "sdk_risk": sdk_risk,
        "static_trust": static_trust,
    }
    if app_info.get("package_name"):
        result["package_name"] = app_info["package_name"]
    if app_info.get("permissions"):
        result["permissions"] = app_info["permissions"]
    return result


def public_static_feedback(report: dict[str, Any]) -> dict[str, Any]:
    """Compact feedback object suitable for frontend/API consumers."""
    return {
        "app_info": report.get("app_info", {}),
        "signature": report.get("signature", {}),
        "packer": report.get("packer", {}),
        "sdk_risk": report.get("sdk_risk", {}),
        "static_trust": report.get("static_trust", {}),
        "structure": {
            "dex_files": [
                {key: value for key, value in dex.items() if key != "string_preview"}
                for dex in report.get("structure", {}).get("dex_files", [])
            ],
            "native_libraries": report.get("structure", {}).get("native_libraries", []),
            "suspicious_entries": report.get("structure", {}).get("suspicious_entries", []),
        },
    }
