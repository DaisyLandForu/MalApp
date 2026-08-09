from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
ASSET_LIBRARY_PATH = DATA_DIR / "official_app_assets.json"
WORKSPACE_ROOT = Path(os.getenv("MALAPP_WORKSPACE_ROOT", str(ROOT.parent))).expanduser().resolve()

TYPO_TAGS = {
    "substitution": "字符替换",
    "insertion": "字符插入",
    "deletion": "字符删除",
    "transposition": "字符交换",
    "homoglyph": "相似字符替换",
}

HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a",
    "$": "s",
    "vv": "w",
    "rn": "m",
}


def analyze_impersonation(sample: dict[str, Any]) -> dict[str, Any]:
    assets = load_asset_library()
    inline_assets = sample.get("official_app_assets") or sample.get("official_asset_library") or []
    assets.extend(normalize_assets(inline_assets))
    visual = visual_similarity(sample, assets)
    semantic = semantic_distance(sample, assets)
    asset_match = match_official_assets(sample, assets, visual, semantic)
    assessment = assess_impersonation(sample, visual, semantic, asset_match)
    return {
        "visual_similarity": visual,
        "semantic_distance": semantic,
        "official_asset_match": asset_match,
        "assessment": assessment,
        "evidence_block": {
            "agent": "impersonation",
            "claim": assessment["claim"],
            "confidence": assessment["confidence"],
            "score": assessment["impersonation_probability"],
            "evidence": assessment["evidence"],
            "missing_fields": assessment["missing_fields"],
        },
    }


def load_asset_library() -> list[dict[str, Any]]:
    if not ASSET_LIBRARY_PATH.exists():
        return []
    try:
        return normalize_assets(json.loads(ASSET_LIBRARY_PATH.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return []


def update_asset_library(records: list[dict[str, Any]]) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = load_asset_library()
    by_key = {asset_key(item): item for item in existing}
    for item in normalize_assets(records):
        by_key[asset_key(item)] = item
    merged = sorted(by_key.values(), key=lambda item: (item.get("brand", ""), item.get("package_name", "")))
    ASSET_LIBRARY_PATH.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"count": len(merged), "path": str(ASSET_LIBRARY_PATH)}


def normalize_assets(records: Any) -> list[dict[str, Any]]:
    if isinstance(records, dict):
        records = records.get("items", [])
    result = []
    for item in records if isinstance(records, list) else []:
        if not isinstance(item, dict):
            continue
        asset = dict(item)
        asset.setdefault("brand", asset.get("app_name") or asset.get("name") or "")
        asset.setdefault("app_name", asset.get("name") or asset.get("brand") or "")
        asset.setdefault("package_name", "")
        asset.setdefault("developer_signature", asset.get("signature") or asset.get("cert_sha256") or "")
        asset.setdefault("icon_text", "")
        asset.setdefault("icon_hash", "")
        result.append(asset)
    return result


def asset_key(asset: dict[str, Any]) -> str:
    return f"{asset.get('brand','').lower()}\x1f{asset.get('package_name','').lower()}"


def visual_similarity(sample: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    sample_icon = load_icon_bytes(sample)
    sample_hash = str(sample.get("icon_hash") or "").strip().lower()
    sample_text = str(sample.get("icon_text") or sample.get("ocr_text") or "").strip().lower()
    if sample_icon and not sample_hash:
        sample_hash = image_fingerprint(sample_icon).get("sha256", "")

    matches = []
    for asset in assets:
        asset_hash = str(asset.get("icon_hash") or "").strip().lower()
        asset_icon = load_icon_bytes(asset)
        if asset_icon and not asset_hash:
            asset_hash = image_fingerprint(asset_icon).get("sha256", "")
        hash_score = compare_hashes(sample_hash, asset_hash)
        image_score = hash_score
        if sample_icon and asset_icon:
            image_score = max(hash_score, compare_images(sample_icon, asset_icon))
        text_score = text_similarity(sample_text, str(asset.get("icon_text") or "").strip().lower())
        combined = 0.72 * image_score + 0.28 * text_score
        matches.append(
            {
                "brand": asset.get("brand", ""),
                "package_name": asset.get("package_name", ""),
                "icon_similarity": round(combined, 4),
                "image_similarity": round(image_score, 4),
                "ocr_text_similarity": round(text_score, 4),
                "detected_tamper": icon_tamper_label(image_score, text_score),
            }
        )
    matches.sort(key=lambda item: item["icon_similarity"], reverse=True)
    return {
        "sample_icon_available": bool(sample_icon or sample_hash or sample_text),
        "matches": matches[:10],
        "best_match": matches[0] if matches else None,
        "ocr_text": sample_text,
        "notice": "OCR uses provided icon_text/ocr_text unless optional OCR dependencies are installed.",
    }


def load_icon_bytes(record: dict[str, Any]) -> bytes:
    encoded = record.get("icon_base64")
    if encoded:
        try:
            return base64.b64decode(str(encoded), validate=False)
        except ValueError:
            return b""
    path_value = record.get("icon_path")
    if not path_value:
        return b""
    path = Path(str(path_value)).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    else:
        path = path.resolve()
    if not str(path).startswith(str(WORKSPACE_ROOT.resolve())) or not path.exists() or not path.is_file():
        return b""
    try:
        return path.read_bytes()
    except OSError:
        return b""


def image_fingerprint(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()}


def compare_hashes(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    if len(left) == len(right) and all(ch in "0123456789abcdef" for ch in left + right):
        distance = sum(1 for a, b in zip(left, right) if a != b)
        return max(0.0, 1.0 - distance / len(left))
    return text_similarity(left, right)


def compare_images(left: bytes, right: bytes) -> float:
    if left == right:
        return 1.0
    try:
        from PIL import Image
        import io

        left_img = Image.open(io.BytesIO(left)).convert("RGB").resize((16, 16))
        right_img = Image.open(io.BytesIO(right)).convert("RGB").resize((16, 16))
        left_pixels = list(left_img.getdata())
        right_pixels = list(right_img.getdata())
        mse = sum(
            (lp[0] - rp[0]) ** 2 + (lp[1] - rp[1]) ** 2 + (lp[2] - rp[2]) ** 2
            for lp, rp in zip(left_pixels, right_pixels)
        ) / (len(left_pixels) * 3)
        return max(0.0, 1.0 - math.sqrt(mse) / 255.0)
    except Exception:
        return compare_hashes(hashlib.sha256(left).hexdigest(), hashlib.sha256(right).hexdigest())


def icon_tamper_label(image_score: float, text_score: float) -> list[str]:
    labels = []
    if 0.72 <= image_score < 0.94:
        labels.append("疑似缩放/裁剪/轻微改色")
    if image_score >= 0.94 and text_score < 0.7:
        labels.append("图标高度相似但文字不一致")
    if text_score >= 0.85 and image_score < 0.7:
        labels.append("文字相近但图形差异较大")
    return labels


def semantic_distance(sample: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    sample_name = str(sample.get("app_name") or "").strip()
    sample_package = str(sample.get("package_name") or "").strip()
    matches = []
    for asset in assets:
        name_score, name_ops = edit_similarity(sample_name, str(asset.get("app_name") or asset.get("brand") or ""))
        package_score, package_ops = edit_similarity(sample_package, str(asset.get("package_name") or ""))
        phonetic_score = phonetic_similarity(sample_name, str(asset.get("app_name") or asset.get("brand") or ""))
        combined = max(name_score, phonetic_score) * 0.55 + package_score * 0.45
        matches.append(
            {
                "brand": asset.get("brand", ""),
                "official_app_name": asset.get("app_name", ""),
                "official_package_name": asset.get("package_name", ""),
                "name_similarity": round(name_score, 4),
                "phonetic_similarity": round(phonetic_score, 4),
                "package_similarity": round(package_score, 4),
                "combined_similarity": round(combined, 4),
                "tamper_tags": sorted(set(name_ops + package_ops + homoglyph_tags(sample_name, asset.get("app_name", "")))),
            }
        )
    matches.sort(key=lambda item: item["combined_similarity"], reverse=True)
    return {"matches": matches[:10], "best_match": matches[0] if matches else None}


def edit_similarity(left: str, right: str) -> tuple[float, list[str]]:
    left_norm = normalize_text(left)
    right_norm = normalize_text(right)
    if not left_norm or not right_norm:
        return 0.0, []
    distance, ops = levenshtein_ops(left_norm, right_norm)
    similarity = 1.0 - distance / max(len(left_norm), len(right_norm))
    return max(0.0, similarity), sorted(set(ops))


def normalize_text(value: str) -> str:
    text = str(value or "").lower().strip()
    for src, target in HOMOGLYPHS.items():
        text = text.replace(src, target)
    return re.sub(r"[\s._\-]+", "", text)


def levenshtein_ops(left: str, right: str) -> tuple[int, list[str]]:
    rows = len(left) + 1
    cols = len(right) + 1
    dp = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        dp[i][0] = i
    for j in range(cols):
        dp[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    ops = []
    i, j = len(left), len(right)
    while i > 0 or j > 0:
        if i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append("deletion")
            i -= 1
        elif j > 0 and dp[i][j] == dp[i][j - 1] + 1:
            ops.append("insertion")
            j -= 1
        else:
            if i > 0 and j > 0 and left[i - 1] != right[j - 1]:
                ops.append("substitution")
            i -= 1
            j -= 1
    if has_transposition(left, right):
        ops.append("transposition")
    return dp[-1][-1], [TYPO_TAGS[item] for item in ops if item in TYPO_TAGS]


def has_transposition(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    diffs = [idx for idx, (a, b) in enumerate(zip(left, right)) if a != b]
    return len(diffs) == 2 and left[diffs[0]] == right[diffs[1]] and left[diffs[1]] == right[diffs[0]]


def homoglyph_tags(left: str, right: str) -> list[str]:
    left_raw = str(left or "").lower()
    right_raw = str(right or "").lower()
    if left_raw != right_raw and normalize_text(left_raw) == normalize_text(right_raw):
        return [TYPO_TAGS["homoglyph"]]
    return []


def phonetic_similarity(left: str, right: str) -> float:
    return edit_similarity(phonetic_key(left), phonetic_key(right))[0]


def phonetic_key(value: str) -> str:
    text = normalize_text(value)
    text = re.sub(r"[aeiou]+", "", text)
    return text


def text_similarity(left: str, right: str) -> float:
    return edit_similarity(left, right)[0]


def match_official_assets(
    sample: dict[str, Any],
    assets: list[dict[str, Any]],
    visual: dict[str, Any],
    semantic: dict[str, Any],
) -> dict[str, Any]:
    sample_signature = str(sample.get("developer_signature") or sample.get("signature") or sample.get("cert_sha256") or "")
    candidates = {}
    for source_name, report in (("visual", visual), ("semantic", semantic)):
        for item in report.get("matches", []):
            key = f"{item.get('brand','')}\x1f{item.get('package_name') or item.get('official_package_name','')}"
            candidates.setdefault(key, {"brand": item.get("brand", ""), "package_name": item.get("package_name") or item.get("official_package_name", ""), "sources": []})
            candidates[key]["sources"].append({"source": source_name, **item})
    for candidate in candidates.values():
        asset = next((item for item in assets if item.get("brand") == candidate["brand"] and item.get("package_name") == candidate["package_name"]), {})
        signature_match = bool(sample_signature and sample_signature == str(asset.get("developer_signature") or ""))
        candidate["developer_signature_match"] = signature_match
        candidate["official_asset"] = {
            "app_name": asset.get("app_name", ""),
            "package_name": asset.get("package_name", ""),
            "developer_signature": asset.get("developer_signature", ""),
        }
    scored = []
    for candidate in candidates.values():
        visual_score = max((item.get("icon_similarity", 0.0) for item in candidate["sources"] if item["source"] == "visual"), default=0.0)
        semantic_score = max((item.get("combined_similarity", 0.0) for item in candidate["sources"] if item["source"] == "semantic"), default=0.0)
        signature_bonus = 0.12 if candidate["developer_signature_match"] else 0.0
        candidate["match_score"] = round(min(1.0, 0.5 * visual_score + 0.38 * semantic_score + signature_bonus), 4)
        scored.append(candidate)
    scored.sort(key=lambda item: item["match_score"], reverse=True)
    return {"asset_count": len(assets), "candidates": scored[:10], "best_match": scored[0] if scored else None}


def assess_impersonation(
    sample: dict[str, Any],
    visual: dict[str, Any],
    semantic: dict[str, Any],
    asset_match: dict[str, Any],
) -> dict[str, Any]:
    visual_score = (visual.get("best_match") or {}).get("icon_similarity", 0.0) or 0.0
    semantic_score = (semantic.get("best_match") or {}).get("combined_similarity", 0.0) or 0.0
    asset_score = (asset_match.get("best_match") or {}).get("match_score", 0.0) or 0.0
    declared_fake = str(sample.get("fake_app", "")).lower() in {"1", "true", "yes", "y"}
    probability = max(asset_score, 0.38 * visual_score + 0.42 * semantic_score + (0.18 if declared_fake else 0.0))
    probability = max(0.0, min(1.0, probability))
    evidence = []
    if visual_score >= 0.7:
        evidence.append(f"图标/图标文字与正版资产相似度 {visual_score:.2f}。")
    if semantic_score >= 0.65:
        evidence.append(f"应用名与包名语义编辑相似度 {semantic_score:.2f}。")
    best = asset_match.get("best_match")
    if best:
        evidence.append(f"最接近正版资产：{best.get('brand') or best.get('package_name')}，匹配分 {best.get('match_score'):.2f}。")
    if declared_fake:
        evidence.append("样本已有仿冒应用标记。")
    if not evidence:
        evidence.append("未发现足够强的仿冒证据。")
    missing = []
    if not visual.get("sample_icon_available"):
        missing.append("icon_path/icon_base64/icon_hash/icon_text")
    if not asset_match.get("asset_count"):
        missing.append("official_app_assets")
    confidence = min(0.98, 0.35 + 0.25 * bool(visual_score) + 0.2 * bool(semantic_score) + 0.2 * bool(asset_match.get("asset_count")))
    return {
        "impersonation_probability": round(probability, 4),
        "harm_level": "high" if probability >= 0.8 else "medium" if probability >= 0.55 else "low",
        "claim": "仿冒风险较高" if probability >= 0.8 else "仿冒风险中等" if probability >= 0.55 else "仿冒风险较低",
        "confidence": round(confidence, 4),
        "evidence": evidence,
        "missing_fields": missing,
    }
