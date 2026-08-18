"""Immutable dataset lineage manifests used by training and release gates."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from malapp.governance.artifacts import (
    canonical_json,
    now_iso,
    resolve_git_commit,
    sha256_file,
    sha256_text,
)

DATASET_MANIFEST_VERSION = 1
DATASET_LINEAGE_VERSION = "malapp-dataset-lineage-v1"
LABEL_TIERS = frozenset({"raw", "silver", "human_reviewed", "gold"})
PARTITIONS = frozenset({"raw", "train", "dev", "test", "calibration", "challenge", "shadow"})
HASH_FIELDS = ("md5", "sha1", "sha256", "cert_md5", "cert_sha1", "cert_sha256")


class DatasetManifestError(ValueError):
    """Raised when dataset lineage is incomplete or inconsistent."""


class DatasetIntegrityError(DatasetManifestError):
    """Raised when immutable dataset bytes no longer match their manifest."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise DatasetManifestError(f"cannot read JSON object: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise DatasetManifestError(f"JSON object required: {path}")
    return value


def iter_jsonl(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DatasetManifestError(
                        f"invalid JSONL at {path}:{line_number}: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise DatasetManifestError(
                        f"JSON object required at {path}:{line_number}"
                    )
                yield line_number, value
    except OSError as exc:
        raise DatasetManifestError(f"cannot read dataset file: {path}: {exc}") from exc


def normalize_label_tier(value: Any, record: dict[str, Any]) -> str:
    raw = str(value or record.get("label_tier") or "").strip().lower().replace("-", "_")
    aliases = {
        "": "raw",
        "manual_review_import": "human_reviewed",
        "human_review": "human_reviewed",
        "human": "human_reviewed",
        "curated_source_reference": "silver",
        "silver_rule_generated": "silver",
    }
    normalized = aliases.get(raw, raw)
    if normalized not in LABEL_TIERS:
        raise DatasetManifestError(f"unsupported label tier: {raw or '<empty>'}")
    return normalized


def normalize_partition(value: Any) -> str:
    partition = str(value or "raw").strip().lower()
    aliases = {"validation": "dev", "val": "dev", "holdout": "test"}
    partition = aliases.get(partition, partition)
    if partition not in PARTITIONS:
        raise DatasetManifestError(f"unsupported dataset partition: {partition}")
    return partition


def normalize_lineage_record(
    record: dict[str, Any],
    *,
    partition: str,
    source_name: str,
    source_version: str,
    line_number: int,
) -> dict[str, Any]:
    sample = record.get("input") or record.get("sample") or {}
    if not isinstance(sample, dict):
        sample = {}
    sample_id = _first(record, "sample_id", "id", "md5") or _first(sample, "sample_id", "id", "md5")
    sample_id = str(sample_id or "").strip()
    if not sample_id:
        raise DatasetManifestError(f"sample_id is required at {source_name}:{line_number}")

    tier = normalize_label_tier(record.get("lineage_tier") or record.get("label_tier"), record)
    original_label = record.get("original_label", record.get("label"))
    reviewed_label = record.get("reviewed_label")
    reviewer = str(record.get("reviewer") or "").strip()
    if tier in {"human_reviewed", "gold"}:
        reviewed_label = reviewed_label if reviewed_label not in {None, ""} else record.get("label")
        if not reviewer:
            reviewer = str(record.get("label_source") or "imported-review").strip()
    if tier == "gold" and (reviewed_label in {None, ""} or not reviewer):
        raise DatasetManifestError(f"gold sample requires reviewed_label and reviewer: {sample_id}")

    identities: dict[str, str] = {}
    for key in HASH_FIELDS:
        value = _first(record, key) or _first(sample, key)
        normalized = _normalize_hash(value)
        if normalized:
            identities[key] = normalized
    for key in ("package_name", "family", "fraud_family"):
        value = _first(record, key) or _first(sample, key)
        if value not in {None, ""}:
            identities["family" if key == "fraud_family" else key] = _normalize_identity(value)

    group = str(record.get("group_key") or record.get("group_id") or "").strip()
    if not group:
        group = _derive_group_key(identities, sample_id)

    evidence = record.get("evidence")
    if evidence is None:
        evidence = {
            "engine_observations": record.get("engine_observations") or [],
            "evidence_refs": record.get("evidence_refs") or [],
            "evidence_quality": record.get("evidence_quality"),
        }
    feature_names = sorted(_collect_feature_names(record))
    return {
        "schema_version": DATASET_LINEAGE_VERSION,
        "sample_id": sample_id,
        "source": str(record.get("source") or record.get("label_source") or source_name),
        "source_version": str(record.get("source_version") or source_version),
        "original_label": original_label,
        "reviewed_label": reviewed_label,
        "reviewer": reviewer,
        "evidence": evidence,
        "created_at": str(record.get("created_at") or ""),
        "group_key": group,
        "label_tier": tier,
        "partition": normalize_partition(record.get("partition") or partition),
        "identities": identities,
        "feature_names": feature_names,
        "source_location": {"file": source_name, "line": line_number},
    }


def build_dataset_manifest(
    *,
    dataset_name: str,
    inputs: dict[str, Path],
    output_dir: Path,
    dataset_version: str = "",
    git_commit: str = "",
    created_at: str = "",
) -> dict[str, Any]:
    if not dataset_name.strip():
        raise DatasetManifestError("dataset_name is required")
    if not inputs:
        raise DatasetManifestError("at least one partition input is required")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    source_entries: list[dict[str, Any]] = []
    lineage: list[dict[str, Any]] = []
    for raw_partition, raw_path in sorted(inputs.items()):
        partition = normalize_partition(raw_partition)
        path = raw_path.expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"dataset input does not exist: {path}")
        digest = sha256_file(path)
        rows = list(iter_jsonl(path))
        source_name = path.name
        source_entries.append(
            {
                "partition": partition,
                "name": source_name,
                "path": str(path),
                "sha256": digest,
                "size": path.stat().st_size,
                "rows": len(rows),
            }
        )
        for line_number, record in rows:
            lineage.append(
                normalize_lineage_record(
                    record,
                    partition=partition,
                    source_name=source_name,
                    source_version=f"sha256:{digest}",
                    line_number=line_number,
                )
            )
    if not lineage:
        raise DatasetManifestError("dataset contains no samples")

    lineage.sort(key=lambda row: (row["partition"], row["sample_id"], row["source"]))
    lineage_path = output_dir / "dataset-lineage.jsonl"
    _write_jsonl_atomic(lineage_path, lineage)
    lineage_digest = sha256_file(lineage_path)
    content_identity = {
        "manifest_version": DATASET_MANIFEST_VERSION,
        "schema_version": DATASET_LINEAGE_VERSION,
        "dataset_name": dataset_name.strip(),
        "sources": [_source_identity(entry) for entry in source_entries],
        "lineage_sha256": lineage_digest,
        "sample_count": len(lineage),
        "partitions": dict(Counter(row["partition"] for row in lineage)),
        "label_tiers": dict(Counter(row["label_tier"] for row in lineage)),
    }
    content_digest = sha256_text(canonical_json(content_identity))
    version = dataset_version.strip() or f"dataset-{content_digest[:16]}"
    identity = {**content_identity, "dataset_id": version}
    digest = sha256_text(canonical_json(identity))
    manifest = {
        **{key: value for key, value in identity.items() if key != "sources"},
        "sources": [_portable_source(entry) for entry in source_entries],
        "content_sha256": content_digest,
        "git_commit": git_commit or resolve_git_commit(),
        "created_at": created_at or now_iso(),
        "lineage": {
            "path": lineage_path.name,
            "sha256": lineage_digest,
            "size": lineage_path.stat().st_size,
        },
        "sha256": digest,
    }
    _write_json_atomic(output_dir / "dataset-manifest.json", manifest)
    return manifest


def validate_dataset_manifest(
    manifest_path: Path,
    *,
    verify_sources: bool = False,
) -> dict[str, Any]:
    path = manifest_path.expanduser().resolve()
    manifest = read_json(path)
    required = {
        "manifest_version",
        "schema_version",
        "dataset_id",
        "dataset_name",
        "sources",
        "lineage",
        "lineage_sha256",
        "content_sha256",
        "sample_count",
        "partitions",
        "label_tiers",
        "git_commit",
        "sha256",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise DatasetManifestError(f"dataset manifest is missing fields: {', '.join(missing)}")
    if manifest["manifest_version"] != DATASET_MANIFEST_VERSION:
        raise DatasetManifestError(f"unsupported dataset manifest version: {manifest['manifest_version']}")
    if manifest["schema_version"] != DATASET_LINEAGE_VERSION:
        raise DatasetManifestError(f"unsupported dataset lineage schema: {manifest['schema_version']}")

    content_identity = {
        "manifest_version": manifest["manifest_version"],
        "schema_version": manifest["schema_version"],
        "dataset_name": manifest["dataset_name"],
        "sources": [_source_identity(entry) for entry in manifest["sources"]],
        "lineage_sha256": manifest["lineage_sha256"],
        "sample_count": manifest["sample_count"],
        "partitions": manifest["partitions"],
        "label_tiers": manifest["label_tiers"],
    }
    content_digest = sha256_text(canonical_json(content_identity))
    if content_digest != manifest["content_sha256"]:
        raise DatasetIntegrityError("dataset content digest mismatch")
    identity = {**content_identity, "dataset_id": manifest["dataset_id"]}
    if sha256_text(canonical_json(identity)) != manifest["sha256"]:
        raise DatasetIntegrityError("dataset manifest digest mismatch")
    expected_id = f"dataset-{content_digest[:16]}"
    if not str(manifest["dataset_id"]).strip():
        raise DatasetManifestError("dataset_id is required")
    if re.fullmatch(r"dataset-[0-9a-f]{16}", str(manifest["dataset_id"])) and manifest["dataset_id"] != expected_id:
        raise DatasetIntegrityError("derived dataset_id does not match manifest digest")

    lineage_entry = manifest.get("lineage") or {}
    lineage_path = _safe_child(path.parent, str(lineage_entry.get("path") or ""))
    _verify_file(lineage_path, lineage_entry, "dataset lineage")
    rows = [row for _, row in iter_jsonl(lineage_path)]
    if len(rows) != int(manifest["sample_count"]):
        raise DatasetIntegrityError("dataset lineage row count mismatch")
    if Counter(row.get("partition") for row in rows) != Counter(manifest["partitions"]):
        raise DatasetIntegrityError("dataset partition counts do not match lineage")
    if Counter(row.get("label_tier") for row in rows) != Counter(manifest["label_tiers"]):
        raise DatasetIntegrityError("dataset label-tier counts do not match lineage")

    if verify_sources:
        for entry in manifest.get("sources") or []:
            source = Path(str(entry.get("path") or "")).expanduser().resolve()
            _verify_file(source, entry, f"dataset source {entry.get('name')}")
    return {"manifest": manifest, "lineage_path": lineage_path, "records": rows}


def _portable_source(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "partition": entry["partition"],
        "name": entry["name"],
        "path": entry["path"],
        "sha256": entry["sha256"],
        "size": entry["size"],
        "rows": entry["rows"],
    }


def _source_identity(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "partition": entry["partition"],
        "name": entry["name"],
        "sha256": entry["sha256"],
        "size": entry["size"],
        "rows": entry["rows"],
    }


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value is not None and value != "":
            return value
    return None


def _normalize_hash(value: Any) -> str:
    text = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    return text if len(text) in {32, 40, 64} else ""


def _normalize_identity(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())[:500]


def _derive_group_key(identities: dict[str, str], sample_id: str) -> str:
    for key in ("cert_sha256", "cert_sha1", "cert_md5", "family", "package_name", "sha256", "sha1", "md5"):
        if identities.get(key):
            return f"{key}:{sha256_text(identities[key])[:20]}"
    return f"sample:{sha256_text(sample_id)[:20]}"


def _collect_feature_names(record: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    explicit = record.get("feature_names")
    if isinstance(explicit, list):
        names.update(str(item).strip() for item in explicit if str(item).strip())
    for container_name in ("features", "feature_evidence"):
        container = record.get(container_name)
        if isinstance(container, dict):
            names.update(str(key).strip() for key in container if str(key).strip())
    return names


def _safe_child(parent: Path, relative: str) -> Path:
    if not relative:
        raise DatasetManifestError("dataset lineage path is required")
    path = (parent / relative).resolve()
    if path != parent and parent not in path.parents:
        raise DatasetManifestError(f"dataset path escapes manifest directory: {relative}")
    return path


def _verify_file(path: Path, entry: dict[str, Any], label: str) -> None:
    if not path.is_file():
        raise DatasetIntegrityError(f"{label} does not exist: {path}")
    if int(entry.get("size", -1)) != path.stat().st_size:
        raise DatasetIntegrityError(f"{label} size mismatch")
    digest = str(entry.get("sha256") or "")
    if len(digest) != 64 or sha256_file(path) != digest:
        raise DatasetIntegrityError(f"{label} SHA256 mismatch")


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _write_jsonl_atomic(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(canonical_json(row) + "\n")
    os.replace(temporary, path)
