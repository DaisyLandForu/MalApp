"""Fail-closed leakage audit for governed MalApp datasets."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from malapp.governance.artifacts import canonical_json, now_iso, sha256_text
from malapp.governance.datasets import (
    validate_dataset_manifest,
    verify_bound_training_sources,
)

LEAKAGE_AUDIT_VERSION = 1
LABEL_DERIVED_PATTERNS = (
    re.compile(r"(^|[._])label($|[._])", re.IGNORECASE),
    re.compile(r"(^|[._])(human_label|reviewed_label|is_correct|reward)($|[._])", re.IGNORECASE),
    re.compile(r"(^|[._])(verdict|final_decision|malicious_flag|is_malicious)($|[._])", re.IGNORECASE),
    re.compile(r"(^|[._])(fraud_category|fraud_type|fraud_subtype)(_|$)", re.IGNORECASE),
    re.compile(r"(^|[._])(virus_name|detect_type|engine_label)($|[._])", re.IGNORECASE),
)


class TrainingLeakageError(RuntimeError):
    """Raised when a training entry point has no passing leakage clearance."""


def require_training_clearance(
    manifest_path: Path,
    *,
    required_partitions: set[str] | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
    report = audit_dataset_manifest(
        manifest_path,
        required_partitions=required_partitions or {"train", "test"},
        verify_sources=True,
    )
    if report_path:
        target = report_path.expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if report["status"] != "pass":
        raise TrainingLeakageError(
            f"training blocked by dataset leakage audit: {report['status']} "
            f"(audit_sha256={report['audit_sha256']})"
        )
    return report


def require_bound_training_sources(
    manifest_path: Path,
    actual_sources: dict[str, Path],
    *,
    required_partitions: set[str] | None = None,
) -> dict[str, Any]:
    audit = require_training_clearance(
        manifest_path,
        required_partitions=required_partitions,
    )
    sources = verify_bound_training_sources(manifest_path, actual_sources)
    return {"audit": audit, "sources": sources}


def audit_dataset_manifest(
    manifest_path: Path,
    *,
    reserved_sample_ids: set[str] | None = None,
    required_partitions: set[str] | None = None,
    verify_sources: bool = True,
) -> dict[str, Any]:
    validated = validate_dataset_manifest(manifest_path, verify_sources=verify_sources)
    return audit_lineage_records(
        validated["records"],
        dataset_id=str(validated["manifest"]["dataset_id"]),
        manifest_sha256=str(validated["manifest"]["sha256"]),
        reserved_sample_ids=reserved_sample_ids,
        required_partitions=required_partitions,
    )


def audit_lineage_records(
    records: Iterable[dict[str, Any]],
    *,
    dataset_id: str = "",
    manifest_sha256: str = "",
    reserved_sample_ids: set[str] | None = None,
    required_partitions: set[str] | None = None,
) -> dict[str, Any]:
    rows = list(records)
    checks: list[dict[str, Any]] = []
    blockers: list[str] = []
    if not rows:
        blockers.append("dataset lineage contains no samples")

    partitions = {str(row.get("partition") or "") for row in rows if row.get("partition")}
    required = set(required_partitions or {"train", "test"})
    missing_partitions = sorted(required - partitions)
    if missing_partitions:
        blockers.append(f"required partitions are missing: {', '.join(missing_partitions)}")

    required_fields = ("sample_id", "source", "source_version", "group_key", "label_tier", "partition")
    incomplete = [
        str(row.get("sample_id") or f"row-{index + 1}")
        for index, row in enumerate(rows)
        if any(row.get(field) in {None, ""} for field in required_fields)
    ]
    if incomplete:
        blockers.append(f"{len(incomplete)} lineage rows are missing required audit fields")

    checks.extend(
        [
            _cross_partition_check(rows, "sample_id", "md5_duplicate_or_identity_overlap"),
            _identity_check(rows, ("sha1", "sha256"), "same_source_apk_overlap"),
            _identity_check(rows, ("cert_md5", "cert_sha1", "cert_sha256"), "certificate_overlap"),
            _identity_check(rows, ("family",), "family_overlap"),
            _cross_partition_check(rows, "group_key", "group_key_overlap"),
            _duplicate_within_partition_check(rows),
            _label_feature_check(rows),
            _reserved_boundary_check(rows, reserved_sample_ids or set()),
        ]
    )
    if blockers:
        status = "blocked"
    elif any(check["status"] == "fail" for check in checks):
        status = "fail"
    else:
        status = "pass"
    identity = {
        "audit_version": LEAKAGE_AUDIT_VERSION,
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "status": status,
        "required_partitions": sorted(required),
        "partitions": sorted(partitions),
        "sample_count": len(rows),
        "blockers": blockers,
        "checks": checks,
    }
    return {
        **identity,
        "generated_at": now_iso(),
        "summary": {
            "passed": sum(check["status"] == "pass" for check in checks),
            "failed": sum(check["status"] == "fail" for check in checks),
            "blocked": len(blockers),
        },
        "audit_sha256": sha256_text(canonical_json(identity)),
    }


def _cross_partition_check(rows: list[dict[str, Any]], field: str, check_id: str) -> dict[str, Any]:
    values: dict[str, set[str]] = defaultdict(set)
    samples: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        value = str(row.get(field) or "").strip().lower()
        if not value:
            continue
        values[value].add(str(row.get("partition") or ""))
        samples[value].add(str(row.get("sample_id") or ""))
    overlaps = [
        {"value": value, "partitions": sorted(parts), "sample_ids": sorted(samples[value])[:20]}
        for value, parts in sorted(values.items())
        if len(parts) > 1
    ]
    return _check(check_id, overlaps, f"{field} must not cross dataset partitions")


def _identity_check(rows: list[dict[str, Any]], fields: tuple[str, ...], check_id: str) -> dict[str, Any]:
    values: dict[str, set[str]] = defaultdict(set)
    samples: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        identities = row.get("identities") or {}
        if not isinstance(identities, dict):
            continue
        for field in fields:
            value = str(identities.get(field) or "").strip().lower()
            if not value:
                continue
            key = f"{field}:{value}"
            values[key].add(str(row.get("partition") or ""))
            samples[key].add(str(row.get("sample_id") or ""))
    overlaps = [
        {"value": value, "partitions": sorted(parts), "sample_ids": sorted(samples[value])[:20]}
        for value, parts in sorted(values.items())
        if len(parts) > 1
    ]
    return _check(check_id, overlaps, f"{', '.join(fields)} identities must stay in one partition")


def _duplicate_within_partition_check(rows: list[dict[str, Any]]) -> dict[str, Any]:
    locations: dict[tuple[str, str], int] = defaultdict(int)
    for row in rows:
        locations[(str(row.get("partition") or ""), str(row.get("sample_id") or "").lower())] += 1
    overlaps = [
        {"partition": partition, "sample_id": sample_id, "count": count}
        for (partition, sample_id), count in sorted(locations.items())
        if sample_id and count > 1
    ]
    return _check("duplicate_sample_within_partition", overlaps, "sample_id must be unique inside a partition")


def _label_feature_check(rows: list[dict[str, Any]]) -> dict[str, Any]:
    violations = []
    for row in rows:
        names = row.get("feature_names") or []
        flagged = sorted(
            {
                str(name)
                for name in names
                if any(pattern.search(str(name)) for pattern in LABEL_DERIVED_PATTERNS)
            }
        )
        if flagged:
            violations.append({"sample_id": row.get("sample_id"), "features": flagged})
    return _check(
        "label_derived_features",
        violations,
        "features derived from labels, verdicts or engine conclusions are forbidden",
    )


def _reserved_boundary_check(rows: list[dict[str, Any]], reserved: set[str]) -> dict[str, Any]:
    normalized = {str(value).strip().lower() for value in reserved if str(value).strip()}
    violations = [
        {"sample_id": row.get("sample_id"), "partition": row.get("partition")}
        for row in rows
        if str(row.get("partition")) in {"train", "dev", "calibration"}
        and str(row.get("sample_id") or "").strip().lower() in normalized
    ]
    return _check(
        "reserved_evaluation_boundary",
        violations,
        "frozen evaluation identities must never enter training or tuning partitions",
    )


def _check(check_id: str, violations: list[dict[str, Any]], reason: str) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": "fail" if violations else "pass",
        "violation_count": len(violations),
        "examples": violations[:50],
        "reason": reason,
    }
