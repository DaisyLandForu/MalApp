from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PROHIBITED_INPUT_KEYS = {
    "candidate_label",
    "gold_label",
    "human_label",
    "label",
    "raw_label",
    "reference_label",
    "target",
    "verdict",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def latest_ready_dir(root: Path) -> Path:
    candidates = [
        path
        for path in (root / "generated_datasets").glob(
            "strict_untrained_judgement_*_ready"
        )
        if path.is_dir()
    ]
    if not candidates:
        raise FileNotFoundError("no strict_untrained_judgement_*_ready directory")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_dir = (args.source_dir or latest_ready_dir(ROOT)).resolve()
    source_manifest = json.loads(
        (source_dir / "manifest.json").read_text(encoding="utf-8")
    )
    dataset_id_parts = str(source_manifest.get("dataset_id") or "").split("-")
    clean_count = dataset_id_parts[3] if len(dataset_id_parts) > 3 else ""
    count = int(clean_count) if clean_count.isdigit() else 0
    if not count:
        candidates = list(source_dir.glob("strict_untrained_judgement_*.json"))
        candidates = [path for path in candidates if not path.name.endswith("audit.json")]
        if len(candidates) != 1:
            raise ValueError("cannot infer strict holdout row count")
        count = int(candidates[0].stem.rsplit("_", 1)[-1])
    input_path = source_dir / f"strict_untrained_judgement_{count}.json"
    key_path = source_dir / f"strict_untrained_judgement_{count}_reference_key.csv"
    audit_path = source_dir / "strict_untrained_audit.json"
    items: list[dict[str, Any]] = json.loads(input_path.read_text(encoding="utf-8"))
    with key_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reference = {row["md5"].upper(): row for row in csv.DictReader(handle)}
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if len(items) != count or len(reference) != count:
        raise ValueError(f"strict holdout asset must contain exactly {count} rows")
    if not all(audit.get("checks", {}).values()):
        raise ValueError("source strict holdout audit did not pass")
    identifiers = {str(row.get("md5") or "").upper() for row in items}
    if len(identifiers) != count or identifiers != set(reference):
        raise ValueError("input/reference MD5 sets do not match")
    forbidden = sorted(
        {
            key
            for row in items
            for key in row
            if str(key).strip().lower() in PROHIBITED_INPUT_KEYS
        }
    )
    if forbidden:
        raise ValueError(f"answer fields remain in model input: {forbidden}")

    rows: list[dict[str, Any]] = []
    for item in items:
        sample_id = str(item["md5"]).upper()
        key = reference[sample_id]
        rows.append(
            {
                **item,
                "md5": sample_id,
                "sample_id": sample_id,
                "gold_label": key["reference_label"].lower(),
                "label_source": "strict_untrained_source_reference",
                "label_quality": "source_reference_requires_two_expert_reviews",
                "annotation_status": key.get("annotation_status")
                or "needs_two_expert_reviews_and_adjudication",
                "strict_untrained": "1",
                "release_tier": "provisional_strict_extension",
            }
        )
    fields = sorted({key for row in rows for key in row})
    preferred = [
        "md5",
        "sample_id",
        "gold_label",
        "label_source",
        "label_quality",
        "annotation_status",
        "strict_untrained",
        "release_tier",
    ]
    fields = preferred + [field for field in fields if field not in preferred]
    output = (
        args.output.resolve()
        if args.output
        else ROOT
        / "training_artifacts"
        / f"strict_untrained_release_{count}.csv"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "asset": output.name,
        "rows": len(rows),
        "unique_md5": len(identifiers),
        "label_distribution": {
            label: sum(1 for row in rows if row["gold_label"] == label)
            for label in ("malicious", "benign")
        },
        "label_tier": "source_reference_requires_two_expert_reviews",
        "release_policy": (
            "May expand strict-unseen diagnostics immediately; final release gate "
            "must retain the label-tier breakdown until expert adjudication."
        ),
        "input_answer_fields_absent": True,
        "source_audit_checks": audit["checks"],
        "sha256": {
            output.name: sha256_file(output),
            input_path.name: sha256_file(input_path),
            key_path.name: sha256_file(key_path),
            audit_path.name: sha256_file(audit_path),
        },
    }
    manifest_path = output.with_suffix(".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"output": str(output), **manifest}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
