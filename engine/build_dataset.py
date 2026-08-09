from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from engine.engine_store import build_sample_from_engine_records
from engine.pipeline import DATA_DIR, DB_PATH


def split_name(md5: str) -> str:
    """Stable 80/10/10 split by MD5 hash.

    The same MD5 will always go to the same split, even after regeneration.
    """
    bucket = int(hashlib.sha1(md5.encode("utf-8")).hexdigest()[:8], 16) % 100
    if bucket < 80:
        return "train"
    if bucket < 90:
        return "val"
    return "test"


def weak_label(sample: dict[str, Any]) -> str:
    """Generate a weak label from engine scores and business fields.

    This is not a human gold label. It is only good enough for rule tuning,
    prompt evaluation, and selecting samples for manual review.
    """
    score_a = float(sample.get("engine_a_score", 50))
    score_b = float(sample.get("engine_b_score", 50))
    scores = [score_a, score_b]
    has_fraud_family = bool(str(sample.get("fraud_family", "")).strip())
    has_impersonation_category = any(
        str(record.get("impersonation_l1", "") or record.get("impersonation_l2", "") or record.get("impersonation_l3", "")).strip()
        for record in sample.get("engine_records", [])
    )
    if has_fraud_family or has_impersonation_category:
        return "malicious"
    if min(scores) >= 70:
        return "malicious"
    if max(scores) < 30:
        return "benign"
    if abs(score_a - score_b) >= 35:
        return "suspicious"
    if max(scores) >= 45:
        return "suspicious"
    return "benign"


def iter_grouped_records(conflict_only: bool = False):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if conflict_only:
            md5_rows = conn.execute(
                """
                SELECT md5 FROM engine_detections
                GROUP BY md5
                HAVING COUNT(DISTINCT engine) >= 2
                ORDER BY md5
                """
            )
        else:
            md5_rows = conn.execute("SELECT DISTINCT md5 FROM engine_detections ORDER BY md5")
        for row in md5_rows:
            records = [
                dict(item)
                for item in conn.execute(
                    "SELECT * FROM engine_detections WHERE md5 = ? ORDER BY engine",
                    (row["md5"],),
                ).fetchall()
            ]
            yield row["md5"], records


def build_dataset(output_dir: Path, conflict_only: bool = False, limit: int | None = None) -> dict[str, int]:
    """Write train/val/test jsonl files from imported engine data."""
    output_dir.mkdir(parents=True, exist_ok=True)
    handles = {
        name: (output_dir / f"{name}.jsonl").open("w", encoding="utf-8")
        for name in ("train", "val", "test")
    }
    counts = {"train": 0, "val": 0, "test": 0}
    try:
        for index, (md5, records) in enumerate(iter_grouped_records(conflict_only=conflict_only), start=1):
            sample = build_sample_from_engine_records(records)
            split = split_name(md5)
            item = {
                "id": md5,
                "split": split,
                "weak_label": weak_label(sample),
                "input": sample,
                "target": {
                    "verdict": weak_label(sample),
                    "note": "weak label generated from engine scores and business fields; not human gold label",
                },
            }
            handles[split].write(json.dumps(item, ensure_ascii=False) + "\n")
            counts[split] += 1
            if limit and index >= limit:
                break
    finally:
        for handle in handles.values():
            handle.close()
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=str(DATA_DIR / "datasets"))
    parser.add_argument("--conflict-only", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    result = build_dataset(Path(args.output_dir), conflict_only=args.conflict_only, limit=args.limit)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
