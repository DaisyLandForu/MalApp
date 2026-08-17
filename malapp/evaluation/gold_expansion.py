from __future__ import annotations

import json
import os
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malapp.config.paths import resolve_data_dir

GOLD_EXPANSION_VERSION = "gold-expansion-v1"
VALID_REVIEW_LABELS = {"malicious", "benign", "exclude"}
APPROVED_STATUSES = {"approved", "adjudicated"}
PENDING_STATUSES = {
    "pending_first_review",
    "pending_second_review",
    "needs_adjudication",
}
GOLD_EXPANSION_LOCK = threading.RLock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: Any) -> str:
    return str(value or "").strip()


def expansion_root(data_dir: Path) -> Path:
    return data_dir / "evaluation" / "gold_expansion"


def state_path(data_dir: Path) -> Path:
    return expansion_root(data_dir) / "review_state.json"


def gold_sets_root(data_dir: Path) -> Path:
    return data_dir / "evaluation" / "gold_sets"


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default
    return value


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(temporary, path)
    return len(rows)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _latest_suite(data_dir: Path) -> dict[str, Any]:
    from malapp.evaluation.five_layer import latest_suite

    return latest_suite(data_dir=data_dir)


def _suite_records(
    data_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    from malapp.evaluation.five_layer import official_gold_row

    manifest = _latest_suite(data_dir)
    if not manifest:
        raise RuntimeError("请先生成五层评测套件。")
    suite_dir = Path(clean(manifest.get("suite_dir"))).resolve()
    release_path = suite_dir / "layer1_model" / "model_release_holdout.jsonl"
    gold_path = suite_dir / "layer1_model" / "expert_gold_holdout.jsonl"
    if not release_path.exists() or not gold_path.exists():
        raise FileNotFoundError("最新套件缺少发布集或专家金标文件，请重新生成套件。")
    release = _read_jsonl(release_path)
    official = [row for row in _read_jsonl(gold_path) if official_gold_row(row)]
    return manifest, release, official


def _new_state() -> dict[str, Any]:
    return {
        "version": GOLD_EXPANSION_VERSION,
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "target_total": 500,
        "malicious_ratio": 0.60,
        "items": [],
        "audit": [],
    }


def _load_state(data_dir: Path) -> dict[str, Any]:
    state = _read_json(state_path(data_dir), _new_state())
    if not isinstance(state, dict):
        state = _new_state()
    state.setdefault("version", GOLD_EXPANSION_VERSION)
    state.setdefault("target_total", 500)
    state.setdefault("malicious_ratio", 0.60)
    state.setdefault("items", [])
    state.setdefault("audit", [])
    return state


def _record_label(record: dict[str, Any]) -> str:
    expected = record.get("expected") or {}
    return clean(expected.get("verdict")).lower()


def _stable_rank(sample_id: str) -> str:
    import hashlib

    return hashlib.sha256(
        f"{GOLD_EXPANSION_VERSION}|candidate|{sample_id}".encode("utf-8")
    ).hexdigest()


def _target_label_counts(target_total: int, malicious_ratio: float) -> dict[str, int]:
    malicious = round(target_total * malicious_ratio)
    return {"malicious": malicious, "benign": target_total - malicious}


def _approved_item(item: dict[str, Any]) -> bool:
    return (
        clean(item.get("status")).lower() in APPROVED_STATUSES
        and clean(item.get("gold_label")).lower() in {"malicious", "benign"}
    )


def _prepare_locked(
    state: dict[str, Any],
    *,
    target_total: int,
    release: list[dict[str, Any]],
    official: list[dict[str, Any]],
    suite_id: str,
) -> dict[str, Any]:
    if target_total < len(official):
        raise ValueError(
            f"目标数量不能小于当前冻结金标数 {len(official)}。"
        )
    if target_total > len(release):
        raise ValueError(
            f"目标数量不能超过当前严格未见发布集 {len(release)} 条。"
        )
    state["target_total"] = target_total
    state["source_suite_id"] = suite_id
    malicious_ratio = float(state.get("malicious_ratio") or 0.60)
    items = [item for item in state.get("items") or [] if isinstance(item, dict)]
    state["items"] = items
    official_ids = {clean(row.get("id")).upper() for row in official}
    approved_extra = [
        item
        for item in items
        if _approved_item(item) and clean(item.get("id")).upper() not in official_ids
    ]
    current_counts = Counter(_record_label(row) for row in official)
    current_counts.update(clean(item.get("gold_label")).lower() for item in approved_extra)
    active_pending = [
        item
        for item in items
        if clean(item.get("status")).lower() in PENDING_STATUSES
        and clean(item.get("id")).upper() not in official_ids
    ]
    pending_counts = Counter(clean(item.get("source_reference_label")).lower() for item in active_pending)
    current_gold_total = len(official) + len(approved_extra)
    slots_needed = max(0, target_total - current_gold_total - len(active_pending))
    selected_ids = {clean(item.get("id")).upper() for item in items}
    candidates = [
        row
        for row in release
        if clean(row.get("id")).upper() not in official_ids
        and clean(row.get("id")).upper() not in selected_ids
        and _record_label(row) in {"malicious", "benign"}
    ]
    candidates.sort(key=lambda row: _stable_rank(clean(row.get("id")).upper()))
    desired = _target_label_counts(target_total, malicious_ratio)
    required_by_label = {
        label: max(0, desired[label] - current_counts[label] - pending_counts[label])
        for label in ("malicious", "benign")
    }
    selected: list[dict[str, Any]] = []
    for label in ("malicious", "benign"):
        for row in candidates:
            if len(selected) >= slots_needed:
                break
            if row in selected or _record_label(row) != label:
                continue
            if required_by_label[label] <= 0:
                break
            selected.append(row)
            required_by_label[label] -= 1
    if len(selected) < slots_needed:
        for row in candidates:
            if len(selected) >= slots_needed:
                break
            if row not in selected:
                selected.append(row)
    created_at = now_iso()
    for row in selected:
        items.append(
            {
                "id": clean(row.get("id")).upper(),
                "status": "pending_first_review",
                "gold_label": None,
                "source_reference_label": _record_label(row),
                "source_label_source": clean((row.get("expected") or {}).get("label_source")),
                "record": row,
                "reviews": [],
                "adjudication": None,
                "selected_at": created_at,
                "selected_for_target": target_total,
                "selection_method": "stable_stratified_60_malicious_40_benign",
            }
        )
    state["updated_at"] = now_iso()
    state["audit"].append(
        {
            "event": "prepare",
            "at": state["updated_at"],
            "target_total": target_total,
            "source_suite_id": suite_id,
            "added_candidates": len(selected),
        }
    )
    return state


def prepare_gold_expansion(
    *,
    target_total: int = 500,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    with GOLD_EXPANSION_LOCK:
        manifest, release, official = _suite_records(data_dir)
        state = _load_state(data_dir)
        _prepare_locked(
            state,
            target_total=int(target_total),
            release=release,
            official=official,
            suite_id=clean(manifest.get("suite_id")),
        )
        _atomic_write_json(state_path(data_dir), state)
    return gold_expansion_overview(data_dir=data_dir, include_items=False)


def _public_item(item: dict[str, Any], *, role: str) -> dict[str, Any]:
    record = item.get("record") or {}
    result = {
        "id": clean(item.get("id")).upper(),
        "status": clean(item.get("status")),
        "input": record.get("input") or {},
        "review_count": len(item.get("reviews") or []),
        "selected_for_target": item.get("selected_for_target"),
        "selection_method": item.get("selection_method"),
    }
    if role == "adjudicate":
        result["independent_reviews"] = [
            {
                "reviewer": clean(review.get("reviewer")),
                "label": clean(review.get("label")),
                "notes": clean(review.get("notes")),
                "submitted_at": review.get("submitted_at"),
            }
            for review in item.get("reviews") or []
        ]
    return result


def gold_expansion_overview(
    *,
    target_total: int | None = None,
    reviewer: str = "",
    role: str = "review",
    limit: int = 20,
    include_items: bool = True,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    manifest, release, official = _suite_records(data_dir)
    state = _load_state(data_dir)
    target = int(target_total or state.get("target_total") or 500)
    items = [item for item in state.get("items") or [] if isinstance(item, dict)]
    statuses = Counter(clean(item.get("status")) or "unknown" for item in items)
    official_ids = {clean(row.get("id")).upper() for row in official}
    approved_extra = [
        item
        for item in items
        if _approved_item(item) and clean(item.get("id")).upper() not in official_ids
    ]
    current_gold = len(official) + len(approved_extra)
    reviewer_key = clean(reviewer).casefold()
    role = "adjudicate" if role == "adjudicate" else "review"
    queue: list[dict[str, Any]] = []
    if include_items:
        for item in items:
            status = clean(item.get("status")).lower()
            review_names = {
                clean(value.get("reviewer")).casefold()
                for value in item.get("reviews") or []
            }
            if role == "adjudicate":
                eligible = status == "needs_adjudication" and reviewer_key not in review_names
            else:
                eligible = status in {"pending_first_review", "pending_second_review"} and reviewer_key not in review_names
            if eligible:
                queue.append(_public_item(item, role=role))
            if len(queue) >= max(1, min(100, int(limit))):
                break
    official_counts = Counter(_record_label(row) for row in official)
    official_counts.update(clean(item.get("gold_label")).lower() for item in approved_extra)
    desired = _target_label_counts(target, float(state.get("malicious_ratio") or 0.60))
    return {
        "version": state.get("version"),
        "source_suite_id": clean(manifest.get("suite_id")),
        "prepared": state_path(data_dir).exists(),
        "target_total": target,
        "release_total": len(release),
        "base_gold_count": len(official),
        "approved_additions": len(approved_extra),
        "current_gold_count": current_gold,
        "remaining_to_target": max(0, target - current_gold),
        "desired_labels": desired,
        "current_labels": {
            "malicious": official_counts["malicious"],
            "benign": official_counts["benign"],
        },
        "candidate_count": len(items),
        "status_counts": dict(statuses),
        "ready_to_freeze": current_gold >= target,
        "requires_two_distinct_reviewers": True,
        "requires_third_adjudicator_on_disagreement": True,
        "source_reference_hidden_from_reviewers": True,
        "role": role,
        "items": queue,
        "state_path": str(state_path(data_dir)),
    }


def save_gold_review(
    *,
    sample_id: str,
    reviewer: str,
    label: str,
    notes: str = "",
    role: str = "review",
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    sample_id = clean(sample_id).upper()
    reviewer = clean(reviewer)
    label = clean(label).lower()
    role = "adjudicate" if role == "adjudicate" else "review"
    if not sample_id or not reviewer:
        raise ValueError("sample_id 和 reviewer 均不能为空。")
    if label not in VALID_REVIEW_LABELS:
        raise ValueError("label 必须是 malicious、benign 或 exclude。")
    with GOLD_EXPANSION_LOCK:
        state = _load_state(data_dir)
        item = next(
            (value for value in state.get("items") or [] if clean(value.get("id")).upper() == sample_id),
            None,
        )
        if not item:
            raise FileNotFoundError(f"金标复核候选不存在：{sample_id}")
        review_names = {
            clean(value.get("reviewer")).casefold()
            for value in item.get("reviews") or []
        }
        if reviewer.casefold() in review_names:
            raise ValueError("同一复核人不能对同一样本重复提交或兼任仲裁人。")
        status = clean(item.get("status")).lower()
        submitted_at = now_iso()
        if role == "adjudicate":
            if status != "needs_adjudication":
                raise ValueError("只有两位专家结论不一致的样本可以进入仲裁。")
            item["adjudication"] = {
                "reviewer": reviewer,
                "label": label,
                "notes": clean(notes),
                "submitted_at": submitted_at,
            }
            item["gold_label"] = None if label == "exclude" else label
            item["status"] = "rejected" if label == "exclude" else "adjudicated"
        else:
            if status not in {"pending_first_review", "pending_second_review"}:
                raise ValueError("该样本当前不在独立复核队列中。")
            reviews = item.setdefault("reviews", [])
            reviews.append(
                {
                    "reviewer": reviewer,
                    "label": label,
                    "notes": clean(notes),
                    "submitted_at": submitted_at,
                }
            )
            if len(reviews) == 1:
                item["status"] = "pending_second_review"
            else:
                first_label = clean(reviews[0].get("label")).lower()
                second_label = clean(reviews[1].get("label")).lower()
                if first_label == second_label:
                    item["gold_label"] = None if first_label == "exclude" else first_label
                    item["status"] = "rejected" if first_label == "exclude" else "approved"
                else:
                    item["gold_label"] = None
                    item["status"] = "needs_adjudication"
        state["updated_at"] = now_iso()
        state.setdefault("audit", []).append(
            {
                "event": role,
                "at": state["updated_at"],
                "sample_id": sample_id,
                "reviewer": reviewer,
                "resulting_status": item.get("status"),
            }
        )
        _atomic_write_json(state_path(data_dir), state)
    # Rejected items are automatically replaced so the target remains reachable.
    prepare_gold_expansion(
        target_total=int(state.get("target_total") or 500),
        data_dir=data_dir,
    )
    return gold_expansion_overview(
        data_dir=data_dir,
        target_total=int(state.get("target_total") or 500),
        reviewer=reviewer,
        role=role,
        include_items=True,
    )


def load_frozen_gold_index(data_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    pointer = _read_json(gold_sets_root(data_dir) / "latest.json", {})
    dataset_path = Path(clean(pointer.get("dataset_path"))) if pointer else Path()
    if not pointer or not dataset_path.is_file():
        return {}
    return {
        clean(row.get("id")).upper(): row
        for row in _read_jsonl(dataset_path)
        if clean(row.get("id"))
    }


def freeze_gold_expansion(
    *,
    target_total: int = 500,
    name: str = "",
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    target_total = int(target_total)
    with GOLD_EXPANSION_LOCK:
        manifest, _, official = _suite_records(data_dir)
        state = _load_state(data_dir)
        official_by_id = {clean(row.get("id")).upper(): row for row in official}
        additions = [
            item
            for item in state.get("items") or []
            if _approved_item(item) and clean(item.get("id")).upper() not in official_by_id
        ]
        additions.sort(
            key=lambda item: (
                clean((item.get("adjudication") or {}).get("submitted_at"))
                or clean((item.get("reviews") or [{}])[-1].get("submitted_at")),
                clean(item.get("id")),
            )
        )
        needed = max(0, target_total - len(official_by_id))
        if len(additions) < needed:
            raise RuntimeError(
                f"尚缺 {needed - len(additions)} 条双专家批准/仲裁金标，不能冻结为 {target_total} 条。"
            )
        rows = list(official_by_id.values())
        for item in additions[:needed]:
            original = item.get("record") or {}
            final_label = clean(item.get("gold_label")).lower()
            status = clean(item.get("status")).lower()
            rows.append(
                {
                    "id": clean(item.get("id")).upper(),
                    "layer": "layer1_model",
                    "track": "single_model_feature_only",
                    "input": original.get("input") or {},
                    "expected": {
                        "verdict": final_label,
                        "label_source": "two_expert_review_with_adjudication_policy",
                        "output_schema": (original.get("expected") or {}).get("output_schema") or {},
                    },
                    "models": original.get("models") or ["model_a", "model_b", "candidate_model"],
                    "annotation_status": status,
                    "label_tier": "expert_adjudicated_gold" if status == "adjudicated" else "expert_approved_gold",
                    "intended_use": "release_gate",
                    "training_overlap": False,
                    "gold_provenance": {
                        "reviewers": [clean(value.get("reviewer")) for value in item.get("reviews") or []],
                        "adjudicator": clean((item.get("adjudication") or {}).get("reviewer")),
                        "frozen_at": now_iso(),
                    },
                }
            )
        if len(rows) != target_total:
            raise RuntimeError(f"冻结数量异常：期望 {target_total}，实际 {len(rows)}。")
        set_id = (
            f"{clean(name) or f'v2-gold{target_total}'}-"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        set_dir = gold_sets_root(data_dir) / set_id
        dataset_path = set_dir / "expert_gold_holdout.jsonl"
        _write_jsonl(dataset_path, rows)
        import hashlib

        dataset_hash = hashlib.sha256(dataset_path.read_bytes()).hexdigest()
        gold_manifest = {
            "version": GOLD_EXPANSION_VERSION,
            "set_id": set_id,
            "created_at": now_iso(),
            "target_total": target_total,
            "dataset_path": str(dataset_path),
            "sha256": dataset_hash,
            "source_suite_id": clean(manifest.get("suite_id")),
            "labels": dict(Counter(_record_label(row) for row in rows)),
            "policy": "existing frozen gold plus two independent expert reviews; disagreements require third adjudicator",
        }
        _atomic_write_json(set_dir / "manifest.json", gold_manifest)
        _atomic_write_json(gold_sets_root(data_dir) / "latest.json", gold_manifest)
        state["last_frozen_set"] = gold_manifest
        state["updated_at"] = now_iso()
        state.setdefault("audit", []).append(
            {
                "event": "freeze",
                "at": state["updated_at"],
                "set_id": set_id,
                "target_total": target_total,
            }
        )
        _atomic_write_json(state_path(data_dir), state)

    from malapp.evaluation.five_layer import generate_five_layer_suite

    suite = generate_five_layer_suite(
        name=clean(name) or f"v2-gold{target_total}",
        data_dir=data_dir,
    )
    return {"gold_set": gold_manifest, "five_layer_suite": suite}
