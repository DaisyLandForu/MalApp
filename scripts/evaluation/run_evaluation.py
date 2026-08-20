from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ANSWER_ONLY_FIELDS = {
    "gold_label",
    "label",
    "raw_label",
    "reference_label",
    "human_label",
    "candidate_label",
    "target",
    "annotation_status",
    "label_source",
    "label_quality",
    "release_tier",
    "strict_untrained",
}
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malapp.config.paths import resolve_data_dir  # noqa: E402
from malapp.evaluation.framework import (  # noqa: E402
    DEFAULT_VALIDATION_CSV,
    build_rag_retrieval_scorecard,
    build_scorecard,
    evaluation_overview,
    evaluation_plan,
    freeze_evaluation_manifest,
    generate_evaluation_datasets,
    latest_report_index,
    load_reports,
    load_validation_rows,
)
from malapp.evaluation.gates import (  # noqa: E402
    evaluate_regression_gate,
    load_gate_policy,
    load_scorecard,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def deep_merge(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def apply_source_model_settings(data_dir: Path) -> dict[str, Any]:
    """Reuse the app's active model endpoints without writing credentials to artifacts."""
    saved = read_json(data_dir / "model_settings.json", {})
    if not isinstance(saved, dict):
        return {}
    mapping = {
        "server_models_enabled": "MALAPP_USE_SERVER_MODELS",
        "model_a_api_url": "MALAPP_MODEL_A_API_URL",
        "model_a_api_key": "MALAPP_MODEL_A_API_KEY",
        "model_a_model": "MALAPP_MODEL_A_MODEL",
        "model_b_api_url": "MALAPP_MODEL_B_API_URL",
        "model_b_api_key": "MALAPP_MODEL_B_API_KEY",
        "model_b_model": "MALAPP_MODEL_B_MODEL",
        "local_qwen_enabled": "MALAPP_USE_LOCAL_QWEN",
        "model": "MALAPP_QWEN_MODEL",
    }
    applied: dict[str, Any] = {}
    for setting_key, env_key in mapping.items():
        value = saved.get(setting_key)
        if value in (None, ""):
            continue
        if setting_key.endswith("_enabled"):
            value = "1" if bool(value) else "0"
        os.environ[env_key] = str(value)
        if "api_key" not in setting_key:
            applied[setting_key] = saved.get(setting_key)
    applied["credentials_reused"] = any(
        bool(saved.get(key)) for key in ("model_a_api_key", "model_b_api_key")
    )
    return applied


def cmd_plan(_: argparse.Namespace) -> None:
    print_json(evaluation_plan())


def cmd_status(args: argparse.Namespace) -> None:
    print_json(
        evaluation_overview(
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir) if args.data_dir else None,
        )
    )


def cmd_freeze(args: argparse.Namespace) -> None:
    print_json(
        freeze_evaluation_manifest(
            name=args.name,
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir) if args.data_dir else None,
        )
    )


def cmd_datasets(args: argparse.Namespace) -> None:
    print_json(
        generate_evaluation_datasets(
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir) if args.data_dir else None,
            core_size=args.core_size,
            challenge_size=args.challenge_size,
            rag_size=args.rag_size,
        )
    )


def cmd_scorecard(args: argparse.Namespace) -> None:
    scorecard = build_scorecard(
        validation_csv=Path(args.validation_csv),
        data_dir=Path(args.data_dir) if args.data_dir else None,
    )
    if args.output:
        write_json(Path(args.output), scorecard)
    print_json(scorecard)


def cmd_rag_scorecard(args: argparse.Namespace) -> None:
    scorecard = build_rag_retrieval_scorecard(Path(args.dataset))
    if args.output:
        write_json(Path(args.output), scorecard)
    print_json(scorecard)


def cmd_compare(args: argparse.Namespace) -> None:
    scorecards = []
    for value in args.scorecard:
        path = Path(value).expanduser().resolve()
        payload = read_json(path, None)
        if not isinstance(payload, dict) or not isinstance(payload.get("metrics"), dict):
            raise ValueError(f"invalid scorecard: {path}")
        scorecards.append((path, payload))
    baseline_path, baseline = scorecards[0]
    baseline_metrics = baseline["metrics"]
    tracked = (
        "coverage",
        "decided_accuracy",
        "malicious_recall",
        "malicious_precision",
        "benign_false_positive_rate",
        "macro_f1",
        "review_rate",
        "structure_success_rate",
        "invalid_fallback_rate",
    )
    rows = []
    for path, payload in scorecards:
        metrics = payload["metrics"]
        row = {
            "scorecard": str(path),
            "baseline": path == baseline_path,
            "metrics": {key: metrics.get(key) for key in tracked},
            "latency_ms": metrics.get("latency_ms") or {},
            "delta_vs_baseline": {},
        }
        for key in tracked:
            current = metrics.get(key)
            base = baseline_metrics.get(key)
            row["delta_vs_baseline"][key] = (
                round(float(current) - float(base), 6)
                if current is not None and base is not None
                else None
            )
        current_p95 = (metrics.get("latency_ms") or {}).get("p95")
        base_p95 = (baseline_metrics.get("latency_ms") or {}).get("p95")
        row["delta_vs_baseline"]["latency_p95_ms"] = (
            round(float(current_p95) - float(base_p95), 3)
            if current_p95 is not None and base_p95 is not None
            else None
        )
        rows.append(row)
    result = {
        "generated_at": now_iso(),
        "baseline": str(baseline_path),
        "comparisons": rows,
    }
    if args.output:
        write_json(Path(args.output), result)
    print_json(result)


def cmd_gate(args: argparse.Namespace) -> None:
    baseline_path = args.baseline_option or args.baseline
    candidate_path = args.candidate_option or args.candidate
    if not baseline_path or not candidate_path:
        raise ValueError("gate requires --baseline and --candidate scorecards")
    baseline = load_scorecard(Path(baseline_path))
    candidate = load_scorecard(Path(candidate_path))
    policy = load_gate_policy(Path(args.policy)) if args.policy else load_gate_policy()
    result = evaluate_regression_gate(baseline, candidate, policy)
    if args.output:
        write_json(Path(args.output), result)
    print_json(result)
    if result["status"] != "pass":
        raise SystemExit(1 if result["status"] == "fail" else 2)


def cmd_trajectory_manifest(args: argparse.Namespace) -> None:
    """Build a frozen 100-200 sample trajectory benchmark without running models."""
    from malapp.evaluation.trajectory import build_benchmark_manifest, write_json as write_traj

    rows = load_validation_rows(Path(args.validation_csv))
    manifest = build_benchmark_manifest(
        rows,
        size=args.size,
        runtime_snapshot_id=args.runtime_snapshot_id,
    )
    output = Path(args.output) if args.output else Path("outputs") / "evaluation" / "trajectory_benchmark.json"
    write_traj(output, manifest)
    print_json({"output": str(output), "size": manifest["size"], "strata": manifest["strata"]})


def cmd_trajectory_score(args: argparse.Namespace) -> None:
    """Score already persisted judgement reports. Does not call models."""
    from malapp.evaluation.trajectory import score_reports, write_json as write_traj

    reports = []
    if args.reports:
        payload = read_json(Path(args.reports), [])
        reports = payload if isinstance(payload, list) else payload.get("reports") or payload.get("trajectories") or []
    else:
        reports = load_reports(Path(args.data_dir) if args.data_dir else None)
    result = score_reports(reports)
    if args.output:
        write_traj(Path(args.output), result)
    print_json(result.get("comparison") or result)


def variant_config(args: argparse.Namespace) -> dict[str, Any]:
    variants = evaluation_plan()["experiment_variants"]
    if args.variant not in variants:
        raise ValueError(f"unsupported variant: {args.variant}")
    selected = json.loads(json.dumps(variants[args.variant], ensure_ascii=False))
    environment = dict(selected.get("environment") or {})
    sample_overrides = dict(selected.get("sample_overrides") or {})

    if args.rag_mode:
        environment["MALAPP_RAG_ENABLED"] = "0" if args.rag_mode == "off" else "1"
        if args.rag_mode != "off":
            environment["MALAPP_RAG_MODE"] = args.rag_mode
    for value, env_key in (
        (args.model_a_url, "MALAPP_MODEL_A_API_URL"),
        (args.model_a_model, "MALAPP_MODEL_A_MODEL"),
        (args.model_b_url, "MALAPP_MODEL_B_API_URL"),
        (args.model_b_model, "MALAPP_MODEL_B_MODEL"),
    ):
        if value:
            environment[env_key] = value
    if args.debate_mode:
        sample_overrides = deep_merge(
            sample_overrides,
            {"evaluation_config": {"debate_mode": args.debate_mode}},
        )
    if args.xgb_mode:
        sample_overrides = deep_merge(
            sample_overrides,
            {"evaluation_config": {"xgb_mode": args.xgb_mode}},
        )
    for agent in args.disabled_agent or []:
        sample_overrides = deep_merge(
            sample_overrides,
            {"agent_runtime_config": {"agents": {agent: {"enabled": False}}}},
        )
    if args.inject_agent_failure:
        sample_overrides = deep_merge(
            sample_overrides,
            {
                "agent_runtime_config": {
                    "agents": {args.inject_agent_failure: {"max_restarts": 1}}
                },
                "agent_runtime_faults": {args.inject_agent_failure: {"failures": 1}},
            },
        )
    mode = str(getattr(args, "orchestration_mode", "") or "").strip().lower()
    if mode in {"v0", "v0_fixed"}:
        environment.update(
            {
                "MALAPP_PLANNER_ENABLED": "0",
                "MALAPP_TOOL_RUNTIME_ENABLED": "0",
                "MALAPP_ORCHESTRATION_MODE": "v0_fixed",
            }
        )
    elif mode in {"v1", "v1_planner"}:
        environment.update(
            {
                "MALAPP_PLANNER_ENABLED": "1",
                "MALAPP_PLANNER_MODE": "rule",
                "MALAPP_TOOL_RUNTIME_ENABLED": "0",
                "MALAPP_ORCHESTRATION_MODE": "v1_planner",
            }
        )
    elif mode in {"v2", "v2_planner_tools"}:
        environment.update(
            {
                "MALAPP_PLANNER_ENABLED": "1",
                "MALAPP_PLANNER_MODE": "rule",
                "MALAPP_TOOL_RUNTIME_ENABLED": "1",
                "MALAPP_ORCHESTRATION_MODE": "v2_planner_tools",
            }
        )
    selected["environment"] = environment
    selected["sample_overrides"] = sample_overrides
    return selected


def load_requested_sample_ids(path: Path) -> set[str]:
    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"sample id file not found: {path}")
    requested: set[str] = set()
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid sample id JSONL at line {line_number}: {exc}"
                ) from exc
            if not isinstance(item, dict):
                raise ValueError(
                    f"invalid sample id JSONL at line {line_number}: object required"
                )
            sample_id = str(
                item.get("sample_id") or item.get("id") or item.get("md5") or ""
            ).strip().upper()
            if sample_id:
                requested.add(sample_id)
    return requested


def blind_model_input(row: dict[str, Any]) -> dict[str, Any]:
    """Remove scoring-only fields before a validation row reaches the pipeline."""
    return {
        key: value
        for key, value in row.items()
        if not key.startswith("_")
        and key.strip().lower() not in ANSWER_ONLY_FIELDS
        and value not in ("", None)
    }


def stage_isolated_runtime_assets(
    source_data_dir: Path,
    run_data_dir: Path,
    excluded_sample_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Copy read-mostly runtime inputs required by an isolated evaluation run."""
    run_data_dir.mkdir(parents=True, exist_ok=True)
    staged: dict[str, Any] = {
        "field_mapping": False,
        "rag_database": False,
        "rag_documents_excluded": 0,
    }
    mapping_sources = [
        source_data_dir / "field_mapping.json",
        ROOT / "data" / "field_mapping.json",
    ]
    mapping_source = next((path for path in mapping_sources if path.exists()), None)
    if mapping_source:
        target_mapping = run_data_dir / "field_mapping.json"
        if target_mapping.exists():
            staged["field_mapping_reused"] = True
        else:
            shutil.copy2(mapping_source, target_mapping)
        staged["field_mapping"] = True
        staged["field_mapping_source"] = str(mapping_source)

    source_rag = source_data_dir / "rag" / "rag_store.db"
    if source_rag.exists():
        target_rag = run_data_dir / "rag" / "rag_store.db"
        target_rag.parent.mkdir(parents=True, exist_ok=True)
        if target_rag.exists():
            staged["rag_database"] = True
            staged["rag_database_reused"] = True
            staged["rag_database_source"] = str(source_rag)
            staged["rag_database_target"] = str(target_rag)
            return staged
        source_conn = sqlite3.connect(
            f"file:{source_rag.as_posix()}?mode=ro", uri=True
        )
        target_conn = sqlite3.connect(target_rag)
        try:
            source_conn.backup(target_conn)
            excluded = {value.upper() for value in (excluded_sample_ids or set())}
            excluded_doc_ids: list[str] = []
            tables = {
                str(row[0])
                for row in target_conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if excluded and "rag_documents" in tables:
                for doc_id, metadata_json in target_conn.execute(
                    "SELECT doc_id,metadata_json FROM rag_documents"
                ):
                    try:
                        metadata = json.loads(metadata_json or "{}")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        metadata = {}
                    if str((metadata or {}).get("md5") or "").strip().upper() in excluded:
                        excluded_doc_ids.append(str(doc_id))
            if excluded_doc_ids:
                for table, column in (
                    ("kg_edges", "source_doc_id"),
                    ("kg_document_links", "doc_id"),
                    ("kg_index_state", "doc_id"),
                ):
                    if table in tables:
                        target_conn.executemany(
                            f"DELETE FROM [{table}] WHERE [{column}]=?",
                            ((doc_id,) for doc_id in excluded_doc_ids),
                        )
                target_conn.executemany(
                    "DELETE FROM rag_documents WHERE doc_id=?",
                    ((doc_id,) for doc_id in excluded_doc_ids),
                )
                if {"kg_nodes", "kg_document_links", "kg_edges"}.issubset(tables):
                    target_conn.execute(
                        "DELETE FROM kg_nodes WHERE node_id NOT IN "
                        "(SELECT node_id FROM kg_document_links) AND node_id NOT IN "
                        "(SELECT subject_id FROM kg_edges UNION SELECT object_id FROM kg_edges)"
                    )
                target_conn.commit()
                staged["rag_documents_excluded"] = len(excluded_doc_ids)
        finally:
            target_conn.close()
            source_conn.close()
        staged["rag_database"] = True
        staged["rag_database_source"] = str(source_rag)
        staged["rag_database_target"] = str(target_rag)
    return staged


def cmd_run(args: argparse.Namespace) -> None:
    if args.limit <= 0:
        raise ValueError("--limit must be positive; run a small smoke before a full evaluation")
    if args.max_consecutive_failures <= 0:
        raise ValueError("--max-consecutive-failures must be positive")
    source_data_dir = (
        Path(args.source_data_dir).expanduser().resolve()
        if args.source_data_dir
        else resolve_data_dir()
    )
    source_model_settings = apply_source_model_settings(source_data_dir)
    config = variant_config(args)
    output_root = Path(args.output_root).expanduser().resolve()
    run_dir = output_root / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    run_data_dir = run_dir / "data"
    previous_run_config = read_json(run_dir / "run_config.json", {})
    rows = load_validation_rows(Path(args.validation_csv))
    requested_sample_ids: set[str] = set()
    if args.sample_id_file:
        requested_sample_ids = load_requested_sample_ids(Path(args.sample_id_file))
    isolation_ids = set(requested_sample_ids)
    if args.isolation_sample_id_file:
        isolation_ids.update(
            load_requested_sample_ids(Path(args.isolation_sample_id_file))
        )
    if not isolation_ids:
        isolation_ids = {row["_row_id"] for row in rows}
    staged_assets = stage_isolated_runtime_assets(
        source_data_dir,
        run_data_dir,
        excluded_sample_ids=isolation_ids,
    )
    checkpoint_path = run_dir / "checkpoint.json"
    checkpoint = read_json(
        checkpoint_path,
        {
            "run_id": args.run_id,
            "variant": args.variant,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "items": {},
        },
    )
    environment = {
        **config.get("environment", {}),
        "MALAPP_DATA_DIR": str(run_data_dir),
        "MALAPP_EVAL_PLAN_VERSION": args.plan_version,
        "MALAPP_EVAL_VARIANT": args.variant,
        "MALAPP_MD5_REPORT_CACHE": "0",
    }
    if staged_assets.get("rag_database"):
        environment["MALAPP_RAG_DB"] = str(run_data_dir / "rag" / "rag_store.db")
    for key, value in environment.items():
        os.environ[str(key)] = str(value)
    compatibility_signature = {
        "plan_version": args.plan_version,
        "variant": args.variant,
        "validation_csv": str(Path(args.validation_csv).resolve()),
        "isolation_sample_id_file": str(args.isolation_sample_id_file or ""),
        "source_model_settings": source_model_settings,
        "variant_environment": config.get("environment", {}),
        "sample_overrides": config.get("sample_overrides", {}),
    }
    previous_signature = previous_run_config.get("compatibility_signature")
    if previous_signature and previous_signature != compatibility_signature:
        raise RuntimeError(
            "当前模型、评测变体或冻结输入与已有累计结果不一致；"
            "请生成新套件或恢复原配置，不能混入同一 run-id。"
        )

    # Import only after MALAPP_DATA_DIR and experiment controls are fixed.
    from malapp.application.judgement import init_db, judge

    init_db()
    indexed_rows = list(enumerate(rows))
    if args.sample_id_file:
        indexed_rows = [
            (source_index, row)
            for source_index, row in indexed_rows
            if row["_row_id"].upper() in requested_sample_ids
        ]
    source_completed = 0
    if args.pending_only:
        source_reports = latest_report_index(load_reports(source_data_dir))
        pending_rows: list[tuple[int, dict[str, Any]]] = []
        for source_index, row in indexed_rows:
            report = source_reports.get(row["_row_id"]) or {}
            verdict = str((report.get("decision") or {}).get("verdict") or "").lower()
            if verdict in {"malicious", "suspicious", "benign"}:
                source_completed += 1
            else:
                pending_rows.append((source_index, row))
        indexed_rows = pending_rows
    if args.replay_last_selection:
        replay_ids = {
            str(value).strip().upper()
            for value in (previous_run_config.get("selected_sample_ids") or [])
            if str(value).strip()
        }
        if not replay_ids:
            raise ValueError(
                "--replay-last-selection requires a previous batch selection for this run-id"
            )
        indexed_rows = [
            (source_index, row)
            for source_index, row in indexed_rows
            if row["_row_id"].upper() in replay_ids
        ]
    checkpoint_completed_before = sum(
        1
        for item in (checkpoint.get("items") or {}).values()
        if isinstance(item, dict) and item.get("status") == "completed"
    )
    if args.next_unfinished:
        indexed_rows = [
            (source_index, row)
            for source_index, row in indexed_rows
            if (checkpoint.get("items", {}).get(row["_row_id"]) or {}).get("status")
            != "completed"
        ]
    candidate_count = len(indexed_rows)
    selected_rows = indexed_rows[args.offset : args.offset + args.limit]
    run_config = {
        "run_id": args.run_id,
        "plan_version": args.plan_version,
        "variant": args.variant,
        "description": config.get("description"),
        "validation_csv": str(Path(args.validation_csv).resolve()),
        "offset": args.offset,
        "limit": args.limit,
        "pending_only": args.pending_only,
        "next_unfinished": args.next_unfinished,
        "replay_last_selection": args.replay_last_selection,
        "source_data_dir": str(source_data_dir),
        "source_completed_count": source_completed,
        "checkpoint_completed_before": checkpoint_completed_before,
        "candidate_count_before_slice": candidate_count,
        "sample_id_file": str(args.sample_id_file or ""),
        "isolation_sample_id_file": str(args.isolation_sample_id_file or ""),
        "requested_sample_id_count": len(requested_sample_ids),
        "selected_count": len(selected_rows),
        "selected_sample_ids": [row["_row_id"] for _, row in selected_rows],
        "source_model_settings": source_model_settings,
        "environment": environment,
        "sample_overrides": config.get("sample_overrides", {}),
        "staged_runtime_assets": staged_assets,
        "compatibility_signature": compatibility_signature,
        "created_at": checkpoint.get("created_at"),
    }
    write_json(run_dir / "run_config.json", run_config)
    if args.dry_run:
        result = {
            "dry_run": True,
            "run_id": args.run_id,
            "run_dir": str(run_dir),
            "pending_only": args.pending_only,
            "next_unfinished": args.next_unfinished,
            "replay_last_selection": args.replay_last_selection,
            "source_completed_count": source_completed,
            "checkpoint_completed_before": checkpoint_completed_before,
            "candidate_count_before_slice": candidate_count,
            "selected_count": len(selected_rows),
            "selected_sample_ids": [row["_row_id"] for _, row in selected_rows[:20]],
            "run_config": str(run_dir / "run_config.json"),
        }
        write_json(run_dir / "result.json", result)
        print_json(result)
        return

    completed = failed = skipped = 0
    consecutive_failures = 0
    aborted_early = False
    abort_reason = ""
    for source_index, row in selected_rows:
        sample_id = row["_row_id"]
        previous = checkpoint["items"].get(sample_id) or {}
        if previous.get("status") == "completed":
            skipped += 1
            continue
        sample = blind_model_input(row)
        sample = deep_merge(sample, config.get("sample_overrides") or {})
        started_at = now_iso()
        try:
            report = judge(sample)
            checkpoint["items"][sample_id] = {
                "status": "completed",
                "source_index": source_index,
                "started_at": started_at,
                "finished_at": now_iso(),
                "report_id": report.get("report_id"),
                "verdict": (report.get("decision") or {}).get("verdict"),
            }
            completed += 1
            consecutive_failures = 0
        except Exception as exc:
            checkpoint["items"][sample_id] = {
                "status": "failed",
                "source_index": source_index,
                "started_at": started_at,
                "finished_at": now_iso(),
                "error": f"{type(exc).__name__}: {exc}",
            }
            failed += 1
            consecutive_failures += 1
            if args.stop_on_error:
                checkpoint["updated_at"] = now_iso()
                write_json(checkpoint_path, checkpoint)
                raise
        checkpoint["updated_at"] = now_iso()
        write_json(checkpoint_path, checkpoint)
        if consecutive_failures >= args.max_consecutive_failures:
            aborted_early = True
            abort_reason = (
                f"连续 {consecutive_failures} 条样本失败，已自动熔断；"
                "请先恢复模型端点后从同一 run-id 续跑。"
            )
            break

    scorecard = build_scorecard(
        validation_csv=Path(args.validation_csv),
        data_dir=Path(environment["MALAPP_DATA_DIR"]),
    )
    write_json(run_dir / "scorecard.json", scorecard)
    cumulative_completed = sum(
        1
        for item in (checkpoint.get("items") or {}).values()
        if isinstance(item, dict) and item.get("status") == "completed"
    )
    cumulative_failed = sum(
        1
        for item in (checkpoint.get("items") or {}).values()
        if isinstance(item, dict) and item.get("status") == "failed"
    )
    result = {
        "run_id": args.run_id,
        "run_dir": str(run_dir),
        "variant": args.variant,
        "selected_this_invocation": len(selected_rows),
        "completed_this_invocation": completed,
        "failed_this_invocation": failed,
        "skipped_completed": skipped,
        "cumulative_completed": cumulative_completed,
        "cumulative_failed": cumulative_failed,
        "remaining_candidates": max(0, candidate_count - completed),
        "aborted_early": aborted_early,
        "abort_reason": abort_reason,
        "checkpoint": str(checkpoint_path),
        "scorecard": str(run_dir / "scorecard.json"),
        "metrics": scorecard["metrics"],
        "status": "failed" if failed else "completed",
    }
    write_json(run_dir / "result.json", result)
    print_json(result)
    if failed:
        raise RuntimeError(
            f"evaluation run completed with {failed} failed samples"
            f"{' and aborted early' if aborted_early else ''}; see {checkpoint_path}"
        )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="MalApp reproducible evaluation, dataset and experiment runner"
    )
    root.add_argument(
        "--validation-csv",
        default=str(DEFAULT_VALIDATION_CSV),
        help="labelled validation CSV",
    )
    sub = root.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="print the phased implementation plan")
    plan.set_defaults(func=cmd_plan)

    status = sub.add_parser("status", help="show plan and current scorecard")
    status.add_argument("--data-dir", default="")
    status.set_defaults(func=cmd_status)

    freeze = sub.add_parser("freeze", help="freeze a versioned evaluation manifest")
    freeze.add_argument("--name", default="v1")
    freeze.add_argument("--data-dir", default="")
    freeze.set_defaults(func=cmd_freeze)

    datasets = sub.add_parser("datasets", help="generate annotation candidate files")
    datasets.add_argument("--data-dir", default="")
    datasets.add_argument("--core-size", type=int, default=500)
    datasets.add_argument("--challenge-size", type=int, default=300)
    datasets.add_argument("--rag-size", type=int, default=200)
    datasets.set_defaults(func=cmd_datasets)

    scorecard = sub.add_parser("scorecard", help="calculate quality and runtime metrics")
    scorecard.add_argument("--data-dir", default="")
    scorecard.add_argument("--output", default="")
    scorecard.set_defaults(func=cmd_scorecard)

    rag_scorecard = sub.add_parser(
        "rag-scorecard",
        help="calculate retrieval metrics from an approved RAG annotation JSONL",
    )
    rag_scorecard.add_argument("dataset")
    rag_scorecard.add_argument("--output", default="")
    rag_scorecard.set_defaults(func=cmd_rag_scorecard)

    compare = sub.add_parser("compare", help="compare two or more saved scorecards")
    compare.add_argument("scorecard", nargs="+")
    compare.add_argument("--output", default="")
    compare.set_defaults(func=cmd_compare)

    gate = sub.add_parser(
        "gate",
        help="enforce release regression gates against an approved baseline",
    )
    gate.add_argument("baseline", nargs="?", help="approved baseline scorecard JSON")
    gate.add_argument("candidate", nargs="?", help="candidate scorecard JSON")
    gate.add_argument(
        "--baseline",
        dest="baseline_option",
        default="",
        help="approved baseline scorecard JSON",
    )
    gate.add_argument(
        "--candidate",
        dest="candidate_option",
        default="",
        help="candidate scorecard JSON",
    )
    gate.add_argument("--policy", default="", help="optional regression gate policy JSON")
    gate.add_argument("--output", default="", help="write the signed gate report JSON")
    gate.set_defaults(func=cmd_gate)

    traj_manifest = sub.add_parser(
        "trajectory-manifest",
        help="freeze a 100-200 sample trajectory benchmark without running models",
    )
    traj_manifest.add_argument("--size", type=int, default=150)
    traj_manifest.add_argument("--runtime-snapshot-id", default="")
    traj_manifest.add_argument("--output", default="")
    traj_manifest.set_defaults(func=cmd_trajectory_manifest)

    traj_score = sub.add_parser(
        "trajectory-score",
        help="score existing reports for V0/V1/V2 trajectory metrics; does not call models",
    )
    traj_score.add_argument("--data-dir", default="")
    traj_score.add_argument("--reports", default="", help="optional JSON list of reports")
    traj_score.add_argument("--output", default="")
    traj_score.set_defaults(func=cmd_trajectory_score)

    run = sub.add_parser("run", help="run one resumable experiment variant")
    run.add_argument("--variant", default="full")
    run.add_argument("--plan-version", default="v1")
    run.add_argument("--run-id", default=f"eval-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    run.add_argument("--output-root", default=str(ROOT / "outputs" / "evaluation_runs"))
    run.add_argument(
        "--source-data-dir",
        default="",
        help="existing app data used for pending detection and current model settings",
    )
    run.add_argument(
        "--pending-only",
        action="store_true",
        help="select only samples without a completed verdict in the source app database",
    )
    run.add_argument(
        "--next-unfinished",
        action="store_true",
        help="exclude checkpoint-completed samples before applying offset/limit so batches accumulate",
    )
    run.add_argument(
        "--replay-last-selection",
        action="store_true",
        help="reuse the previous run_config sample IDs to verify checkpoint idempotency",
    )
    run.add_argument("--offset", type=int, default=0)
    run.add_argument("--limit", type=int, default=10)
    run.add_argument(
        "--sample-id-file",
        default="",
        help="optional JSONL whose id/sample_id/md5 values restrict the evaluation rows",
    )
    run.add_argument(
        "--isolation-sample-id-file",
        default="",
        help="optional full-suite JSONL whose IDs must be excluded from staged RAG assets",
    )
    run.add_argument("--rag-mode", choices=["off", "vector", "hybrid"], default="")
    run.add_argument("--model-a-url", default="")
    run.add_argument("--model-a-model", default="")
    run.add_argument("--model-b-url", default="")
    run.add_argument("--model-b-model", default="")
    run.add_argument(
        "--debate-mode",
        choices=["no_debate", "single_model", "verification", "full"],
        default="",
    )
    run.add_argument(
        "--xgb-mode",
        choices=["off", "agent_only", "fusion", "full"],
        default="",
    )
    run.add_argument(
        "--disabled-agent",
        action="append",
        choices=["static_analysis", "threat_intel", "impersonation", "business_label"],
    )
    run.add_argument(
        "--inject-agent-failure",
        choices=["static_analysis", "threat_intel", "impersonation", "business_label"],
        default="",
    )
    run.add_argument(
        "--orchestration-mode",
        choices=["v0", "v1", "v2", "v0_fixed", "v1_planner", "v2_planner_tools"],
        default="",
        help="set Planner/Tool flags without invoking a new experiment family",
    )
    run.add_argument("--stop-on-error", action="store_true")
    run.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=3,
        help="abort after this many consecutive sample failures (default: 3)",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve the variant and sample selection without invoking any model",
    )
    run.set_defaults(func=cmd_run)
    return root


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
