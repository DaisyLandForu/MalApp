from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malapp.config.paths import resolve_data_dir
from malapp.evaluation.five_layer import (
    official_gold_row,
    selected_five_layer_suite,
)
from malapp.evaluation.framework import (
    DEFAULT_VALIDATION_CSV,
    latest_report_index,
    load_reports,
)

ROOT = Path(__file__).resolve().parents[2]
ACTIVE_STATUSES = {"queued", "running", "cancelling"}
TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
WORKFLOW_CATALOG: dict[str, dict[str, Any]] = {
    "gold_compare": {
        "layer": "layer1_model",
        "name": "运行专家金标集评测",
        "description": (
            "按与其他数据集相同的累计和持久化规则运行专家金标集，"
            "并比较最终融合、模型甲、模型乙和XGBoost四条决策路径。"
        ),
        "automatic": True,
        "estimated_model_calls": 0,
        "default_batch_size": 10,
        "variant_count": 1,
    },
    "model_release": {
        "layer": "layer1_model",
        "name": "运行严格集模型甲乙对比",
        "description": "在最新严格训练未见集上重新运行完整双模型流程并保存可恢复检查点。",
        "automatic": True,
        "estimated_model_calls": 0,
        "default_batch_size": 50,
        "variant_count": 1,
    },
    "rag_compare": {
        "layer": "layer2_rag",
        "name": "运行无RAG/向量/混合RAG对比",
        "description": "在用户指定的同一批检索样本上运行三种RAG变体；专家检索标注仍需人工完成。",
        "automatic": True,
        "estimated_model_calls": 0,
        "default_batch_size": 20,
        "variant_count": 3,
    },
    "agent_ablation": {
        "layer": "layer3_agent",
        "name": "运行完整与四个去Agent消融",
        "description": "依次运行完整系统及去静态、情报、仿冒、业务Agent五个变体。",
        "automatic": True,
        "estimated_model_calls": 0,
        "default_batch_size": 10,
        "variant_count": 5,
    },
    "complete_release": {
        "layer": "layer4_e2e",
        "name": "补跑严格集未完成样本",
        "description": "根据当前APP报告自动筛选严格训练未见集中的未完成样本并断点续跑。",
        "automatic": True,
        "estimated_model_calls": 0,
        "default_batch_size": 50,
        "variant_count": 1,
    },
    "production_reliability": {
        "layer": "layer5_production",
        "name": "运行故障恢复与断点幂等测试",
        "description": "在挑战样本上注入四Agent瞬时故障，并重复同一run-id验证检查点跳过与幂等恢复。",
        "automatic": True,
        "estimated_model_calls": 20,
        "default_batch_size": 10,
        "variant_count": 2,
    },
}


def workflow_dataset_total(action: str, manifest: dict[str, Any]) -> int:
    counts = manifest.get("dataset_counts") or {}
    if action == "gold_compare":
        return int(
            ((counts.get("layer1_model") or {}).get("expert_gold_holdout"))
            or (manifest.get("selection") or {}).get("expert_gold_holdout_count")
            or (manifest.get("selection") or {}).get("frozen_gold_release_count")
            or 0
        )
    if action in {"model_release", "complete_release"}:
        return int((manifest.get("selection") or {}).get("release_holdout_count") or 0)
    if action == "rag_compare":
        return int(((counts.get("layer2_rag") or {}).get("rag_retrieval_eval")) or 0)
    if action == "agent_ablation":
        return int(((counts.get("layer3_agent") or {}).get("agent_ablation_eval")) or 0)
    if action == "production_reliability":
        return int(
            ((counts.get("layer4_e2e") or {}).get("end_to_end_challenge_eval")) or 0
        )
    return 0


def workflow_run_ids(action: str, suite_id: str) -> list[str]:
    if action == "gold_compare":
        return [f"{suite_id}-gold-compare"]
    if action in {"model_release", "complete_release"}:
        return [f"{suite_id}-model-release"]
    if action == "rag_compare":
        return [f"{suite_id}-{variant}" for variant in ("rag_off", "rag_vector", "rag_hybrid")]
    if action == "agent_ablation":
        return [
            f"{suite_id}-{suffix}"
            for suffix in (
                "full",
                "no-static_analysis",
                "no-threat_intel",
                "no-impersonation",
                "no-business_label",
            )
        ]
    if action == "production_reliability":
        return [f"{suite_id}-fault-recovery"]
    return []


def workflow_cumulative_progress(
    action: str,
    manifest: dict[str, Any],
    data_dir: Path,
) -> dict[str, Any]:
    dataset_total = workflow_dataset_total(action, manifest)
    suite_id = str(manifest.get("suite_id") or "")
    completed_by_variant: list[int] = []
    failed_by_variant: list[int] = []
    completed_ids_by_variant: list[set[str]] = []
    for run_id in workflow_run_ids(action, suite_id):
        checkpoint = read_json(
            data_dir / "evaluation" / "five_layer_runs" / run_id / "checkpoint.json",
            {},
        )
        items = checkpoint.get("items") or {}
        completed_ids = {
            str(sample_id).upper()
            for sample_id, item in items.items()
            if isinstance(item, dict) and item.get("status") == "completed"
        }
        completed_ids_by_variant.append(completed_ids)
        completed_by_variant.append(len(completed_ids))
        failed_by_variant.append(
            sum(
                1
                for item in items.values()
                if isinstance(item, dict) and item.get("status") == "failed"
            )
        )
    completed_base = min(completed_by_variant) if completed_by_variant else 0
    if action == "complete_release":
        suite_dir = Path(str(manifest.get("suite_dir") or ""))
        release_file = workflow_sample_file(action, suite_dir)
        release_ids: set[str] = set()
        if release_file.exists():
            with release_file.open("r", encoding="utf-8-sig") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    if isinstance(item, dict):
                        sample_id = str(
                            item.get("sample_id") or item.get("id") or item.get("md5") or ""
                        ).strip().upper()
                        if sample_id:
                            release_ids.add(sample_id)
        source_completed = {
            str(sample_id).upper()
            for sample_id, report in latest_report_index(load_reports(data_dir)).items()
            if str((report.get("decision") or {}).get("verdict") or "").lower()
            in {"malicious", "suspicious", "benign"}
        }
        checkpoint_completed = set().union(*completed_ids_by_variant) if completed_ids_by_variant else set()
        completed_base = len((source_completed | checkpoint_completed) & release_ids)
    completed_base = min(dataset_total, completed_base)
    remaining = max(0, dataset_total - completed_base)
    return {
        "dataset_total": dataset_total,
        "completed_base_samples": completed_base,
        "remaining_base_samples": remaining,
        "coverage": completed_base / dataset_total if dataset_total else 0.0,
        "completed_executions": sum(completed_by_variant),
        "failed_executions": sum(failed_by_variant),
        "completed_by_variant": completed_by_variant,
        "failed_by_variant": failed_by_variant,
    }


def prepare_workflow_batch(
    action: str,
    *,
    manifest: dict[str, Any],
    data_dir: Path,
    source_file: Path,
    job_id: str,
    batch_size: int,
) -> dict[str, Any]:
    rows: list[tuple[str, dict[str, Any]]] = []
    with source_file.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                continue
            sample_id = str(
                item.get("sample_id") or item.get("id") or item.get("md5") or ""
            ).strip().upper()
            if sample_id:
                rows.append((sample_id, item))

    suite_id = str(manifest.get("suite_id") or "")
    completed_sets: list[set[str]] = []
    for run_id in workflow_run_ids(action, suite_id):
        checkpoint = read_json(
            data_dir / "evaluation" / "five_layer_runs" / run_id / "checkpoint.json",
            {},
        )
        completed_sets.append(
            {
                str(sample_id).upper()
                for sample_id, item in (checkpoint.get("items") or {}).items()
                if isinstance(item, dict) and item.get("status") == "completed"
            }
        )

    source_completed: set[str] = set()
    if action == "complete_release":
        for sample_id, report in latest_report_index(load_reports(data_dir)).items():
            verdict = str((report.get("decision") or {}).get("verdict") or "").lower()
            if verdict in {"malicious", "suspicious", "benign"}:
                source_completed.add(str(sample_id).upper())

    eligible: list[tuple[str, dict[str, Any]]] = []
    for sample_id, item in rows:
        if sample_id in source_completed:
            continue
        if completed_sets and all(sample_id in completed for completed in completed_sets):
            continue
        eligible.append((sample_id, item))
    selected = eligible[: max(1, int(batch_size))]
    batch_file = jobs_dir(data_dir) / f"{job_id}-samples.jsonl"
    temporary = batch_file.with_suffix(batch_file.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for _, item in selected),
        encoding="utf-8",
    )
    os.replace(temporary, batch_file)
    return {
        "path": str(batch_file),
        "selected_count": len(selected),
        "eligible_count": len(eligible),
        "source_completed_count": len(source_completed),
        "selected_sample_ids": [sample_id for sample_id, _ in selected],
    }


def workflow_sample_file(action: str, suite_dir: Path) -> Path:
    if action == "gold_compare":
        path = suite_dir / "layer1_model" / "expert_gold_holdout.jsonl"
        if not path.exists():
            release_path = suite_dir / "layer1_model" / "model_release_holdout.jsonl"
            if release_path.exists():
                rows = []
                with release_path.open("r", encoding="utf-8-sig") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        item = json.loads(line)
                        if isinstance(item, dict) and official_gold_row(item):
                            rows.append(item)
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
                temporary.write_text(
                    "".join(
                        json.dumps(item, ensure_ascii=False) + "\n"
                        for item in rows
                    ),
                    encoding="utf-8",
                )
                os.replace(temporary, path)
        return path
    if action in {"model_release", "complete_release"}:
        return suite_dir / "layer1_model" / "model_release_holdout.jsonl"
    if action == "rag_compare":
        return suite_dir / "layer2_rag" / "rag_retrieval_eval.jsonl"
    if action == "agent_ablation":
        return suite_dir / "layer3_agent" / "agent_ablation_eval.jsonl"
    if action == "production_reliability":
        return suite_dir / "layer4_e2e" / "end_to_end_challenge_eval.jsonl"
    raise ValueError(f"unsupported five-layer workflow: {action}")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def jobs_dir(data_dir: Path) -> Path:
    path = data_dir / "evaluation" / "five_layer_jobs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        process_query_limited_information = 0x1000
        still_active = 259
        handle = ctypes.windll.kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        try:
            return bool(
                ctypes.windll.kernel32.GetExitCodeProcess(
                    handle, ctypes.byref(exit_code)
                )
                and exit_code.value == still_active
            )
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def live_job_batch_progress(job: dict[str, Any]) -> dict[str, Any]:
    selected_ids = {
        str(value).upper()
        for value in ((job.get("batch_selection") or {}).get("selected_sample_ids") or [])
        if str(value).strip()
    }
    commands = list(job.get("commands") or [])
    results = list(job.get("results") or [])
    completed_executions = 0
    failed_executions = 0
    for index, command_item in enumerate(commands):
        args = list(command_item.get("args") or [])
        is_replay = "--replay-last-selection" in args
        if is_replay:
            if index < len(results):
                completed_executions += int(results[index].get("selected") or 0)
                failed_executions += int(results[index].get("failed") or 0)
            continue
        run_id = args[args.index("--run-id") + 1] if "--run-id" in args else ""
        output_root = (
            Path(args[args.index("--output-root") + 1])
            if "--output-root" in args
            else None
        )
        checkpoint = (
            read_json(output_root / run_id / "checkpoint.json", {})
            if output_root and run_id
            else {}
        )
        items = checkpoint.get("items") or {}
        completed_executions += sum(
            1
            for sample_id, item in items.items()
            if str(sample_id).upper() in selected_ids
            and isinstance(item, dict)
            and item.get("status") == "completed"
        )
        failed_executions += sum(
            1
            for sample_id, item in items.items()
            if str(sample_id).upper() in selected_ids
            and isinstance(item, dict)
            and item.get("status") == "failed"
        )
    planned = int(job.get("planned_executions") or 0)
    finished = min(planned, completed_executions + failed_executions)
    return {
        "planned_executions": planned,
        "completed_executions": completed_executions,
        "failed_executions": failed_executions,
        "finished_executions": finished,
        "remaining_executions": max(0, planned - finished),
        "percent": finished / planned if planned else 0.0,
    }


def load_jobs(data_dir: Path) -> list[dict[str, Any]]:
    directory = jobs_dir(data_dir)
    jobs = [
        payload
        for path in directory.glob("*.json")
        if isinstance((payload := read_json(path, {})), dict) and payload.get("job_id")
    ]
    jobs.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    changed = False
    for job in jobs:
        worker_pid = int(job.get("worker_pid") or 0)
        child_pid = int(job.get("active_child_pid") or 0)
        worker_alive = process_alive(worker_pid)
        child_alive = process_alive(child_pid)
        if job.get("status") == "failed" and (worker_alive or child_alive):
            job["status"] = "running"
            job["error"] = "已修正后台进程存活状态；任务仍在运行。"
            job["finished_at"] = None
            job["updated_at"] = now_iso()
            write_json(directory / f"{job['job_id']}.json", job)
            changed = True
            continue
        if job.get("status") in ACTIVE_STATUSES:
            if (worker_pid or child_pid) and not worker_alive and not child_alive:
                job["status"] = "failed"
                job["error"] = job.get("error") or "后台评测进程已退出，请查看日志后重新运行。"
                job["finished_at"] = job.get("finished_at") or now_iso()
                write_json(directory / f"{job['job_id']}.json", job)
                changed = True
    if changed:
        jobs.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return jobs


def workflow_overview(
    data_dir: Path | None = None, suite_id: str = ""
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    jobs = load_jobs(data_dir)
    for job in jobs:
        job["batch_progress"] = live_job_batch_progress(job)
    manifest = selected_five_layer_suite(suite_id, data_dir=data_dir)
    selected_suite_id = str(manifest.get("suite_id") or "")
    suite_jobs = [
        job
        for job in jobs
        if str(job.get("suite_id") or "") == selected_suite_id
    ]
    latest_by_action: dict[str, dict[str, Any]] = {}
    for job in suite_jobs:
        latest_by_action.setdefault(str(job.get("action")), job)
    catalog = json.loads(json.dumps(WORKFLOW_CATALOG, ensure_ascii=False))
    counts = manifest.get("dataset_counts") or {}
    release_count = int((manifest.get("selection") or {}).get("release_holdout_count") or 0)
    rag_count = int(((counts.get("layer2_rag") or {}).get("rag_retrieval_eval")) or 0)
    ablation_count = int(((counts.get("layer3_agent") or {}).get("agent_ablation_eval")) or 0)
    challenge_count = int(((counts.get("layer4_e2e") or {}).get("end_to_end_challenge_eval")) or 0)
    catalog["model_release"]["estimated_model_calls"] = release_count
    gold_count = workflow_dataset_total("gold_compare", manifest)
    catalog["gold_compare"]["estimated_model_calls"] = gold_count
    catalog["complete_release"]["estimated_model_calls"] = release_count
    catalog["rag_compare"]["estimated_model_calls"] = rag_count * 3
    catalog["agent_ablation"]["estimated_model_calls"] = ablation_count * 5
    catalog["production_reliability"]["estimated_model_calls"] = challenge_count
    for action, definition in catalog.items():
        total = workflow_dataset_total(action, manifest)
        definition["sample_total"] = total
        progress = workflow_cumulative_progress(
            action,
            manifest,
            data_dir,
        )
        remaining = int(progress.get("remaining_base_samples") or 0)
        definition["min_batch_size"] = 1 if remaining else 0
        definition["max_batch_size"] = remaining
        definition["default_batch_size"] = min(
            max(1, int(definition.get("default_batch_size") or 1)),
            max(1, remaining),
        )
        definition["batch_presets"] = sorted(
            {
                value
                for value in (1, 10, 20, 50, 100, remaining)
                if 0 < value <= remaining
            }
        )
        definition["progress"] = progress
    return {
        "generated_at": now_iso(),
        "selected_suite_id": selected_suite_id or None,
        "catalog": catalog,
        "active_job": next(
            (job for job in jobs if job.get("status") in ACTIVE_STATUSES),
            None,
        ),
        "latest_by_action": latest_by_action,
        "recent_jobs": suite_jobs[:20],
    }


def command(
    *,
    validation_csv: Path,
    output_root: Path,
    source_data_dir: Path,
    run_id: str,
    variant: str,
    sample_id_file: Path,
    isolation_sample_id_file: Path | None,
    limit: int,
    pending_only: bool = False,
    next_unfinished: bool = False,
    replay_last_selection: bool = False,
    disabled_agent: str = "",
) -> list[str]:
    args = [
        "--validation-csv",
        str(validation_csv),
        "run",
        "--variant",
        variant,
        "--run-id",
        run_id,
        "--output-root",
        str(output_root),
        "--source-data-dir",
        str(source_data_dir),
        "--sample-id-file",
        str(sample_id_file),
        "--limit",
        str(limit),
    ]
    if isolation_sample_id_file is not None:
        args.extend(["--isolation-sample-id-file", str(isolation_sample_id_file)])
    if pending_only:
        args.append("--pending-only")
    if next_unfinished:
        args.append("--next-unfinished")
    if replay_last_selection:
        args.append("--replay-last-selection")
    if disabled_agent:
        args.extend(["--disabled-agent", disabled_agent])
    return args


def build_commands(
    action: str,
    *,
    manifest: dict[str, Any],
    data_dir: Path,
    job_id: str,
    batch_size: int | None = None,
    batch_sample_file: Path | None = None,
) -> list[dict[str, Any]]:
    suite_dir = Path(str(manifest.get("suite_dir") or "")).resolve()
    validation_csv = Path(
        str(
            (manifest.get("workflow_validation_source") or {}).get("path")
            or (manifest.get("validation_source") or {}).get("path")
            or DEFAULT_VALIDATION_CSV
        )
    ).resolve()
    counts = manifest.get("dataset_counts") or {}
    release_limit = int((manifest.get("selection") or {}).get("release_holdout_count") or 0)
    rag_limit = int(((counts.get("layer2_rag") or {}).get("rag_retrieval_eval")) or 0)
    ablation_limit = int(((counts.get("layer3_agent") or {}).get("agent_ablation_eval")) or 0)
    challenge_limit = int(((counts.get("layer4_e2e") or {}).get("end_to_end_challenge_eval")) or 0)
    requested_batch_size = int(batch_size) if batch_size is not None else None

    def batch_limit(dataset_limit: int, *, maximum: int | None = None) -> int:
        upper = max(1, dataset_limit)
        if maximum is not None:
            upper = min(upper, max(1, maximum))
        return min(upper, max(1, requested_batch_size or upper))
    output_root = data_dir / "evaluation" / "five_layer_runs"
    suite_id = str(manifest.get("suite_id") or job_id)
    release_file = suite_dir / "layer1_model" / "model_release_holdout.jsonl"
    rag_file = suite_dir / "layer2_rag" / "rag_retrieval_eval.jsonl"
    ablation_file = suite_dir / "layer3_agent" / "agent_ablation_eval.jsonl"
    challenge_file = suite_dir / "layer4_e2e" / "end_to_end_challenge_eval.jsonl"
    release_isolation_file = release_file
    rag_isolation_file = rag_file
    ablation_isolation_file = ablation_file
    challenge_isolation_file = challenge_file
    required = [validation_csv, suite_dir]
    if action in {"model_release", "complete_release"}:
        required.append(release_file)
    elif action == "gold_compare":
        required.append(suite_dir / "layer1_model" / "expert_gold_holdout.jsonl")
    elif action == "rag_compare":
        required.append(rag_file)
    elif action == "agent_ablation":
        required.append(ablation_file)
    elif action == "production_reliability":
        required.append(challenge_file)
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError("缺少评测输入：" + "；".join(missing))
    if batch_sample_file is not None:
        if not batch_sample_file.exists():
            raise FileNotFoundError(f"缺少批次样本清单：{batch_sample_file}")
        release_file = rag_file = ablation_file = challenge_file = batch_sample_file

    def entry(name: str, args: list[str]) -> dict[str, Any]:
        return {"name": name, "args": args}

    if action == "gold_compare":
        gold_file = (
            batch_sample_file
            if batch_sample_file is not None
            else suite_dir / "layer1_model" / "expert_gold_holdout.jsonl"
        )
        gold_isolation_file = suite_dir / "layer1_model" / "expert_gold_holdout.jsonl"
        gold_limit = workflow_dataset_total(action, manifest)
        return [
            entry(
                "专家金标集",
                command(
                    validation_csv=validation_csv,
                    output_root=output_root,
                    source_data_dir=data_dir,
                    run_id=f"{suite_id}-gold-compare",
                    variant="full",
                    sample_id_file=gold_file,
                    isolation_sample_id_file=gold_isolation_file,
                    limit=batch_limit(gold_limit),
                    next_unfinished=True,
                ),
            )
        ]

    if action == "model_release":
        return [
            entry(
                "严格集完整双模型",
                command(
                    validation_csv=validation_csv,
                    output_root=output_root,
                    source_data_dir=data_dir,
                    run_id=f"{suite_id}-model-release",
                    variant="full",
                    sample_id_file=release_file,
                    isolation_sample_id_file=release_isolation_file,
                    limit=batch_limit(release_limit),
                    next_unfinished=True,
                ),
            )
        ]
    if action == "complete_release":
        return [
            entry(
                "严格集未完成样本",
                command(
                    validation_csv=validation_csv,
                    output_root=output_root,
                    source_data_dir=data_dir,
                    run_id=f"{suite_id}-model-release",
                    variant="full",
                    sample_id_file=release_file,
                    isolation_sample_id_file=release_isolation_file,
                    limit=batch_limit(release_limit),
                    pending_only=True,
                    next_unfinished=True,
                ),
            )
        ]
    if action == "rag_compare":
        return [
            entry(
                label,
                command(
                    validation_csv=validation_csv,
                    output_root=output_root,
                    source_data_dir=data_dir,
                    run_id=f"{suite_id}-{variant}",
                    variant=variant,
                    sample_id_file=rag_file,
                    isolation_sample_id_file=rag_isolation_file,
                    limit=batch_limit(rag_limit),
                    next_unfinished=True,
                ),
            )
            for variant, label in (
                ("rag_off", "无RAG"),
                ("rag_vector", "向量RAG"),
                ("rag_hybrid", "混合RAG"),
            )
        ]
    if action == "agent_ablation":
        variants = [("", "完整系统")]
        variants.extend(
            [
                ("static_analysis", "去静态分析Agent"),
                ("threat_intel", "去威胁情报Agent"),
                ("impersonation", "去仿冒研判Agent"),
                ("business_label", "去业务标签Agent"),
            ]
        )
        return [
            entry(
                label,
                command(
                    validation_csv=validation_csv,
                    output_root=output_root,
                    source_data_dir=data_dir,
                    run_id=f"{suite_id}-{'full' if not disabled else 'no-' + disabled}",
                    variant="full",
                    sample_id_file=ablation_file,
                    isolation_sample_id_file=ablation_isolation_file,
                    limit=batch_limit(ablation_limit),
                    next_unfinished=True,
                    disabled_agent=disabled,
                ),
            )
            for disabled, label in variants
        ]
    if action == "production_reliability":
        run_id = f"{suite_id}-fault-recovery"
        first_args = command(
            validation_csv=validation_csv,
            output_root=output_root,
            source_data_dir=data_dir,
            run_id=run_id,
            variant="fault_recovery",
            sample_id_file=challenge_file,
            isolation_sample_id_file=challenge_isolation_file,
            limit=batch_limit(challenge_limit),
            next_unfinished=True,
        )
        replay_args = command(
            validation_csv=validation_csv,
            output_root=output_root,
            source_data_dir=data_dir,
            run_id=run_id,
            variant="fault_recovery",
            sample_id_file=challenge_file,
            isolation_sample_id_file=challenge_isolation_file,
            limit=batch_limit(challenge_limit),
            replay_last_selection=True,
        )
        return [
            entry("瞬时故障恢复", first_args),
            entry("相同检查点幂等重放", replay_args),
        ]
    raise ValueError(f"unsupported five-layer workflow: {action}")


def worker_command(job_path: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--five-layer-worker", str(job_path)]
    return [
        sys.executable,
        "-m",
        "malapp.evaluation.workflows",
        "--worker",
        str(job_path),
    ]


def evaluation_command(args: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--five-layer-eval", *args]
    return [sys.executable, str(ROOT / "scripts" / "evaluation" / "run_evaluation.py"), *args]


def start_workflow(
    action: str,
    *,
    data_dir: Path | None = None,
    batch_size: int | None = None,
    suite_id: str = "",
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    if action not in WORKFLOW_CATALOG:
        raise ValueError(f"unsupported workflow: {action}")
    overview = workflow_overview(data_dir, suite_id=suite_id)
    active = overview.get("active_job")
    if active:
        raise RuntimeError(
            f"已有五层任务 {active.get('job_id')} 正在运行；请等待完成或先取消。"
        )
    manifest = selected_five_layer_suite(suite_id, data_dir=data_dir)
    if not manifest:
        raise RuntimeError("请先生成五层评测套件。")
    dataset_total = workflow_dataset_total(action, manifest)
    if dataset_total <= 0:
        raise RuntimeError("当前评测层没有可运行的样本，请重新生成五层评测套件。")
    if batch_size is not None and int(batch_size) <= 0:
        raise ValueError("本次运行样本数必须是大于0的整数。")
    selected_batch_size = min(
        dataset_total,
        max(
            1,
            int(
                batch_size
                if batch_size is not None
                else WORKFLOW_CATALOG[action].get("default_batch_size") or dataset_total
            ),
        ),
    )
    job_id = f"five-{action}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    suite_dir = Path(str(manifest.get("suite_dir") or "")).resolve()
    batch_selection = prepare_workflow_batch(
        action,
        manifest=manifest,
        data_dir=data_dir,
        source_file=workflow_sample_file(action, suite_dir),
        job_id=job_id,
        batch_size=selected_batch_size,
    )
    actual_batch_size = int(batch_selection.get("selected_count") or 0)
    if actual_batch_size <= 0:
        raise RuntimeError("本层没有未完成样本；累计结果已经覆盖当前可运行数据。")
    commands = build_commands(
        action,
        manifest=manifest,
        data_dir=data_dir,
        job_id=job_id,
        batch_size=actual_batch_size,
        batch_sample_file=Path(str(batch_selection["path"])),
    )
    directory = jobs_dir(data_dir)
    job_path = directory / f"{job_id}.json"
    job = {
        "job_id": job_id,
        "action": action,
        "layer": WORKFLOW_CATALOG[action]["layer"],
        "name": WORKFLOW_CATALOG[action]["name"],
        "status": "queued",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "suite_id": manifest.get("suite_id"),
        "suite_dir": manifest.get("suite_dir"),
        "dataset_total": dataset_total,
        "requested_batch_size": selected_batch_size,
        "batch_size": actual_batch_size,
        "batch_selection": batch_selection,
        "variant_count": int(WORKFLOW_CATALOG[action].get("variant_count") or 1),
        "planned_executions": actual_batch_size
        * int(WORKFLOW_CATALOG[action].get("variant_count") or 1),
        "data_dir": str(data_dir),
        "commands": commands,
        "command_total": len(commands),
        "command_completed": 0,
        "current_command": "",
        "results": [],
        "log_file": str(directory / f"{job_id}.log"),
    }
    write_json(job_path, job)
    log_handle = Path(job["log_file"]).open("a", encoding="utf-8")
    creationflags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    )
    try:
        process = subprocess.Popen(
            worker_command(job_path),
            cwd=str(ROOT),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )
    finally:
        log_handle.close()
    current = read_json(job_path, job)
    current["status"] = (
        current.get("status")
        if current.get("status") in TERMINAL_STATUSES
        else "running"
    )
    current["worker_pid"] = process.pid
    current["started_at"] = current.get("started_at") or now_iso()
    current["updated_at"] = now_iso()
    write_json(job_path, current)
    return current


def cancel_workflow(
    job_id: str,
    *,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    job_path = jobs_dir(data_dir) / f"{job_id}.json"
    job = read_json(job_path, {})
    if not job:
        raise FileNotFoundError(f"workflow not found: {job_id}")
    process_is_active = process_alive(
        int(job.get("worker_pid") or job.get("active_child_pid") or 0)
    ) or process_alive(int(job.get("active_child_pid") or 0))
    if job.get("status") in TERMINAL_STATUSES and not process_is_active:
        return job
    job["status"] = "cancelling"
    job["updated_at"] = now_iso()
    write_json(job_path, job)
    # Terminate the worker process tree so its child cannot overwrite "cancelled"
    # with a synthetic failure after taskkill returns.
    pid = int(job.get("worker_pid") or job.get("active_child_pid") or 0)
    if pid > 0:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
        else:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
    job["status"] = "cancelled"
    job["finished_at"] = now_iso()
    job["updated_at"] = now_iso()
    write_json(job_path, job)
    return job


def worker_main(job_path: Path) -> int:
    job_path = job_path.resolve()
    job = read_json(job_path, {})
    if not job:
        return 2
    job["status"] = "running"
    job["worker_pid"] = os.getpid()
    job["updated_at"] = now_iso()
    write_json(job_path, job)
    creationflags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    )
    try:
        for index, item in enumerate(job.get("commands") or []):
            latest = read_json(job_path, job)
            if latest.get("status") == "cancelling":
                latest["status"] = "cancelled"
                latest["finished_at"] = now_iso()
                write_json(job_path, latest)
                return 3
            job = latest
            job["current_command"] = item.get("name")
            job["updated_at"] = now_iso()
            write_json(job_path, job)
            process = subprocess.Popen(
                evaluation_command(list(item.get("args") or [])),
                cwd=str(ROOT),
                creationflags=creationflags,
            )
            job["active_child_pid"] = process.pid
            write_json(job_path, job)
            return_code = process.wait()
            cancellation = read_json(job_path, job)
            if cancellation.get("status") in {"cancelling", "cancelled"}:
                cancellation["status"] = "cancelled"
                cancellation["active_child_pid"] = None
                cancellation["finished_at"] = cancellation.get("finished_at") or now_iso()
                cancellation["updated_at"] = now_iso()
                write_json(job_path, cancellation)
                return 3
            args = list(item.get("args") or [])
            run_id = args[args.index("--run-id") + 1] if "--run-id" in args else ""
            output_root = (
                Path(args[args.index("--output-root") + 1])
                if "--output-root" in args
                else None
            )
            run_result = (
                read_json(output_root / run_id / "result.json", {})
                if output_root and run_id
                else {}
            )
            result = {
                "name": item.get("name"),
                "return_code": return_code,
                "run_id": run_id,
                "run_status": run_result.get("status"),
                "selected": int(run_result.get("selected_this_invocation") or 0),
                "completed": int(run_result.get("completed_this_invocation") or 0),
                "failed": int(run_result.get("failed_this_invocation") or 0),
                "skipped_completed": int(run_result.get("skipped_completed") or 0),
                "cumulative_completed": int(run_result.get("cumulative_completed") or 0),
                "cumulative_failed": int(run_result.get("cumulative_failed") or 0),
                "remaining": int(run_result.get("remaining_candidates") or 0),
                "finished_at": now_iso(),
            }
            job = read_json(job_path, job)
            job.setdefault("results", []).append(result)
            job["active_child_pid"] = None
            job["command_completed"] = index + 1
            job["updated_at"] = now_iso()
            write_json(job_path, job)
            if return_code != 0 or result["failed"] or result["run_status"] == "failed":
                raise RuntimeError(
                    f"子实验 {item.get('name')} 失败，退出码 {return_code}，"
                    f"样本失败 {result['failed']} 条"
                )
        job["status"] = "completed"
        job.pop("error", None)
        job["current_command"] = ""
        job["finished_at"] = now_iso()
        job["updated_at"] = now_iso()
        write_json(job_path, job)
        return 0
    except Exception as exc:
        job = read_json(job_path, job)
        job["status"] = "failed"
        job["error"] = f"{type(exc).__name__}: {exc}"
        job["finished_at"] = now_iso()
        job["updated_at"] = now_iso()
        write_json(job_path, job)
        return 1


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        raise SystemExit(worker_main(Path(sys.argv[2])))
    raise SystemExit("usage: python -m malapp.evaluation.workflows --worker <job.json>")


if __name__ == "__main__":
    main()
