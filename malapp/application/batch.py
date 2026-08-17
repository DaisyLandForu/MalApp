from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from malapp.application.judgement import judge
from malapp.data_import import preprocess
from malapp.data_import.preprocess import (
    batch_pending_md5s,
    init_preprocess_tables,
    load_feature_context,
    update_batch_item_status,
    update_task_status,
)
from malapp.inference.settings import ensure_runtime_ready_for_judgement

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
CONTROLS: dict[str, threading.Event] = {}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def recover_interrupted_jobs() -> int:
    init_preprocess_tables()
    now = utc_now()
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT job_id FROM batch_jobs WHERE status IN ('running', 'pausing')"
        ).fetchall()
        job_ids = [row[0] for row in rows]
        if job_ids:
            placeholders = ",".join("?" for _ in job_ids)
            conn.execute(
                f"UPDATE batch_jobs SET status='paused', current_md5='', updated_at=? "
                f"WHERE job_id IN ({placeholders})",
                (now, *job_ids),
            )
            conn.execute(
                f"UPDATE batch_job_items SET status='pending' "
                f"WHERE job_id IN ({placeholders}) AND status='processing'",
                tuple(job_ids),
            )
            conn.execute(
                "UPDATE sample_tasks SET status='pending', updated_at=? WHERE status='processing'",
                (now,),
            )
            conn.execute(
                "UPDATE batch_items SET status='pending', updated_at=? WHERE status='processing'",
                (now,),
            )
            conn.commit()
    return len(job_ids)


def start_batch_judgement(batch_id: str, limit: int) -> dict[str, Any]:
    limit = max(1, min(int(limit), 1000))
    md5s = batch_pending_md5s(batch_id, limit)
    if not md5s:
        raise ValueError("该批次没有待研判样本")
    ensure_runtime_ready_for_judgement()
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    job = create_job_record(job_id, batch_id, limit, md5s)
    with JOBS_LOCK:
        JOBS[job_id] = job
        CONTROLS[job_id] = threading.Event()
    launch_worker(job_id)
    return dict(job)


def retry_failed_batch_judgement(job_id: str, limit: int | None = None) -> dict[str, Any]:
    source_job = get_batch_job(job_id)
    retry_limit = max(1, min(int(limit), 1000)) if limit is not None else None
    md5s = failed_job_md5s(job_id, retry_limit)
    if not md5s:
        raise ValueError("当前任务没有失败样本可重新研判")
    ensure_runtime_ready_for_judgement()
    retry_job_id = f"retry-{uuid.uuid4().hex[:12]}"
    job = create_job_record(retry_job_id, source_job["batch_id"], len(md5s), md5s)
    for md5 in md5s:
        update_task_status(md5, "pending")
        update_batch_item_status(source_job["batch_id"], md5, "pending")
    with JOBS_LOCK:
        JOBS[retry_job_id] = job
        CONTROLS[retry_job_id] = threading.Event()
    launch_worker(retry_job_id)
    return dict(job)


def create_job_record(job_id: str, batch_id: str, requested: int, md5s: list[str]) -> dict[str, Any]:
    now = utc_now()
    job = {
        "job_id": job_id,
        "batch_id": batch_id,
        "requested": requested,
        "total": len(md5s),
        "processed": 0,
        "succeeded": 0,
        "failed": 0,
        "status": "running",
        "current_md5": "",
        "results": [],
        "errors": [],
        "created_at": now,
        "updated_at": now,
        "finished_at": "",
    }
    init_preprocess_tables()
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO batch_jobs
            (job_id, batch_id, requested, total, processed, succeeded, failed, status,
             current_md5, results_json, errors_json, created_at, updated_at, finished_at)
            VALUES (?, ?, ?, ?, 0, 0, 0, 'running', '', '[]', '[]', ?, ?, '')
            """,
            (job_id, batch_id, requested, len(md5s), now, now),
        )
        conn.executemany(
            "INSERT INTO batch_job_items (job_id, md5, sequence_no, status) VALUES (?, ?, ?, 'pending')",
            [(job_id, md5, index) for index, md5 in enumerate(md5s)],
        )
        conn.commit()
    return job


def pause_batch_judgement(job_id: str) -> dict[str, Any]:
    job = get_batch_job(job_id)
    if job["status"] in {"completed", "paused"}:
        return job
    control = CONTROLS.setdefault(job_id, threading.Event())
    control.set()
    _patch_job(job_id, status="pausing")
    return get_batch_job(job_id)


def resume_batch_judgement(job_id: str) -> dict[str, Any]:
    job = get_batch_job(job_id)
    if job["status"] == "completed":
        return job
    if job["status"] not in {"paused", "pausing", "failed"}:
        raise ValueError("当前任务不需要继续")
    CONTROLS.setdefault(job_id, threading.Event()).clear()
    _patch_job(job_id, status="running", finished_at="")
    launch_worker(job_id)
    return get_batch_job(job_id)


def get_batch_job(job_id: str) -> dict[str, Any]:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job:
        return dict(job)
    init_preprocess_tables()
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM batch_jobs WHERE job_id = ?", (job_id,)).fetchone()
    if not row:
        raise ValueError("批量研判任务不存在")
    job = row_to_job(row)
    with JOBS_LOCK:
        JOBS[job_id] = job
        CONTROLS.setdefault(job_id, threading.Event())
    return dict(job)


def launch_worker(job_id: str) -> None:
    threading.Thread(
        target=_run_job,
        args=(job_id,),
        daemon=True,
        name=f"batch-{job_id}",
    ).start()


def batch_judge_workers() -> int:
    try:
        configured = int(os.getenv("MALAPP_BATCH_JUDGE_WORKERS", "1"))
    except ValueError:
        configured = 1
    return max(1, min(configured, 4))


def _run_job(job_id: str) -> None:
    control = CONTROLS.setdefault(job_id, threading.Event())
    batch_id = str(get_batch_job(job_id).get("batch_id", ""))
    workers = batch_judge_workers()
    pending = pending_job_md5s(job_id)
    for start in range(0, len(pending), workers):
        if control.is_set():
            _patch_job(job_id, status="paused", current_md5="")
            return
        chunk = pending[start : start + workers]
        _patch_job(job_id, current_md5=",".join(chunk), status="running")
        if workers == 1:
            for md5 in chunk:
                set_job_item_status(job_id, md5, "processing")
                update_task_status(md5, "processing")
                update_batch_item_status(batch_id, md5, "processing")
                _record_job_item_result(job_id, _judge_job_item(job_id, md5))
            continue
        with ThreadPoolExecutor(max_workers=len(chunk), thread_name_prefix=f"judge-{job_id}") as pool:
            futures = []
            for md5 in chunk:
                set_job_item_status(job_id, md5, "processing")
                update_task_status(md5, "processing")
                update_batch_item_status(batch_id, md5, "processing")
                futures.append(pool.submit(_judge_job_item, job_id, md5))
            for future in as_completed(futures):
                _record_job_item_result(job_id, future.result())
    _patch_job(job_id, status="completed", current_md5="", finished_at=utc_now())


def _judge_job_item(job_id: str, md5: str) -> dict[str, Any]:
    max_attempts = batch_item_max_attempts()
    try:
        sample = load_feature_context(md5)
    except Exception as exc:
        error = str(exc)
        return {
            "ok": False,
            "md5": md5,
            "error": error,
            "category": classify_judgement_failure(error),
            "attempts": 1,
        }
    last_error = ""
    category = "unknown"
    for attempt in range(1, max_attempts + 1):
        try:
            report = judge(sample)
            return {
                "ok": True,
                "md5": md5,
                "attempts": attempt,
                "result": {
                    "md5": md5,
                    "report_id": report.get("report_id"),
                    "verdict": report.get("decision", {}).get("verdict"),
                    "risk_level": report.get("decision", {}).get("risk_level"),
                    "final_score": report.get("decision", {}).get("final_score"),
                    "attempts": attempt,
                    "history_reused": bool(
                        report.get("execution", {}).get("history_reused")
                        or report.get("cache_hit")
                    ),
                    "orchestrator": report.get("execution", {}).get("orchestrator", ""),
                },
            }
        except Exception as exc:
            last_error = str(exc)
            category = classify_judgement_failure(last_error)
            if attempt >= max_attempts or not retryable_judgement_failure(category):
                break
            time.sleep(batch_retry_delay_seconds() * attempt)
    return {
        "ok": False,
        "md5": md5,
        "error": last_error,
        "category": category,
        "attempts": attempt,
    }


def batch_item_max_attempts() -> int:
    try:
        configured = int(os.getenv("MALAPP_BATCH_ITEM_MAX_ATTEMPTS", "2") or "2")
    except ValueError:
        configured = 2
    return max(1, min(configured, 3))


def batch_retry_delay_seconds() -> float:
    try:
        configured = float(os.getenv("MALAPP_BATCH_RETRY_DELAY_SECONDS", "1.0") or "1.0")
    except ValueError:
        configured = 1.0
    return max(0.0, min(configured, 10.0))


def classify_judgement_failure(error: str) -> str:
    text = str(error or "").lower()
    if "schema" in text or "合法 json" in text or "输出无效" in text:
        return "schema"
    if "timeout" in text or "timed out" in text or "超时" in text or "10060" in text:
        return "timeout"
    if any(token in text for token in ("connection", "remote end closed", "url error", "断开", "连接")):
        return "connection"
    if any(token in text for token in ("429", "502", "503", "504", "service unavailable")):
        return "service"
    if any(token in text for token in ("missing md5", "not found", "数据缺失", "找不到")):
        return "data"
    return "unknown"


def retryable_judgement_failure(category: str) -> bool:
    return category in {"schema", "timeout", "connection", "service", "unknown"}


def _record_job_item_result(job_id: str, outcome: dict[str, Any]) -> None:
    md5 = outcome["md5"]
    batch_id = str(get_batch_job(job_id).get("batch_id", ""))
    if outcome.get("ok"):
        update_task_status(md5, "completed")
        update_batch_item_status(batch_id, md5, "completed")
        set_job_item_status(job_id, md5, "completed")
        _append_result(job_id, outcome["result"])
    else:
        update_task_status(md5, "failed")
        update_batch_item_status(batch_id, md5, "failed")
        set_job_item_status(job_id, md5, "failed")
        _append_error(
            job_id,
            {
                "md5": md5,
                "error": outcome.get("error", ""),
                "category": outcome.get("category", "unknown"),
                "attempts": outcome.get("attempts", 1),
            },
        )


def pending_job_md5s(job_id: str) -> list[str]:
    init_preprocess_tables()
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        rows = conn.execute(
            """
            SELECT md5 FROM batch_job_items
            WHERE job_id = ? AND status IN ('pending', 'processing')
            ORDER BY sequence_no
            """,
            (job_id,),
        ).fetchall()
    return [row[0] for row in rows]


def failed_job_md5s(job_id: str, limit: int | None = None) -> list[str]:
    init_preprocess_tables()
    sql = """
        SELECT md5 FROM batch_job_items
        WHERE job_id = ? AND status = 'failed'
        ORDER BY sequence_no
    """
    params: tuple[Any, ...] = (job_id,)
    if limit is not None:
        sql += " LIMIT ?"
        params = (job_id, max(1, int(limit)))
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [row[0] for row in rows]


def set_job_item_status(job_id: str, md5: str, status: str) -> None:
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        conn.execute(
            "UPDATE batch_job_items SET status = ? WHERE job_id = ? AND md5 = ?",
            (status, job_id, md5),
        )
        conn.commit()


def _patch_job(job_id: str, **values: Any) -> None:
    with JOBS_LOCK:
        existing = JOBS.get(job_id)
    job = existing or get_batch_job(job_id)
    with JOBS_LOCK:
        job.update(values)
        job["updated_at"] = utc_now()
        JOBS[job_id] = job
        persist_job(job)


def _append_result(job_id: str, result: dict[str, Any]) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["processed"] += 1
        job["succeeded"] += 1
        job["results"].append(result)
        job["updated_at"] = utc_now()
        persist_job(job)


def _append_error(job_id: str, error: dict[str, Any]) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["processed"] += 1
        job["failed"] += 1
        job["errors"].append(error)
        job["updated_at"] = utc_now()
        persist_job(job)


def persist_job(job: dict[str, Any]) -> None:
    with closing(sqlite3.connect(preprocess.DB_PATH)) as conn:
        conn.execute(
            """
            UPDATE batch_jobs SET processed=?, succeeded=?, failed=?, status=?,
                current_md5=?, results_json=?, errors_json=?, updated_at=?, finished_at=?
            WHERE job_id=?
            """,
            (
                job["processed"],
                job["succeeded"],
                job["failed"],
                job["status"],
                job.get("current_md5", ""),
                json.dumps(job.get("results", []), ensure_ascii=False),
                json.dumps(job.get("errors", []), ensure_ascii=False),
                job["updated_at"],
                job.get("finished_at", ""),
                job["job_id"],
            ),
        )
        conn.commit()


def row_to_job(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "job_id": row["job_id"],
        "batch_id": row["batch_id"],
        "requested": row["requested"],
        "total": row["total"],
        "processed": row["processed"],
        "succeeded": row["succeeded"],
        "failed": row["failed"],
        "status": row["status"],
        "current_md5": row["current_md5"],
        "results": json.loads(row["results_json"]),
        "errors": json.loads(row["errors_json"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "finished_at": row["finished_at"],
    }
