from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status

from apps.server.auth import require_admin, require_authenticated, server_config
from apps.server.limits import bounded_int, payload_object
from malapp.application.dashboard import import_feature_records
from malapp.data_import.excel import excel_preview, import_excel
from malapp.data_import.preprocess import (
    list_import_batches,
    load_feature_context,
    next_tasks,
    preprocess_stats,
    pull_conflict_samples,
    save_feature_record,
    task_status_summary,
)
from malapp.evaluation.validation import get_validation_sample, list_validation_items
from malapp.storage.engine_store import build_sample_by_md5, engine_stats, search_engine_records
from training.datasets.export import export_all_datasets

router = APIRouter(dependencies=[Depends(require_authenticated)])


def _query_limit(request: Request, value: Any, default: int) -> int:
    return bounded_int(
        value,
        name="limit",
        default=default,
        maximum=server_config(request).max_query_limit,
    )


@router.get("/api/engine/stats")
def get_engine_stats() -> dict[str, Any]:
    return engine_stats()


@router.get("/api/engine/samples")
def engine_samples(request: Request, limit: int = Query(50), conflict_only: bool = False) -> dict[str, Any]:
    return {
        "items": search_engine_records(
            limit=_query_limit(request, limit, 50),
            conflict_only=conflict_only,
        )
    }


@router.get("/api/engine/sample")
def engine_sample(md5: str = "") -> dict[str, Any]:
    if not md5:
        raise ValueError("md5 is required")
    return build_sample_by_md5(md5)


@router.get("/api/preprocess/stats")
def get_preprocess_stats() -> dict[str, Any]:
    return preprocess_stats()


@router.get("/api/tasks/next", dependencies=[Depends(require_admin)])
def tasks_next(request: Request, limit: int = Query(20)) -> dict[str, Any]:
    return {"items": next_tasks(limit=_query_limit(request, limit, 20))}


@router.get("/api/tasks/summary")
def tasks_summary() -> dict[str, Any]:
    return task_status_summary()


@router.get("/api/batches")
def batches(request: Request, limit: int = Query(30)) -> dict[str, Any]:
    return {"items": list_import_batches(limit=_query_limit(request, limit, 30))}


@router.get("/api/features/sample")
def feature_sample(md5: str = "") -> dict[str, Any]:
    if not md5:
        raise ValueError("md5 is required")
    return load_feature_context(md5)


@router.get("/api/validation/items")
def validation_items(
    request: Request,
    limit: int = Query(200),
    offset: int = Query(0, ge=0),
    label: str = "",
    result: str = "",
    q: str = "",
    judged: bool = False,
    pending: bool = False,
    order: str = "",
) -> dict[str, Any]:
    return list_validation_items(
        limit=_query_limit(request, limit, 200),
        offset=offset,
        label=label,
        result=result,
        query=q,
        judged=judged,
        pending=pending,
        order=order,
    )


@router.get("/api/validation/sample")
def validation_sample(md5: str = "") -> dict[str, Any]:
    try:
        return get_validation_sample(md5)
    except Exception as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post(
    "/api/preprocess/ingest",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def preprocess_ingest(
    payload: Any = Body(default_factory=dict),
    format: str = "json",
    source: str = "api_gateway",
) -> dict[str, Any]:
    return save_feature_record(payload, source=source, payload_format=format)


@router.post(
    "/api/data/import",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def data_import(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    if isinstance(payload, list):
        items = payload
        source = "manual_upload"
        payload_format = "json"
    else:
        item = payload_object(payload)
        items = item.get("items", [])
        source = str(item.get("source") or "manual_upload")
        payload_format = str(item.get("format") or "json")
    if not isinstance(items, list):
        raise ValueError("items must be an array")
    if len(items) > server_config(request).max_batch_items:
        raise ValueError("items exceeds MALAPP_MAX_BATCH_ITEMS")
    return import_feature_records(items, source=source, payload_format=payload_format)


@router.post("/api/data/excel-preview", dependencies=[Depends(require_admin)])
async def data_excel_preview(request: Request, sheet: str = "", header_row: int = Query(1, ge=1)) -> dict[str, Any]:
    return excel_preview(await request.body(), sheet_name=sheet, header_row=header_row)


@router.post(
    "/api/data/import-excel",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
async def data_import_excel(
    request: Request,
    sheet: str = "",
    header_row: int = Query(1, ge=1),
    start_row: int = Query(2, ge=1),
    limit: int = Query(100),
    source: str = "excel_upload",
) -> dict[str, Any]:
    row_limit = bounded_int(
        limit,
        name="limit",
        default=100,
        maximum=server_config(request).max_excel_rows,
    )
    return import_excel(
        await request.body(),
        sheet_name=sheet,
        header_row=header_row,
        start_row=start_row,
        limit=row_limit,
        source=source,
    )


@router.post(
    "/api/preprocess/pull-conflicts",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def preprocess_pull_conflicts(request: Request, limit: int = Query(1000)) -> dict[str, Any]:
    return pull_conflict_samples(
        limit=bounded_int(
            limit,
            name="limit",
            default=1000,
            maximum=server_config(request).max_batch_items,
        )
    )


@router.post(
    "/api/datasets/export",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def datasets_export(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    limit = bounded_int(
        item.get("limit"),
        name="limit",
        default=5000,
        maximum=server_config(request).max_excel_rows,
    )
    return export_all_datasets(
        output_dir=str(item.get("output_dir") or "") or None,
        limit=limit,
    )
