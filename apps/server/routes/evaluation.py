from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request, status

from apps.server.auth import require_admin, server_config
from apps.server.limits import bounded_int, payload_object
from malapp.application.judgement import DATA_DIR
from malapp.evaluation.five_layer import (
    five_layer_overview,
    generate_five_layer_suite,
    list_rag_annotations,
    save_rag_annotation,
)
from malapp.evaluation.framework import (
    build_scorecard,
    evaluation_overview,
    freeze_evaluation_manifest,
    generate_evaluation_datasets,
)
from malapp.evaluation.gold_expansion import (
    freeze_gold_expansion,
    gold_expansion_overview,
    prepare_gold_expansion,
    save_gold_review,
)
from malapp.evaluation.workflows import cancel_workflow, start_workflow, workflow_overview

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/api/evaluation/overview")
def get_evaluation_overview() -> dict[str, Any]:
    return evaluation_overview()


@router.get("/api/evaluation/scorecard")
def scorecard() -> dict[str, Any]:
    return build_scorecard()


@router.get("/api/evaluation/five-layer")
def five_layer(suite_id: str = "") -> dict[str, Any]:
    return five_layer_overview(data_dir=DATA_DIR, suite_id=suite_id)


@router.get("/api/evaluation/five-layer/workflows")
def workflows(suite_id: str = "") -> dict[str, Any]:
    return workflow_overview(DATA_DIR, suite_id=suite_id)


@router.get("/api/evaluation/five-layer/gold-expansion")
def gold_expansion(
    request: Request,
    target: int | None = None,
    reviewer: str = "",
    role: str = "review",
    limit: int = Query(20),
) -> dict[str, Any]:
    config = server_config(request)
    return gold_expansion_overview(
        data_dir=DATA_DIR,
        target_total=target,
        reviewer=reviewer,
        role=role,
        limit=bounded_int(limit, name="limit", default=20, maximum=config.max_query_limit),
    )


@router.get("/api/evaluation/five-layer/rag-annotations")
def rag_annotations(
    request: Request,
    annotation_status: str = Query("pending", alias="status"),
    limit: int = Query(20),
) -> dict[str, Any]:
    return list_rag_annotations(
        data_dir=DATA_DIR,
        status=annotation_status,
        limit=bounded_int(
            limit,
            name="limit",
            default=20,
            maximum=server_config(request).max_query_limit,
        ),
    )


@router.post("/api/evaluation/freeze", status_code=status.HTTP_201_CREATED)
def freeze_evaluation(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    return freeze_evaluation_manifest(name=str(item.get("name") or "v1"))


@router.post("/api/evaluation/datasets", status_code=status.HTTP_201_CREATED)
def generate_datasets(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    maximum = server_config(request).max_excel_rows
    return generate_evaluation_datasets(
        core_size=bounded_int(item.get("core_size"), name="core_size", default=500, maximum=maximum),
        challenge_size=bounded_int(
            item.get("challenge_size"),
            name="challenge_size",
            default=300,
            maximum=maximum,
        ),
        rag_size=bounded_int(item.get("rag_size"), name="rag_size", default=200, maximum=maximum),
    )


@router.post("/api/evaluation/five-layer/generate", status_code=status.HTTP_201_CREATED)
def generate_five_layer(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    maximum = server_config(request).max_excel_rows

    def size(name: str, default: int) -> int:
        return bounded_int(item.get(name), name=name, default=default, maximum=maximum)

    return generate_five_layer_suite(
        name=str(item.get("name") or "v1"),
        data_dir=DATA_DIR,
        model_size=size("model_size", 500),
        rag_size=size("rag_size", 200),
        agent_size=size("agent_size", 500),
        challenge_size=size("challenge_size", 300),
        fresh_candidate_size=size("fresh_candidate_size", 1000),
    )


@router.post("/api/evaluation/five-layer/workflows/start", status_code=status.HTTP_201_CREATED)
def start_evaluation_workflow(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    raw_batch_size = item.get("batch_size")
    batch_size = (
        bounded_int(
            raw_batch_size,
            name="batch_size",
            default=1,
            maximum=server_config(request).max_batch_items,
        )
        if raw_batch_size not in (None, "")
        else None
    )
    return start_workflow(
        str(item.get("action") or "").strip(),
        data_dir=DATA_DIR,
        suite_id=str(item.get("suite_id") or "").strip(),
        batch_size=batch_size,
    )


@router.post("/api/evaluation/five-layer/workflows/cancel")
def cancel_evaluation_workflow(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    return cancel_workflow(str(item.get("job_id") or "").strip(), data_dir=DATA_DIR)


@router.post("/api/evaluation/five-layer/gold-expansion/prepare", status_code=status.HTTP_201_CREATED)
def prepare_gold(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    target_total = bounded_int(
        item.get("target_total"),
        name="target_total",
        default=500,
        maximum=server_config(request).max_excel_rows,
    )
    return prepare_gold_expansion(target_total=target_total, data_dir=DATA_DIR)


@router.post("/api/evaluation/five-layer/gold-expansion/review", status_code=status.HTTP_201_CREATED)
def review_gold(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    return save_gold_review(
        sample_id=str(item.get("sample_id") or ""),
        reviewer=str(item.get("reviewer") or ""),
        label=str(item.get("label") or ""),
        notes=str(item.get("notes") or ""),
        role=str(item.get("role") or "review"),
        data_dir=DATA_DIR,
    )


@router.post("/api/evaluation/five-layer/gold-expansion/freeze", status_code=status.HTTP_201_CREATED)
def freeze_gold(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    target_total = bounded_int(
        item.get("target_total"),
        name="target_total",
        default=500,
        maximum=server_config(request).max_excel_rows,
    )
    return freeze_gold_expansion(
        target_total=target_total,
        name=str(item.get("name") or ""),
        data_dir=DATA_DIR,
    )


@router.post("/api/evaluation/five-layer/rag-annotations", status_code=status.HTTP_201_CREATED)
def save_annotation(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    relevant = [str(value) for value in item.get("relevant_doc_ids") or []]
    hard_negatives = [str(value) for value in item.get("hard_negative_doc_ids") or []]
    maximum = server_config(request).max_query_limit
    if len(relevant) > maximum or len(hard_negatives) > maximum:
        raise ValueError("annotation document ids exceed MALAPP_MAX_QUERY_LIMIT")
    return save_rag_annotation(
        sample_id=str(item.get("sample_id") or ""),
        relevant_doc_ids=relevant,
        hard_negative_doc_ids=hard_negatives,
        annotation_status=str(item.get("annotation_status") or "needs_expert_review"),
        reviewer=str(item.get("reviewer") or ""),
        review_notes=str(item.get("review_notes") or ""),
        no_relevant_document=bool(item.get("no_relevant_document")),
        evidence_supported=(
            item.get("evidence_supported") if isinstance(item.get("evidence_supported"), bool) else None
        ),
        hallucination=item.get("hallucination") if isinstance(item.get("hallucination"), bool) else None,
        wrong_evidence=bool(item.get("wrong_evidence")),
        missing_evidence=bool(item.get("missing_evidence")),
        data_dir=DATA_DIR,
    )
