from __future__ import annotations

import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from integrations.hermes.runtime import hermes_status
from malapp.agents.business_label import analyze_business_label
from malapp.agents.impersonation import analyze_impersonation, load_asset_library, update_asset_library
from malapp.agents.static_features import analyze_apk_from_sample, public_static_feedback
from malapp.agents.threat_intelligence import analyze_threat_intelligence
from malapp.application.batch import (
    get_batch_job,
    pause_batch_judgement,
    recover_interrupted_jobs,
    resume_batch_judgement,
    retry_failed_batch_judgement,
    start_batch_judgement,
)
from malapp.application.dashboard import dashboard_overview, import_feature_records
from malapp.application.judgement import DATA_DIR, ROOT, init_db, judge, list_reports, load_json
from malapp.config.paths import initialize_runtime_files
from malapp.data_import.excel import excel_preview, import_excel
from malapp.data_import.preprocess import (
    list_import_batches,
    load_feature_context,
    next_tasks,
    preprocess_stats,
    pull_conflict_samples,
    reset_runtime_state,
    save_feature_record,
    task_status_summary,
)
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
from malapp.evaluation.validation import get_validation_sample, list_validation_items
from malapp.evaluation.workflows import (
    cancel_workflow,
    start_workflow,
    workflow_overview,
)
from malapp.inference.settings import load_model_settings, model_runtime_status, update_model_settings
from malapp.observability.rewards import get_reward, list_rewards
from malapp.observability.trace import get_trace, list_human_reviews, list_traces, save_human_review
from malapp.orchestration.decision import load_decision_params, update_decision_params
from malapp.rag import (
    hybrid_search as rag_hybrid_search,
)
from malapp.rag import (
    rag_context_for_sample,
    rag_status,
    rebuild_graph_index,
)
from malapp.rag import (
    search as rag_search,
)
from malapp.rag import (
    search_graph as rag_search_graph,
)
from malapp.storage.engine_store import build_sample_by_md5, engine_stats, search_engine_records
from malapp.version import APP_VERSION, BUILD_DATE
from training.datasets.export import export_all_datasets

WEB_DIR = ROOT / "apps" / "web"


class Handler(BaseHTTPRequestHandler):
    """Local HTTP handler.

    This file is the MVP entrypoint. It serves both the browser UI under `/`
    and JSON APIs under `/api/...`.
    """

    server_version = f"MalAppMVP/{APP_VERSION}"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        # Basic service check used by the browser and by manual debugging.
        if parsed.path == "/api/health":
            self.send_json(
                {
                    "status": "ok",
                    "service": "malicious-app-judgement-mvp",
                    "version": APP_VERSION,
                    "build_date": BUILD_DATE,
                    "profile": os.getenv("MALAPP_PROFILE", "demo"),
                    "data_dir": str(DATA_DIR),
                }
            )
            return
        if parsed.path == "/api/model/settings":
            self.send_json(model_runtime_status(check_remote=False))
            return
        if parsed.path == "/api/xgb/status":
            try:
                from malapp.inference.xgboost import runtime_status

                self.send_json(runtime_status())
            except Exception as exc:
                self.send_json(
                    {"ready": False, "error": f"{type(exc).__name__}: {exc}"},
                    status=500,
                )
            return
        if parsed.path == "/api/rag/status":
            self.send_json(rag_status())
            return
        if parsed.path == "/api/hermes/status":
            self.send_json(hermes_status())
            return

        # Static schema and demo sample for the input editor.
        if parsed.path == "/api/schema":
            self.send_json(load_json(DATA_DIR / "schema.json"))
            return
        if parsed.path == "/api/sample":
            self.send_json(load_json(DATA_DIR / "sample_conflict.json"))
            return

        # Historical reports already written to SQLite.
        if parsed.path == "/api/reports":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["50"])[0])
            self.send_json({"items": list_reports(limit=limit)})
            return
        if parsed.path == "/api/agent-traces":
            query = parse_qs(parsed.query)
            self.send_json({"items": list_traces(limit=int(query.get("limit", ["100"])[0]))})
            return
        if parsed.path == "/api/agent-trace":
            query = parse_qs(parsed.query)
            trace = get_trace(
                report_id=query.get("report_id", [""])[0],
                trace_id=query.get("trace_id", [""])[0],
            )
            if not trace:
                self.send_json({"error": "trace not found"}, status=404)
                return
            self.send_json(trace)
            return
        if parsed.path == "/api/human-reviews":
            query = parse_qs(parsed.query)
            self.send_json({"items": list_human_reviews(limit=int(query.get("limit", ["200"])[0]))})
            return
        if parsed.path == "/api/rewards":
            query = parse_qs(parsed.query)
            report_id = query.get("report_id", [""])[0]
            if report_id:
                self.send_json(get_reward(report_id) or {"error": "reward not found"})
            else:
                self.send_json({"items": list_rewards(limit=int(query.get("limit", ["200"])[0]))})
            return
        if parsed.path == "/api/dashboard/overview":
            self.send_json(dashboard_overview())
            return

        # APIs backed by imported 360/cm engine spreadsheets.
        if parsed.path == "/api/engine/stats":
            self.send_json(engine_stats())
            return
        if parsed.path == "/api/engine/samples":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["50"])[0])
            conflict_only = query.get("conflict_only", ["0"])[0] in {"1", "true", "yes"}
            self.send_json({"items": search_engine_records(limit=limit, conflict_only=conflict_only)})
            return
        if parsed.path == "/api/engine/sample":
            query = parse_qs(parsed.query)
            md5 = query.get("md5", [""])[0]
            if not md5:
                self.send_json({"error": "md5 is required"}, status=400)
                return
            self.send_json(build_sample_by_md5(md5))
            return
        if parsed.path == "/api/preprocess/stats":
            self.send_json(preprocess_stats())
            return
        if parsed.path == "/api/decision/params":
            self.send_json(load_decision_params())
            return
        if parsed.path == "/api/impersonation/assets":
            self.send_json({"items": load_asset_library()})
            return
        if parsed.path == "/api/tasks/next":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["20"])[0])
            self.send_json({"items": next_tasks(limit=limit)})
            return
        if parsed.path == "/api/tasks/summary":
            self.send_json(task_status_summary())
            return
        if parsed.path == "/api/batches":
            query = parse_qs(parsed.query)
            self.send_json({"items": list_import_batches(limit=int(query.get("limit", ["30"])[0]))})
            return
        if parsed.path == "/api/batch-jobs/status":
            query = parse_qs(parsed.query)
            try:
                self.send_json(get_batch_job(query.get("job_id", [""])[0]))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=404)
            return
        if parsed.path == "/api/features/sample":
            query = parse_qs(parsed.query)
            md5 = query.get("md5", [""])[0]
            if not md5:
                self.send_json({"error": "md5 is required"}, status=400)
                return
            self.send_json(load_feature_context(md5))
            return
        if parsed.path == "/api/validation/items":
            query = parse_qs(parsed.query)
            self.send_json(
                list_validation_items(
                    limit=int(query.get("limit", ["200"])[0]),
                    offset=int(query.get("offset", ["0"])[0]),
                    label=query.get("label", [""])[0],
                    result=query.get("result", [""])[0],
                    query=query.get("q", [""])[0],
                    judged=query.get("judged", ["0"])[0].lower() in {"1", "true", "yes"},
                    pending=query.get("pending", ["0"])[0].lower() in {"1", "true", "yes"},
                    order=query.get("order", [""])[0],
                )
            )
            return
        if parsed.path == "/api/validation/sample":
            query = parse_qs(parsed.query)
            try:
                self.send_json(get_validation_sample(query.get("md5", [""])[0]))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=404)
            return
        if parsed.path == "/api/evaluation/overview":
            self.send_json(evaluation_overview())
            return
        if parsed.path == "/api/evaluation/scorecard":
            self.send_json(build_scorecard())
            return
        if parsed.path == "/api/evaluation/five-layer":
            query = parse_qs(parsed.query)
            self.send_json(
                five_layer_overview(
                    data_dir=DATA_DIR,
                    suite_id=query.get("suite_id", [""])[0],
                )
            )
            return
        if parsed.path == "/api/evaluation/five-layer/workflows":
            query = parse_qs(parsed.query)
            self.send_json(
                workflow_overview(
                    DATA_DIR,
                    suite_id=query.get("suite_id", [""])[0],
                )
            )
            return
        if parsed.path == "/api/evaluation/five-layer/gold-expansion":
            query = parse_qs(parsed.query)
            target_text = query.get("target", [""])[0]
            self.send_json(
                gold_expansion_overview(
                    data_dir=DATA_DIR,
                    target_total=int(target_text) if target_text else None,
                    reviewer=query.get("reviewer", [""])[0],
                    role=query.get("role", ["review"])[0],
                    limit=max(1, min(100, int(query.get("limit", ["20"])[0] or 20))),
                )
            )
            return
        if parsed.path == "/api/evaluation/five-layer/rag-annotations":
            query = parse_qs(parsed.query)
            self.send_json(
                list_rag_annotations(
                    data_dir=DATA_DIR,
                    status=query.get("status", ["pending"])[0],
                    limit=max(
                        1,
                        min(100, int(query.get("limit", ["20"])[0] or 20)),
                    ),
                )
            )
            return
        self.serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        # Main judgement endpoint. The browser sends one normalized or raw
        # sample JSON object here, then `judge()` runs the whole pipeline.
        if parsed.path == "/api/judgements":
            try:
                payload = self.read_json()
                report = judge(payload)
                self.send_json(report, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/human-reviews":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                report_id = str(payload.get("report_id") or "").strip()
                if not report_id:
                    raise ValueError("report_id is required")
                review = save_human_review(
                    report_id=report_id,
                    human_label=str(payload.get("human_label") or "").strip(),
                    notes=str(payload.get("notes") or ""),
                    reviewer=str(payload.get("reviewer") or ""),
                    is_correct=payload.get("is_correct") if "is_correct" in payload else None,
                    error_types=payload.get("error_types"),
                    evidence_supported=payload.get("evidence_supported"),
                    json_valid=payload.get("json_valid"),
                    concise=payload.get("concise"),
                    punctuation_valid=payload.get("punctuation_valid"),
                    hallucination=payload.get("hallucination"),
                    corrected_output=str(payload.get("corrected_output") or ""),
                    review_status=str(payload.get("review_status") or "reviewed"),
                    second_reviewer=str(payload.get("second_reviewer") or ""),
                    adjudication_notes=str(payload.get("adjudication_notes") or ""),
                )
                self.send_json(review, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/freeze":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = freeze_evaluation_manifest(
                    name=str(payload.get("name") or "v1"),
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/datasets":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = generate_evaluation_datasets(
                    core_size=int(payload.get("core_size") or 500),
                    challenge_size=int(payload.get("challenge_size") or 300),
                    rag_size=int(payload.get("rag_size") or 200),
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/generate":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}

                def bounded(name: str, default: int, maximum: int = 5000) -> int:
                    return max(1, min(maximum, int(payload.get(name) or default)))

                result = generate_five_layer_suite(
                    name=str(payload.get("name") or "v1"),
                    data_dir=DATA_DIR,
                    model_size=bounded("model_size", 500),
                    rag_size=bounded("rag_size", 200),
                    agent_size=bounded("agent_size", 500),
                    challenge_size=bounded("challenge_size", 300),
                    fresh_candidate_size=bounded("fresh_candidate_size", 1000),
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/workflows/start":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = start_workflow(
                    str(payload.get("action") or "").strip(),
                    data_dir=DATA_DIR,
                    suite_id=str(payload.get("suite_id") or "").strip(),
                    batch_size=(
                        int(payload.get("batch_size"))
                        if payload.get("batch_size") not in (None, "")
                        else None
                    ),
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/gold-expansion/prepare":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = prepare_gold_expansion(
                    target_total=int(payload.get("target_total") or 500),
                    data_dir=DATA_DIR,
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/gold-expansion/review":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                result = save_gold_review(
                    sample_id=str(payload.get("sample_id") or ""),
                    reviewer=str(payload.get("reviewer") or ""),
                    label=str(payload.get("label") or ""),
                    notes=str(payload.get("notes") or ""),
                    role=str(payload.get("role") or "review"),
                    data_dir=DATA_DIR,
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/gold-expansion/freeze":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = freeze_gold_expansion(
                    target_total=int(payload.get("target_total") or 500),
                    name=str(payload.get("name") or ""),
                    data_dir=DATA_DIR,
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/workflows/cancel":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = cancel_workflow(
                    str(payload.get("job_id") or "").strip(),
                    data_dir=DATA_DIR,
                )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/evaluation/five-layer/rag-annotations":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                result = save_rag_annotation(
                    sample_id=str(payload.get("sample_id") or ""),
                    relevant_doc_ids=[
                        str(value)
                        for value in payload.get("relevant_doc_ids") or []
                    ],
                    hard_negative_doc_ids=[
                        str(value)
                        for value in payload.get("hard_negative_doc_ids") or []
                    ],
                    annotation_status=str(
                        payload.get("annotation_status")
                        or "needs_expert_review"
                    ),
                    reviewer=str(payload.get("reviewer") or ""),
                    review_notes=str(payload.get("review_notes") or ""),
                    no_relevant_document=bool(
                        payload.get("no_relevant_document")
                    ),
                    evidence_supported=(
                        payload.get("evidence_supported")
                        if isinstance(payload.get("evidence_supported"), bool)
                        else None
                    ),
                    hallucination=(
                        payload.get("hallucination")
                        if isinstance(payload.get("hallucination"), bool)
                        else None
                    ),
                    wrong_evidence=bool(payload.get("wrong_evidence")),
                    missing_evidence=bool(payload.get("missing_evidence")),
                    data_dir=DATA_DIR,
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/datasets/export":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = export_all_datasets(
                    output_dir=str(payload.get("output_dir") or "") or None,
                    limit=int(payload.get("limit") or 5000),
                )
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/model/settings":
            try:
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("设置内容必须是对象")
                self.send_json(update_model_settings(payload), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/preprocess/ingest":
            try:
                query = parse_qs(parsed.query)
                payload_format = query.get("format", ["json"])[0]
                source = query.get("source", ["api_gateway"])[0]
                payload = self.read_json()
                result = save_feature_record(payload, source=source, payload_format=payload_format)
                self.send_json(result, status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/data/import":
            try:
                payload = self.read_json()
                items = payload if isinstance(payload, list) else payload.get("items", [])
                if not isinstance(items, list):
                    raise ValueError("items must be an array")
                source = "manual_upload"
                payload_format = "json"
                if isinstance(payload, dict):
                    source = str(payload.get("source") or source)
                    payload_format = str(payload.get("format") or payload_format)
                self.send_json(
                    import_feature_records(items, source=source, payload_format=payload_format),
                    status=201,
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/data/excel-preview":
            try:
                query = parse_qs(parsed.query)
                content = self.read_body()
                self.send_json(
                    excel_preview(
                        content,
                        sheet_name=query.get("sheet", [""])[0],
                        header_row=int(query.get("header_row", ["1"])[0]),
                    )
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/data/import-excel":
            try:
                query = parse_qs(parsed.query)
                content = self.read_body()
                self.send_json(
                    import_excel(
                        content,
                        sheet_name=query.get("sheet", [""])[0],
                        header_row=int(query.get("header_row", ["1"])[0]),
                        start_row=int(query.get("start_row", ["2"])[0]),
                        limit=int(query.get("limit", ["100"])[0]),
                        source=query.get("source", ["excel_upload"])[0],
                    ),
                    status=201,
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/rag/search":
            try:
                if not self.rag_request_authorized():
                    return
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                query_text = str(payload.get("query") or "").strip()
                if not query_text:
                    raise ValueError("query is required")
                source_types = payload.get("source_types")
                if source_types is not None and not isinstance(source_types, list):
                    raise ValueError("source_types must be an array")
                self.send_json(
                    {
                        "items": rag_search(
                            query_text,
                            top_k=int(payload.get("top_k") or 6),
                            source_types=source_types,
                        )
                    }
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/rag/hybrid-search":
            try:
                if not self.rag_request_authorized():
                    return
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                sample = payload.get("sample") or {}
                evidence_blocks = payload.get("evidence_blocks") or []
                raw_evidence = payload.get("raw_evidence") or {}
                if not isinstance(sample, dict) or not isinstance(evidence_blocks, list) or not isinstance(raw_evidence, dict):
                    raise ValueError("sample, evidence_blocks and raw_evidence must be structured data")
                self.send_json(
                    rag_context_for_sample(
                        sample,
                        evidence_blocks,
                        raw_evidence,
                        top_k=int(payload.get("top_k") or 6),
                        allow_remote=False,
                    )
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/rag/graph-search":
            try:
                if not self.rag_request_authorized():
                    return
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                self.send_json(
                    {
                        "items": rag_search_graph(
                            payload.get("sample") or {},
                            payload.get("evidence_blocks") or [],
                            payload.get("raw_evidence") or {},
                            top_k=int(payload.get("top_k") or 6),
                            max_hops=int(payload.get("max_hops") or 1),
                        )
                    }
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/rag/text-search":
            try:
                if not self.rag_request_authorized():
                    return
                payload = self.read_json()
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                query_text = str(payload.get("query") or "").strip()
                if not query_text:
                    raise ValueError("query is required")
                self.send_json(rag_hybrid_search(query_text, top_k=int(payload.get("top_k") or 6)))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/rag/rebuild-graph":
            try:
                if not self.rag_request_authorized():
                    return
                self.send_json(rebuild_graph_index(), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/static-analysis":
            try:
                payload = self.read_json()
                _, full_report = analyze_apk_from_sample(payload)
                if not full_report:
                    self.send_json({"error": "apk_path or apk_base64 is required"}, status=400)
                    return
                self.send_json(public_static_feedback(full_report), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/threat-intelligence":
            try:
                payload = self.read_json()
                self.send_json(analyze_threat_intelligence(payload), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/impersonation":
            try:
                payload = self.read_json()
                self.send_json(analyze_impersonation(payload), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/business-label":
            try:
                payload = self.read_json()
                self.send_json(analyze_business_label(payload), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/decision/params":
            try:
                payload = self.read_json()
                self.send_json(update_decision_params(payload), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/impersonation/assets":
            try:
                payload = self.read_json()
                records = payload if isinstance(payload, list) else payload.get("items", [])
                self.send_json(update_asset_library(records), status=201)
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/preprocess/pull-conflicts":
            query = parse_qs(parsed.query)
            limit = int(query.get("limit", ["1000"])[0])
            self.send_json(pull_conflict_samples(limit=limit), status=201)
            return
        if parsed.path == "/api/batch-jobs/start":
            try:
                payload = self.read_json()
                self.send_json(
                    start_batch_judgement(
                        str(payload.get("batch_id") or ""),
                        int(payload.get("limit") or 1),
                    ),
                    status=201,
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/batch-jobs/pause":
            try:
                payload = self.read_json()
                self.send_json(pause_batch_judgement(str(payload.get("job_id") or "")))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/batch-jobs/resume":
            try:
                payload = self.read_json()
                self.send_json(resume_batch_judgement(str(payload.get("job_id") or "")))
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        if parsed.path == "/api/batch-jobs/retry-failed":
            try:
                payload = self.read_json()
                limit = payload.get("limit")
                self.send_json(
                    retry_failed_batch_judgement(
                        str(payload.get("job_id") or ""),
                        int(limit) if limit not in (None, "") else None,
                    ),
                    status=201,
                )
            except Exception as exc:
                self.send_json({"error": str(exc)}, status=400)
            return
        self.send_json({"error": "not found"}, status=404)

    def read_json(self) -> object:
        body = self.read_body()
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))

    def rag_request_authorized(self) -> bool:
        """Protect shared RAG endpoints when the optional service key is enabled."""
        expected = str(os.getenv("MALAPP_RAG_API_KEY", "")).strip()
        if not expected or self.headers.get("X-MalApp-Rag-Key", "") == expected:
            return True
        self.send_json({"error": "unauthorized RAG request"}, status=401)
        return False

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            path = "/index.html"
        target = (WEB_DIR / path.lstrip("/")).resolve()
        if not str(target).startswith(str(WEB_DIR.resolve())) or not target.exists() or not target.is_file():
            self.send_json({"error": "not found"}, status=404)
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload: object, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))


def main() -> None:
    profile = os.getenv("MALAPP_PROFILE", "demo").strip().lower()
    if profile not in {"demo", "offline", "production"}:
        raise ValueError("MALAPP_PROFILE must be demo, offline, or production")
    if profile == "production":
        os.environ.setdefault("MALAPP_DISABLE_LLM_RULE_FALLBACK", "1")
    initialize_runtime_files()
    load_model_settings()
    init_db()
    # Preserve imported features, queues and interrupted batch jobs across
    # desktop upgrades. A destructive runtime reset is available only through
    # an explicit opt-in environment flag.
    reset_on_start = os.getenv("MALAPP_RESET_RUNTIME_ON_START", "0").strip().lower()
    if reset_on_start not in {"0", "false", "no", "off"}:
        reset_runtime_state()
    recover_interrupted_jobs()
    host = os.getenv("MALAPP_HOST", "127.0.0.1")
    port = int(os.getenv("MALAPP_PORT", "8765"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Malicious APP judgement MVP running at http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
