from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def build_notebook(build_dir: Path) -> tuple[Path, Path]:
    import nbformat
    from nbclient import NotebookClient

    audit_dir = build_dir / "audit"
    notebook_path = audit_dir / "training_data_audit.ipynb"
    executed_path = audit_dir / "training_data_audit_executed.ipynb"
    notebook = nbformat.v4.new_notebook(
        metadata={
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3"},
        }
    )
    notebook.cells = [
        nbformat.v4.new_markdown_cell(
            "# MalApp训练数据构造审计\n\n"
            "本Notebook复核五类数据的数量、逐行JSON有效性、冻结评测泄漏、"
            "校准组泄漏、标签比例和待人工补标缺口。"
        ),
        nbformat.v4.new_code_cell(
            "from pathlib import Path\n"
            "import json\n"
            "from collections import Counter\n"
            "import pandas as pd\n"
            "BUILD_DIR = Path('..').resolve()\n"
            "manifest = json.loads((BUILD_DIR / 'manifest.json').read_text(encoding='utf-8'))\n"
            "quality = json.loads((BUILD_DIR / 'quality_report.json').read_text(encoding='utf-8'))\n"
            "manifest['build_id'], manifest['quality_gate_passed']"
        ),
        nbformat.v4.new_code_cell(
            "def validate_jsonl(path):\n"
            "    rows = 0\n"
            "    bad = []\n"
            "    with path.open(encoding='utf-8') as handle:\n"
            "        for line_no, line in enumerate(handle, 1):\n"
            "            if not line.strip():\n"
            "                continue\n"
            "            rows += 1\n"
            "            try:\n"
            "                json.loads(line)\n"
            "            except Exception as exc:\n"
            "                bad.append((line_no, str(exc)))\n"
            "    return rows, bad\n"
            "jsonl_validation = []\n"
            "for path in sorted(BUILD_DIR.rglob('*.jsonl')):\n"
            "    rows, bad = validate_jsonl(path)\n"
            "    jsonl_validation.append({'file': str(path.relative_to(BUILD_DIR)), 'rows': rows, 'invalid': len(bad)})\n"
            "validation_df = pd.DataFrame(jsonl_validation)\n"
            "assert int(validation_df['invalid'].sum()) == 0\n"
            "validation_df"
        ),
        nbformat.v4.new_code_cell(
            "counts = manifest['counts']\n"
            "capacity = pd.DataFrame([\n"
            "    {'数据类型':'SFT', '已构造':counts['sft_total'], '可训练/已验证':counts['sft_total'], '待运行或复核':0},\n"
            "    {'数据类型':'DPO', '已构造':counts['dpo_candidate_capacity'], '可训练/已验证':counts['dpo_ready'], '待运行或复核':counts['dpo_candidate_capacity']},\n"
            "    {'数据类型':'RAG', '已构造':counts['rag_silver'], '可训练/已验证':counts['rag_gold_ready'], '待运行或复核':counts['rag_silver']},\n"
            "    {'数据类型':'Agent成功', '已构造':counts['agent_success_capacity'], '可训练/已验证':counts['agent_success'], '待运行或复核':counts['agent_success_generation_queue']},\n"
            "    {'数据类型':'故障恢复', '已构造':counts['agent_fault_recovery_execution_queue'], '可训练/已验证':counts['agent_fault_recovery_verified'], '待运行或复核':counts['agent_fault_recovery_execution_queue']},\n"
            "    {'数据类型':'校准开发', '已构造':counts['calibration_dev'], '可训练/已验证':counts['calibration_dev'], '待运行或复核':0},\n"
            "])\n"
            "capacity"
        ),
        nbformat.v4.new_code_cell(
            "checks = pd.DataFrame([{'检查项': key, '问题数': value} for key, value in quality['checks'].items()])\n"
            "assert int(checks['问题数'].sum()) == 0\n"
            "checks"
        ),
        nbformat.v4.new_code_cell(
            "sft_dist = quality['distributions']\n"
            "pd.DataFrame({\n"
            "    '标签': pd.Series(sft_dist['sft_labels']),\n"
            "    '标签等级': pd.Series(sft_dist['sft_label_tiers']),\n"
            "    '证据质量': pd.Series(sft_dist['sft_evidence_quality']),\n"
            "})"
        ),
        nbformat.v4.new_markdown_cell(
            "## 审计结论\n\n"
            "- 数量达标不等于已经具备专家金标：DPO、RAG和故障恢复仍有人工或环境执行门槛。\n"
            "- SFT应先用证据富集子集做小规模LoRA/QLoRA，并在独立校准集上调阈值。\n"
            "- 每轮训练后必须重新生成诊断与生产回放基线，但永久冻结集不能回流训练。"
        ),
    ]
    notebook_path.parent.mkdir(parents=True, exist_ok=True)
    nbformat.write(notebook, notebook_path)
    client = NotebookClient(
        notebook,
        timeout=600,
        kernel_name="python3",
        resources={"metadata": {"path": str(audit_dir)}},
    )
    executed = client.execute()
    nbformat.write(executed, executed_path)
    return notebook_path, executed_path


def build_artifact(build_dir: Path) -> Path:
    manifest = read_json(build_dir / "manifest.json")
    quality = read_json(build_dir / "quality_report.json")
    counts = manifest["counts"]
    targets = manifest["targets"]
    modality_rows = [
        {
            "modality": "SFT",
            "target": targets["sft_core"] + targets["sft_expansion"],
            "ready": counts["sft_total"],
            "queued": 0,
            "capacity": counts["sft_total"],
            "status": "来源监督可分层使用",
        },
        {
            "modality": "DPO",
            "target": targets["dpo"],
            "ready": counts["dpo_ready"],
            "queued": counts["dpo_candidate_capacity"],
            "capacity": counts["dpo_candidate_capacity"],
            "status": "需生成并逐对专家复核",
        },
        {
            "modality": "RAG",
            "target": targets["rag"],
            "ready": counts["rag_gold_ready"],
            "queued": counts["rag_silver"],
            "capacity": counts["rag_silver"],
            "status": "银标可预热，发布指标需专家标注",
        },
        {
            "modality": "Agent成功",
            "target": targets["agent_success"],
            "ready": counts["agent_success"],
            "queued": counts["agent_success_generation_queue"],
            "capacity": counts["agent_success_capacity"],
            "status": "补跑队列已生成",
        },
        {
            "modality": "故障恢复",
            "target": targets["agent_fault_recovery"],
            "ready": counts["agent_fault_recovery_verified"],
            "queued": counts["agent_fault_recovery_execution_queue"],
            "capacity": counts["agent_fault_recovery_execution_queue"],
            "status": "需隔离注入并验证恢复",
        },
        {
            "modality": "校准开发",
            "target": targets["calibration"],
            "ready": counts["calibration_dev"],
            "queued": 0,
            "capacity": counts["calibration_dev"],
            "status": "仅用于阈值/校准",
        },
    ]
    sft_quality_rows = [
        {"tier": "证据富集", "count": quality["distributions"]["sft_evidence_quality"].get("enriched", 0)},
        {"tier": "字段较少", "count": quality["distributions"]["sft_evidence_quality"].get("minimal", 0)},
    ]
    check_rows = [
        {
            "check": key,
            "issues": value,
            "result": "通过" if value == 0 else "失败",
        }
        for key, value in quality["checks"].items()
    ]
    artifact = {
        "surface": "report",
        "manifest": {
            "version": 1,
            "surface": "report",
            "title": "MalApp训练数据构造与质量审计",
            "description": "基于现有标签、RAG知识库和Agent轨迹生成的五类训练数据容量、可用性和泄漏检查。",
            "generatedAt": manifest["generated_at"],
            "filters": [],
            "cards": [
                {
                    "id": "sft_card",
                    "description": "SFT总量及证据富集子集。",
                    "dataset": "summary",
                    "sourceId": "training_manifest",
                    "filter": {"metric": "sft"},
                    "metrics": [
                        {"label": "SFT总量", "field": "total"},
                        {"label": "证据富集", "field": "enriched"},
                    ],
                },
                {
                    "id": "queue_card",
                    "description": "DPO和Agent候选容量。",
                    "dataset": "summary",
                    "sourceId": "training_manifest",
                    "filter": {"metric": "queues"},
                    "metrics": [
                        {"label": "DPO容量", "field": "dpo_capacity"},
                        {"label": "Agent容量", "field": "agent_capacity"},
                    ],
                },
                {
                    "id": "quality_card",
                    "description": "泄漏与重复检查。",
                    "dataset": "summary",
                    "sourceId": "quality_report",
                    "filter": {"metric": "quality"},
                    "metrics": [
                        {"label": "冻结ID", "field": "reserved"},
                        {"label": "质量问题", "field": "issues"},
                    ],
                },
            ],
            "charts": [
                {
                    "id": "capacity_chart",
                    "title": "各类数据目标与当前容量",
                    "subtitle": "容量包含待运行/待人工复核记录；Ready只表示已经满足当前训练门槛。",
                    "type": "bar",
                    "dataset": "modality_capacity",
                    "sourceId": "training_manifest",
                    "encodings": {
                        "x": {"field": "modality", "type": "nominal", "label": "数据类型"},
                        "y": {"field": "capacity", "type": "quantitative", "label": "记录数"},
                        "tooltip": [
                            {"field": "target", "type": "quantitative", "label": "目标"},
                            {"field": "ready", "type": "quantitative", "label": "Ready"},
                            {"field": "queued", "type": "quantitative", "label": "待运行/复核"},
                        ],
                    },
                },
                {
                    "id": "sft_quality_chart",
                    "title": "SFT证据质量构成",
                    "subtitle": "建议首轮仅使用证据富集子集。",
                    "type": "bar",
                    "dataset": "sft_quality",
                    "sourceId": "quality_report",
                    "encodings": {
                        "x": {"field": "tier", "type": "nominal", "label": "证据等级"},
                        "y": {"field": "count", "type": "quantitative", "label": "样本数"},
                    },
                },
            ],
            "tables": [
                {
                    "id": "capacity_table",
                    "title": "数据构造明细",
                    "subtitle": "Ready、排队和目标必须分开解读。",
                    "dataset": "modality_capacity",
                    "sourceId": "training_manifest",
                    "columns": [
                        {"field": "modality", "label": "类型", "type": "text"},
                        {"field": "target", "label": "目标"},
                        {"field": "ready", "label": "Ready"},
                        {"field": "queued", "label": "待运行/复核"},
                        {"field": "capacity", "label": "总容量"},
                        {"field": "status", "label": "当前状态", "type": "text"},
                    ],
                },
                {
                    "id": "quality_table",
                    "title": "泄漏与重复检查",
                    "subtitle": "所有问题数应为0。",
                    "dataset": "quality_checks",
                    "sourceId": "quality_report",
                    "columns": [
                        {"field": "check", "label": "检查项", "type": "text"},
                        {"field": "issues", "label": "问题数"},
                        {"field": "result", "label": "结论", "type": "text"},
                    ],
                },
            ],
            "sources": [
                {"id": "training_manifest", "label": "训练数据构造清单", "path": "manifest.json"},
                {"id": "quality_report", "label": "训练数据质量报告", "path": "quality_report.json"},
            ],
            "blocks": [
                {
                    "id": "summary_text",
                    "type": "markdown",
                    "body": (
                        "## 结论\n\n"
                        f"- SFT已构造 **{counts['sft_total']:,}** 条，其中证据富集 **{counts['sft_enriched_only']:,}** 条。\n"
                        f"- DPO容量 **{counts['dpo_candidate_capacity']:,}**，但专家批准仍为 **0**；不得直接启动DPO。\n"
                        f"- Agent已有 **{counts['agent_success']:,}** 条成功轨迹，另有 **{counts['agent_success_generation_queue']:,}** 条补跑任务。\n"
                        "- RAG银标用于检索器预热；发布门禁仍需独立专家相关性和证据忠实度标注。"
                    ),
                },
                {"id": "metrics", "type": "metric-strip", "cardIds": ["sft_card", "queue_card", "quality_card"]},
                {"id": "capacity", "type": "chart", "chartId": "capacity_chart"},
                {"id": "sft_quality", "type": "chart", "chartId": "sft_quality_chart"},
                {"id": "detail", "type": "table", "tableId": "capacity_table"},
                {"id": "checks", "type": "table", "tableId": "quality_table"},
                {
                    "id": "next_steps",
                    "type": "markdown",
                    "body": (
                        "## 建议执行顺序\n\n"
                        "1. 用证据富集SFT子集做首轮LoRA/QLoRA并在800条校准集上调阈值。\n"
                        "2. 补跑DPO和Agent队列；DPO逐对确认，Agent按验收条件自动入库。\n"
                        "3. 对RAG查询做双人相关性标注，对故障注入做隔离执行和恢复验证。\n"
                        "4. 训练后重建诊断/生产回放基线，永久冻结集继续隔离。"
                    ),
                },
            ],
        },
        "snapshot": {
            "version": 1,
            "generatedAt": manifest["generated_at"],
            "status": "ready",
            "datasets": {
                "summary": [
                    {
                        "metric": "sft",
                        "total": counts["sft_total"],
                        "enriched": counts["sft_enriched_only"],
                        "dpo_capacity": 0,
                        "agent_capacity": 0,
                        "reserved": 0,
                        "issues": 0,
                    },
                    {
                        "metric": "queues",
                        "total": 0,
                        "enriched": 0,
                        "dpo_capacity": counts["dpo_candidate_capacity"],
                        "agent_capacity": counts["agent_success_capacity"],
                        "reserved": 0,
                        "issues": 0,
                    },
                    {
                        "metric": "quality",
                        "total": 0,
                        "enriched": 0,
                        "dpo_capacity": 0,
                        "agent_capacity": 0,
                        "reserved": counts["reserved_eval_ids"],
                        "issues": sum(quality["checks"].values()),
                    },
                ],
                "modality_capacity": modality_rows,
                "sft_quality": sft_quality_rows,
                "quality_checks": check_rows,
            },
            "accessIssues": [],
        },
        "sources": [
            {
                "id": "training_manifest",
                "query": {
                    "engine": "local-json-audit",
                    "sql": "SELECT targets, counts, files FROM manifest",
                    "description": "读取版本化训练数据构造清单。",
                    "executed_at": manifest["generated_at"],
                },
            },
            {
                "id": "quality_report",
                "query": {
                    "engine": "local-json-audit",
                    "sql": "SELECT checks, distributions, readiness FROM quality_report",
                    "description": "读取冻结泄漏、重复、分布和可用性检查。",
                    "executed_at": quality["generated_at"],
                },
            },
        ],
        "package_info": {
            "originUrl": "artifact://malapp-training-data-audit",
            "controls": {"edit": False, "refresh": False},
        },
    }
    path = build_dir / "audit" / "artifact.json"
    write_json(path, artifact)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and execute MalApp training-data audit artifacts.")
    parser.add_argument("build_dir")
    parser.add_argument("--skip-notebook", action="store_true")
    args = parser.parse_args()
    build_dir = Path(args.build_dir).expanduser().resolve()
    artifact = build_artifact(build_dir)
    result: dict[str, Any] = {"artifact": str(artifact)}
    if not args.skip_notebook:
        notebook, executed = build_notebook(build_dir)
        result.update({"notebook": str(notebook), "executed_notebook": str(executed)})
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
