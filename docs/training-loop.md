# MalApp 训练闭环与 Agent Trace 使用说明

本文说明本版本新增的训练闭环能力：`agent_trace`、人工复核、`reward_builder`、SFT/DPO/策略数据导出，以及后续训练入口。

## 1. 新增能力总览

本版本没有覆盖旧 APP，而是在原有研判流程之后新增一条学习闭环：

```text
样本研判
  -> 保存完整报告 judgements
  -> 保存 agent_trace 完整轨迹
  -> reward_builder 自动评分
  -> 人工复核保存 human_label 和备注
  -> 重新计算 reward
  -> 导出 SFT / DPO / policy_training 数据
```

## 2. agent_trace 是什么

`agent_trace` 是每次研判的完整轨迹记录，保存位置在 SQLite 数据库 `data/mvp.db` 的 `agent_traces` 表。

它记录：

- 样本基础信息：MD5、SHA1、SHA256、应用名、包名。
- 输入快照：预处理结果、Raw Evidence、RAG 召回结果。
- 四智能体输出：静态分析、情报溯源、仿冒研判、业务打标的 EvidenceBlock。
- 大模型解释层：四智能体中文解释。
- 双模型辩论：模型甲、模型乙、交叉质疑、反驳、终审。
- 协同决策：最终结论、风险等级、分数、关键证据。
- 执行信息：入口来源、统一 Agent Runtime、Pipeline Stage、缓存、模型签名和错误信息。

相关代码：

- `malapp/observability/trace.py`
- `malapp/application/judgement.py` 中 `judge()` 结束时调用 `save_agent_trace(report)`
- `apps/server/main.py` 中 `/api/agent-trace` 和 `/api/agent-traces`

## 3. 人工复核入口

APP 左侧新增 `训练闭环` 页面。

使用步骤：

1. 在 `研判任务` 或 `结果详情` 打开一份报告。
2. 进入 `训练闭环`。
3. 选择人工标签：`恶意 / 可疑 / 良性`。
4. 填写复核备注，例如误报原因、关键证据、缺失字段。
5. 点击 `保存人工复核`。

保存后会写入：

- SQLite 表：`human_reviews`
- 字段：`report_id`、`human_label`、`notes`、`reviewer`、`is_correct`

相关代码：

- `malapp/observability/trace.py` 中 `save_human_review()`
- `apps/server/main.py` 中 `POST /api/human-reviews`
- `web/index.html` 的 `learningView`
- `web/app.js` 的 `saveHumanReview()`

## 4. reward_builder 怎么评分

`reward_builder` 不是最终业务判定，而是训练反馈分数。

没有人工标签时，它用弱奖励：

- 结构完整性：报告是否包含样本、四智能体、模型甲乙、终审、决策。
- 证据覆盖率：EvidenceBlock 数量、证据条目数量、字段缺失情况。
- 辩论有效性：是否完成模型甲、模型乙、质疑、终审。
- 模型健康：是否出现 timeout、schema failed、fallback 等错误。
- 置信质量：最终分数是否远离边界、证据分数是否稳定。

有人工作标签时，人工标签优先：

- 研判结论和人工标签一致：提高 reward。
- 不一致：降低 reward，并用于 DPO 纠偏数据。

相关代码：

- `malapp/observability/rewards.py`
- `malapp/application/judgement.py` 中 `save_reward_for_report(report)`
- `apps/server/main.py` 中 `/api/rewards`

## 5. 导出 SFT / DPO / 策略训练数据

APP 页面导出：

1. 进入 `训练闭环`。
2. 设置最多导出报告数。
3. 点击 `导出训练数据集`。

命令行导出：

```bash
python -m scripts.training.export_datasets --limit 5000
```

默认输出到：

```text
data/exports/training_loop_YYYYMMDD_HHMMSS/
```

导出文件：

- `report_generation_sft.jsonl`
  - 用于训练“报告生成 SFT”。
  - 目标：让模型输出格式更稳定、证据链更清楚。
- `debate_dpo.jsonl`
  - 用于后续 DPO/RLHF。
  - 只有人工复核发现模型错误时，才会产生 chosen/rejected 偏好对。
- `policy_training.jsonl`
  - 用于训练“策略模型”。
  - 学习是否调用 RAG、是否完整辩论、是否进入人工复核。
- `export_summary.json`
  - 导出数量和文件路径摘要。

相关代码：

- `training/datasets/export.py`
- `apps/server/main.py` 中 `POST /api/datasets/export`
- `scripts/training/export_datasets.py`

## 6. 报告生成 SFT 怎么做

第一阶段建议先训练“报告生成 SFT”，不是直接训练判恶意。

训练目标：

- 输入：样本信息、四智能体 EvidenceBlock、RAG 摘要、双模型辩论摘要。
- 输出：稳定中文研判报告 JSON。

推荐流程：

```text
导出 report_generation_sft.jsonl
  -> 转成 LLaMA-Factory 或其他微调框架格式
  -> 使用 Qwen / DeepSeek 系列基座模型做 LoRA/QLoRA SFT
  -> 用验证集检查 JSON 合规率、证据引用率、人工可读性
```

当前项目已经提供导出数据，实际大模型微调需要你在训练服务器上执行。

## 7. 策略模型怎么训练

策略模型不是输出研判报告，而是决定：

- 是否调用 RAG。
- 是否完整辩论。
- 是否进入人工复核。

导出 `policy_training.jsonl` 后运行：

```bash
python -m training.sft.train_policy \
  data/exports/training_loop_YYYYMMDD_HHMMSS/policy_training.jsonl \
  --dataset-manifest training_artifacts/datasets/current/dataset-manifest.json
```

输出：

```text
training_artifacts/policy_model/policy_model.pkl
training_artifacts/policy_model/policy_training_report.json
```

当前脚本使用 `RandomForestClassifier` 做基线，后续可以替换成 XGBoost 或轻量神经网络。

相关代码：

- `training/sft/train_policy.py`

## 8. DPO / RLHF 什么时候做

现在不建议马上做 DPO/RLHF，因为需要较多人工复核数据。

建议顺序：

1. 先积累人工复核。
2. 每次人工复核都写清楚备注。
3. 当错误样本和纠正样本达到数百到数千条后，再导出 `debate_dpo.jsonl`。
4. 用 chosen/rejected 做 DPO。
5. 如果要做 Agent RL，再把策略动作和最终 reward 作为轨迹训练数据。

## 9. 新增 API

```text
GET  /api/agent-traces?limit=100
GET  /api/agent-trace?report_id=...
GET  /api/human-reviews?limit=200
POST /api/human-reviews
GET  /api/rewards?report_id=...
GET  /api/rewards?limit=200
POST /api/datasets/export
```

`POST /api/human-reviews` 示例：

```json
{
  "report_id": "report-xxxx",
  "human_label": "malicious",
  "notes": "业务标签和黑产家族均支持恶意，当前结论正确。",
  "reviewer": "analyst_a"
}
```

`POST /api/datasets/export` 示例：

```json
{
  "limit": 5000
}
```

## 10. 修改过的核心文件

- `malapp/observability/trace.py`
- `malapp/observability/rewards.py`
- `training/datasets/export.py`
- `malapp/application/judgement.py`
- `apps/server/main.py`
- `web/index.html`
- `web/app.js`
- `scripts/training/export_datasets.py`
- `training/sft/train_policy.py`
