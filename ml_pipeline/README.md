# MalApp 六阶段训练流水线

## 设计结论

这套流程把三个不同问题分开处理：

1. 四智能体领域风险学习。
2. 标准化证据选择和输出。
3. 四智能体融合、A/B/C WEC 与冲突终审。

当前原始数据没有人工逐条标注的证据，因此首次生成的 evidence JSON 属于
`silver_rule_generated` 银标。建议每个智能体至少抽查 300～500 条，人工修正后再做正式 SFT。

## 数据来源

- `output_app_judgment`：已知恶意样本。
- `output_app_white_lite`：已知白样本。
- `数据/360.xlsx`、`数据/cm.xlsx`：两个引擎的完整字段。
- `数据/冲突样本分析_人工标注_分身规则更新.xlsx`：人工冲突标签。

所有数据按 MD5 关联，人工冲突标签优先级最高。

## 运行

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py audit
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py prepare
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py sft
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py train
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py calibrate
```

也可以一次执行：

```powershell
.\.venv\Scripts\python.exe .\ml_pipeline\pipeline.py all
```

## 主要产物

- `training_artifacts/training_dataset.db`：统一数据底座。
- `training_artifacts/sft/<agent>/{train,val,test}.jsonl`：四智能体 SFT 数据。
- `training_artifacts/frozen_evidence_blocks.jsonl`：冻结证据块。
- `training_artifacts/models/*.json`：内部、融合、WEC、终审权重。
- `training_artifacts/models/*_calibration.json`：Temperature/Isotonic 校准参数。
- `training_artifacts/*_report.json`：数据、训练和校准报告。

## 六阶段实现

1. `audit/prepare`：选择恶意与白样本目录中最新且完整的多批次导出，排除旧快照；按 MD5 关联 360、CM 与人工冲突表。
2. `evidence_schema.json`：定义四智能体可输出的 evidence type、来源字段、证据方向、强度和缺失字段。
3. `sft`：为四个智能体分别生成 train/val/test 对话 JSONL。当前自动结果是银标，正式 SFT 前必须人工复核。
4. `sft` 同时冻结每个样本的四份 evidence block，写入 SQLite 和 `frozen_evidence_blocks.jsonl`。
5. `train`：使用类别平衡逻辑回归训练四智能体内部证据权重、四智能体融合权重、A/B/C WEC 权重和终审器。
6. `calibrate`：只在验证集比较原始概率、temperature scaling 和 isotonic regression，以 Brier score 最低者作为部署校准器。

## 权重如何训练

- 四智能体内部权重：输入为该智能体各 evidence type 的强度、证据数量和字段完整度，目标为恶意/良性标签。
- 融合权重：输入为四智能体模型概率和各自证据置信度，目标仍为恶意/良性标签。
- WEC 权重：输入 Engine A 概率、Engine B 概率、四智能体融合后的 Engine C 概率、A/B 分差和分歧标志。
- 终审裁决器：只应使用人工标注冲突样本训练。若人工冲突标签只有一个类别，程序拒绝伪训练并暂时复用 WEC。
- 损失函数：类别平衡二元交叉熵，避免恶意样本占多数时模型退化为“全部判恶意”；权重带 L2 正则。

## 标签泄漏警告

`fraud_category_big`、`fraud_category_small`、`anti_fraud_tag` 等字段可能本身就是上游研判结论。
如果这些字段由待预测标签反向生成，就不能作为独立训练特征，否则验证指标会虚高。部署前必须记录字段来源，
区分“样本原始字段”“外部情报字段”“上游模型输出”和“人工标签”，并做一次移除可疑字段的消融实验。

## 四智能体 LoRA/QLoRA

`train_sft.py` 已实现四智能体独立训练入口，`train_all_sft.ps1` 可依次训练四个适配器：

```powershell
pip install torch transformers peft accelerate bitsandbytes
.\ml_pipeline\train_all_sft.ps1 -Model "Qwen/Qwen2.5-7B-Instruct" -QLoRA
```

建议在 GPU 服务器执行。语言模型负责从输入字段生成标准化 evidence JSON；数值权重模型负责概率融合与校准，
二者分开训练，便于审计和替换。

## XGBoost 版本

`xgb_pipeline.py` 实现四智能体内部模型、融合模型、A/B/C WEC、验证集自动阈值和测试集导出：

```powershell
.\.venv\Scripts\python.exe .\ml_pipeline\xgb_pipeline.py prepare
.\.venv\Scripts\python.exe .\ml_pipeline\xgb_pipeline.py train
```

模型和测试产物位于 `training_artifacts/xgb`。APP 默认通过 `engine/xgb_runtime.py` 使用该模型，
可设置 `MALAPP_USE_XGB=0` 回退到原决策逻辑。

## 正式 SFT 前的要求

1. 对银标 evidence 抽样人工复核。
2. 检查 `source_fields` 和 `source_values` 是否真的支撑证据。
3. 删除任何无法从输入字段回溯的描述。
4. 使用 GPU 环境安装 `transformers`、`datasets`、`peft`、`trl`。
5. 每个智能体独立 LoRA/QLoRA，不能用同一输出模板训练四个角色。

## 防止数据泄漏

训练、验证、测试不是简单按行随机拆分，而是优先按证书、病毒家族和应用基础名组成
`group_id` 后再拆分，降低同一家族或分身样本跨集合泄漏的风险。
