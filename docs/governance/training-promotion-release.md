# P6 Training / Promotion / Release Governance

P6 把训练数据、候选模型、P5 评测门禁和正式 Release 串成一条不可跳步的审计链：

```text
Dataset Lineage
      ↓
Leakage Audit
      ↓
Candidate → Offline Evaluation → Regression Gate
      ↓
Shadow → Human Approval → Champion
      ↓
Release Snapshot → Verify → Deploy / Rollback
```

## 1. 数据血缘

用于生成逐样本 lineage 的规范化输入必须是 JSONL，并为每个文件声明 Partition；Excel、SQLite 等训练原始源通过独立 role 绑定：

```bash
python -m scripts.governance.manage dataset-build \
  --name malapp-training-2026q3 \
  --input train=outputs/train.jsonl \
  --input dev=outputs/dev.jsonl \
  --input test=outputs/frozen-test.jsonl \
  --source malicious=source/known-malicious.xlsx \
  --source white=source/known-white.xlsx \
  --source manual=source/manual-conflicts.xlsx \
  --source consensus=source/consensus-benign.xlsx \
  --output-dir training_artifacts/datasets/malapp-training-2026q3
```

输出：

```text
dataset-manifest.json
dataset-lineage.jsonl
```

每条 lineage 绑定 `sample_id/source/source_version/original_label/reviewed_label/reviewer/evidence/created_at/group_key/label_tier/partition`，同时提取 APK、证书、Family 和特征名称用于泄漏审计。`--source role=path` 用来额外绑定 Excel、SQLite 等真正参与训练的原始文件及其 SHA256。标签等级只有：

```text
raw → silver → human_reviewed → gold
```

规则标签、引擎共识和自动生成标签只能是 `silver`。`gold` 必须包含人工 `reviewer` 和 `reviewed_label`。

验证字节和来源文件：

```bash
python -m scripts.governance.manage dataset-validate \
  --manifest training_artifacts/datasets/malapp-training-2026q3/dataset-manifest.json \
  --verify-sources
```

## 2. 泄漏门禁

```bash
python -m scripts.governance.manage leakage-audit \
  --manifest training_artifacts/datasets/malapp-training-2026q3/dataset-manifest.json \
  --reserved data/evaluation/frozen-ids.txt \
  --output training_artifacts/datasets/malapp-training-2026q3/leakage-audit.json
```

门禁检查 MD5/SHA、证书、Family、`group_key` 跨 Partition、同一 Partition 重复、冻结评测 ID，以及标签/最终结论/引擎结论衍生特征。退出码固定为：

```text
PASS=0  FAIL=1  BLOCKED=2
```

所有正式 SFT、Policy 和 XGBoost 训练入口都要求 `--dataset-manifest`，并在加载模型或开始训练前重新执行审计和文件 SHA256 校验。单独保存一份旧 audit 报告不能绕过门禁：

```text
SFT       从 Manifest 的 train/dev partition 解析实际 JSONL
Policy    从 Manifest 的 train/test partition 解析实际 JSONL
XGBoost   将命令行 Excel 或训练 SQLite 与 Manifest source role 逐一比对
```

例如四文件 XGBoost 入口要求 Manifest 中存在 `malicious/white/manual/consensus` 四个 source role。标准 `training.xgboost.pipeline` 先执行 `prepare`，再把生成的 `xgb_training.db` 以 `xgb_training_db` role 写入 Manifest，最后单独执行 `train --dataset-manifest ...`。不再提供把准备和训练混在一起、无法预先绑定 DB 摘要的 `all` 命令。

## 3. Champion / Challenger

注册候选工件：

```bash
python -m scripts.governance.manage candidate-register \
  --registry training_artifacts/governance/model-registry.json \
  --candidate-id judgement-2026q3-01 \
  --component judgement-runtime \
  --artifact-manifest training_artifacts/xgb/models/runtime_manifest.json \
  --dataset-manifest training_artifacts/datasets/malapp-training-2026q3/dataset-manifest.json
```

执行 P5 Regression Gate：

```bash
python -m scripts.governance.manage candidate-evaluate \
  --registry training_artifacts/governance/model-registry.json \
  --candidate-id judgement-2026q3-01 \
  --baseline outputs/approved-baseline-scorecard.json \
  --candidate-scorecard outputs/candidate-scorecard.json
```

Shadow 报告必须包含：

```json
{
  "candidate_id": "judgement-2026q3-01",
  "status": "pass",
  "sample_count": 500,
  "critical_regressions": 0
}
```

然后显式记录 Shadow、人工批准和晋级：

```bash
python -m scripts.governance.manage candidate-shadow --registry ... --candidate-id ... --report outputs/shadow.json
python -m scripts.governance.manage candidate-approve --registry ... --candidate-id ... --approver analyst_a --note "reviewed"
python -m scripts.governance.manage candidate-promote --registry ... --candidate-id ...
```

状态机禁止跳过 Gate、Shadow 或人工批准。Candidate 注册会重新执行 Leakage Audit，只接受 `status=pass`，并保存 `manifest_sha256/leakage_audit_sha256/leakage_status`。声明了 `dataset_version` 的模型 Artifact 也必须和 Candidate Dataset 一致。

Registry 采用原子替换和进程锁；新 Champion 上线后旧 Champion 保留为可回滚目标：

```bash
python -m scripts.governance.manage candidate-rollback \
  --registry training_artifacts/governance/model-registry.json \
  --component judgement-runtime \
  --actor incident_commander
```

## 4. Release Snapshot

Docker 镜像构建完成后使用 registry digest，而不是 tag：

```bash
python -m scripts.governance.manage release-build \
  --version 2.1.0 \
  --component judgement-runtime \
  --registry training_artifacts/governance/model-registry.json \
  --dataset-manifest training_artifacts/datasets/malapp-training-2026q3/dataset-manifest.json \
  --baseline outputs/approved-baseline-scorecard.json \
  --candidate-scorecard outputs/candidate-scorecard.json \
  --docker-digest sha256:... \
  --runtime-snapshot data/evaluation/snapshots/runtime-....json \
  --output-dir training_artifacts/releases
```

Release Snapshot 绑定 Git Commit、Docker Digest、Agent、Prompt、模型 A/B、XGBoost、RAG、决策参数、数据集、Scorecard、Gate、Champion 和回滚目标。构建与启动验证都会重新执行 Leakage Audit，并要求当前 `audit_sha256` 与 Champion 注册时完全相同；同时重新执行 P5 Gate，并拒绝工件篡改或 Secret 字段。

部署前验证：

```bash
python -m scripts.governance.manage release-verify \
  --manifest training_artifacts/releases/release-2.1.0.json
```

服务启动时也可以启用同一验证：

```dotenv
MALAPP_RELEASE_MANIFEST=/var/lib/malapp/releases/release-2.1.0.json
```

未设置时 Demo/Offline 不受影响；正式发布应设置该变量，并确保 Manifest 引用的 Dataset、Scorecard 和 Artifact 文件在容器内可读。

## 5. CI 和真实发布边界

普通 CI 使用无业务数据 fixture 验证 Dataset Manifest、泄漏 Gate、晋级状态机、Release Snapshot 和回滚，不在 GitHub Runner 上训练大模型。真实 Release 仍必须完成：

1. 专家复核训练/评测数据。
2. 在训练环境产出真实模型工件。
3. 对相同冻结集运行完整 P5 评测。
4. 完成真实 Shadow 和人工批准。
5. 使用镜像仓库返回的 Docker Digest 构建 Release Snapshot。

因此“P6 工程闭环通过”不等于某个未经审核的模型已经具备生产发布资格。
