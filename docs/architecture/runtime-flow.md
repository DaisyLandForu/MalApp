# 运行流程

## 主链路

```text
FastAPI / Batch / Hermes MCP
             ↓
       JudgementRequest
             ↓
       JudgementService
             ↓
 A/B INPUT VALIDATION → ENGINE C ADMISSION
  ↙ CLEAR/LOW-RISK       ↘ RUN ENGINE C
 A/B RESULT + REVIEW   NORMALIZE → STATIC_EXTRACTION
       │                     ↓
       │               AGENT_EXECUTION
       │           （Planner 默认关闭；开启后在 Runtime 前
       │             生成 InvestigationPlan，跳过的 Agent
       │             以 skipped_by_plan 占位，不走失败降级。
       │             Evidence Gate + 最多一次 Re-plan
       │             仍在本阶段内部完成。
       │             统一 Runtime 并行/重试/超时，
       │             确定性 Tool + 共享专家模型）
       │                     ↓
       │          RAG_RETRIEVAL → XGB_INFERENCE
       │                     ↓
       │                   DEBATE
       │            （首轮共享完整 Evidence）
       │                     ↓
       │              FINAL_DECISION_C
       │                     ↓
       │                   PERSIST
       │                     ↓
       └──────────→ A/B/C DYNAMIC WEC
                             ↓
          Report + Agent Trace + Metrics + Provenance + Reward
```

八阶段状态机是 Engine C 的内部流水线。清晰 A/B 共识和低风险不确定结果都不进入 Engine C，八阶段全部记录为 `skipped`，也不生成 Score C；后者额外设置人工复核。

旧版线性图如下逻辑已由上图取代：

```text
 NORMALIZE → STATIC_EXTRACTION
             ↓
       AGENT_EXECUTION
   （统一 Runtime 并行/重试/超时）
             ↓
 RAG_RETRIEVAL → XGB_INFERENCE
             ↓
           DEBATE
             ↓
      FINAL_DECISION
       （显式降级策略）
             ↓
           PERSIST
             ↓
 Report + Agent Trace + Reward
```

## 分层职责

- `apps/server`：FastAPI 协议转换、Bearer 鉴权、请求限额和分域路由；不承载业务研判逻辑。
- `malapp/application`：提供唯一 `JudgementService`，组织单样本、批处理和 Dashboard 用例。
- `malapp/agents`：遵循统一 `Agent` Protocol；领域分析与 Evidence 生成都在 `Agent.run()` 内完成并返回 `AgentResult`。
- `malapp/orchestration`：统一管理注册、并发、重试、超时、失败分类、状态机、降级、辩论和决策。
- `malapp/inference`：模型 Provider 与学习模型 Runtime。
- `malapp/rag`：文本向量和知识图谱检索。
- `malapp/governance`：校验 XGBoost Artifact、生成 RAG/Prompt/Runtime 版本快照。
- `malapp/observability`：统一 Trace、长期指标、Decision Provenance、人工反馈和 Reward。

## 失败语义

Agent 超时、执行异常、证据不足和模型不可用是不同状态。非关键 Agent 失败允许继续，但会降低最终置信度；静态分析等关键 Agent 失败会强制人工复核，并阻止良性结论直接放行。生产 Profile 禁止用规则输出伪装大模型推理。

每个 Agent 在 `preprocess.agent_runtime.agents.<name>.trace` 中保存生命周期；每个 Pipeline Stage 在 `execution.pipeline.stages` 中保存 `completed / failed / degraded / skipped` 终态。降级原因同时进入顶层 `degradation` 与 `decision.degradation`。

Hermes 不拥有第二套 Agent Pipeline。它只把 MCP 参数转换为 `JudgementRequest`，并调用与 Web、Batch 相同的 `JudgementService`。

每份新报告通过 `runtime_snapshot` 绑定实际代码提交、模型 A/B、XGBoost Artifact、RAG Snapshot、Prompt Bundle、决策参数和四 Agent 版本。Trace 复用同一 Snapshot；统一 `run_id`、Stage/Model Trace、长期指标与决策图见 [可观测性与决策溯源](observability.md)，Artifact 校验规则见 [Artifact Governance](artifact-governance.md)。

## 缓存

研判会使用严格样本缓存和可选 MD5 历史缓存。缓存命中还要求 `execution.orchestration_mode` 一致（`v0_fixed` / `v1_planner` / `v2_planner_tools`），避免 Planner 关闭与开启之间复用旧报告。修改模型、Prompt、Artifact 或报告 schema 时，应同步更新缓存签名，防止跨版本复用旧结果。
