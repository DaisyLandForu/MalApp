# 运行流程

## 主链路

```text
FastAPI / Hermes MCP
       ↓
Judgement Application
       ↓
字段归一化与静态特征补齐
       ↓
四领域 Agent 并行执行
       ↓
EvidenceBlock 校验与结构化
       ↓
RAG Context + 可选 XGBoost Prior
       ↓
模型甲 / 模型乙辩论
       ↓
动态权重与安全护栏决策
       ↓
Report + Agent Trace + Reward
```

## 分层职责

- `apps/server`：FastAPI 协议转换、Bearer 鉴权、请求限额和分域路由；不承载业务研判逻辑。
- `malapp/application`：组织单样本、批处理和 Dashboard 用例。
- `malapp/agents`：只分析本领域并返回可追溯证据。
- `malapp/orchestration`：并发、重试、辩论和决策。
- `malapp/inference`：模型 Provider 与学习模型 Runtime。
- `malapp/rag`：文本向量和知识图谱检索。
- `malapp/observability`：Trace、人工反馈和 Reward。

## 失败语义

Agent 失败、证据不足和模型不可用是三种不同状态。失败 Agent 进入 degraded 状态，不能自动成为良性证据；生产 Profile 禁止用规则输出伪装大模型推理。

## 缓存

研判会使用严格样本缓存和可选 MD5 历史缓存。修改模型、Prompt、Artifact 或报告 schema 时，应同步更新缓存签名，防止跨版本复用旧结果。
