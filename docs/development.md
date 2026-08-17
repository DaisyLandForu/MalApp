# 开发与调试

## 环境

使用 Python 3.11 或 3.12：

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

启动服务：

```bash
python -m apps.server.main
```

运行检查：

```bash
python -m compileall -q apps malapp integrations training scripts
python -m ruff check apps malapp integrations training scripts tests
python -m pytest
```

## 代码导航

| 目标 | 文件 |
|---|---|
| HTTP 应用工厂 | `apps/server/app.py` |
| 安全配置与中间件 | `apps/server/config.py`、`auth.py`、`middleware.py` |
| 分域 HTTP 路由 | `apps/server/routes/` |
| 服务启动入口 | `apps/server/main.py` |
| 单样本研判 | `malapp/application/judgement.py` |
| 统一研判服务 | `malapp/application/service.py` |
| 批量研判 | `malapp/application/batch.py` |
| Agent Protocol | `malapp/agents/base.py` |
| 四 Agent Runtime | `malapp/orchestration/runtime.py` |
| Pipeline 状态机 | `malapp/orchestration/pipeline.py` |
| 降级策略 | `malapp/orchestration/degradation.py` |
| 双模型辩论 | `malapp/orchestration/debate.py` |
| 最终决策 | `malapp/orchestration/decision.py` |
| 模型配置 | `malapp/inference/settings.py` |
| XGBoost Runtime | `malapp/inference/xgboost.py` |
| RAG | `malapp/rag/` |
| Hermes MCP | `integrations/hermes/` |
| 离线训练 | `training/` |

## 运行数据

默认运行数据位于仓库的 `data/`，也可通过 `MALAPP_DATA_DIR` 修改。首次启动只从 `malapp/config/defaults/` 复制缺失的最小资源，不覆盖已有数据。

APK 和图标路径只能位于 `MALAPP_WORKSPACE_ROOT`；本地默认值是仓库的 `workspace/`。

## 调试顺序

1. `/api/health` 检查服务、版本和 Profile。
2. 使用 Admin Bearer Token 调用 `/api/model/settings` 检查 Provider 状态；该接口不会回显 API key。
3. `/api/rag/status` 和 `/api/xgb/status` 检查可选组件。
4. 用 `config/defaults/sample_conflict.json` 验证完整研判链。
5. 先查看 `execution.pipeline` 定位失败 Stage，再查看 `preprocess.agent_runtime` 的单 Agent Trace、`degradation`、`debate` 和 `decision.decision_trace`。

不要在源码、测试或文档中写入真实 endpoint、Secret、作者机器路径或私有数据文件名。

生产模式会在启动阶段验证 API Key 和模型 Host allowlist。测试不同权限时建议设置两个 Key：

```bash
MALAPP_API_KEY=test-user
MALAPP_ADMIN_API_KEY=test-admin
```
