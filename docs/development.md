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
python -m pytest
```

## 代码导航

| 目标 | 文件 |
|---|---|
| HTTP API | `apps/server/main.py` |
| 单样本研判 | `malapp/application/judgement.py` |
| 批量研判 | `malapp/application/batch.py` |
| 四 Agent 调度 | `malapp/orchestration/agent_runtime.py` |
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
2. `/api/model/settings` 检查 Provider 状态；该接口不会回显 API key。
3. `/api/rag/status` 和 `/api/xgb/status` 检查可选组件。
4. 用 `config/defaults/sample_conflict.json` 验证完整研判链。
5. 通过报告中的 `preprocess.agent_runtime`、`debate` 和 `decision.decision_trace` 定位阶段错误。

不要在源码、测试或文档中写入真实 endpoint、Secret、作者机器路径或私有数据文件名。
