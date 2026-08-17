# MalApp Agent

MalApp 是一个面向恶意 Android 应用研判的证据驱动多 Agent 项目。系统将样本交给静态分析、威胁情报、仿冒识别和业务标签四个领域 Agent，并把结构化证据送入 RAG、可选 XGBoost、双模型辩论和最终决策链。

## Architecture

```text
Web / JSON API / Hermes MCP
             │
             ▼
      Judgement Application
             │
             ▼
      Agent Orchestrator
       ┌─────┼─────┬──────────┐
       ▼     ▼     ▼          ▼
    Static  Intel  Impersonation  Business
       └─────┼─────┴──────────┘
             ▼
      Evidence + RAG + XGBoost
             ▼
       Dual-model Debate
             ▼
      Decision / Trace / Review
```

主目录：

```text
apps/                 可执行应用：HTTP 服务、模型 Worker、Web UI
malapp/               在线研判核心包
  agents/             四领域 Agent 与证据处理
  application/        单样本、批处理和 Dashboard 用例
  orchestration/      Agent 调度、辩论和最终决策
  inference/          LLM 设置、本地 Qwen 和 XGBoost Runtime
  rag/                向量检索与知识图谱
  storage/            持久化适配器
  evaluation/         在线评测与人工复核流程
integrations/hermes/  Hermes MCP 与 Orchestrator Adapter
training/             离线数据集、XGBoost 和 SFT 训练
scripts/              数据、RAG、训练和评测命令
malapp/config/defaults/ 可提交、无敏感信息的最小运行资源
deploy/               Docker 和模型服务示例
tests/                单元与集成测试
```

## Quick start

推荐 Python 3.11 或 3.12：

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m apps.server.main
```

Windows PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m apps.server.main
```

访问：

```text
http://127.0.0.1:8765
http://127.0.0.1:8765/api/health
```

首次启动会把 `malapp/config/defaults/` 中的 schema、字段映射和 Demo 样本复制到运行数据目录。运行数据、模型和训练产物不提交到 Git。

## Docker

```bash
cp .env.docker.example .env
docker compose up --build -d
curl --fail http://127.0.0.1:8765/api/health
```

Compose 默认只向宿主机 `127.0.0.1` 发布端口。需要 XGBoost Runtime 时，在 `.env` 中设置：

```dotenv
MALAPP_EXTRAS=[ml]
```

## Runtime profiles

- `demo`：无外部模型时运行确定性证据链，用于页面和工程演示。
- `offline`：只运行本地分析组件，不依赖外部网络。
- `production`：应配置真实 OpenAI-compatible Provider，并在网关后启用认证、限流和 Secret 管理。

源码不再包含作者内网模型地址。模型 endpoint 和 API key 只能通过本地环境或运行配置提供；状态 API 不回显 Secret。

## Optional capabilities

```bash
python -m pip install -e '.[ml]'         # XGBoost Runtime
python -m pip install -e '.[local-llm]'  # 本地 Qwen
python -m pip install -e '.[train]'      # 离线训练与评测
python -m pip install -e '.[sft]'        # GPU SFT
```

常用命令：

```bash
python -m scripts.rag.build_index --help
python -m scripts.evaluation.run_evaluation --help
python -m scripts.evaluation.run_five_layer --help
python -m scripts.training.build_corpora --help
```

## Test

```bash
python -m pytest
python -m compileall -q apps malapp integrations training scripts
```

## Documentation

- [运行架构](docs/architecture/runtime-flow.md)
- [Docker 部署](docs/deployment.md)
- [数据接入](docs/data-ingestion.md)
- [RAG](docs/rag/guide.md)
- [评测](docs/evaluation/plan.md)
- [训练闭环](docs/training-loop.md)

项目只对 APK 做静态解析，不执行未知 APK。生产部署前仍需补充统一 API 鉴权、上传限额、模型 URL allowlist 和正式数据库迁移机制。
