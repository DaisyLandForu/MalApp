# Docker 部署

## 快速启动

```bash
cp .env.docker.example .env
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8765/api/health
```

默认只绑定宿主机 `127.0.0.1:8765`。容器使用非 root 用户、只读根文件系统、移除 Linux capabilities，并把运行数据和输入工作区分开挂载。

```text
malapp-judgement-data       → /var/lib/malapp
deploy/docker/workspace/    → /workspace（只读）
```

## Profile

Demo：

```dotenv
MALAPP_PROFILE=demo
MALAPP_USE_SERVER_MODELS=0
MALAPP_USE_LOCAL_QWEN=0
```

生产：

```dotenv
MALAPP_PROFILE=production
MALAPP_API_KEY=replace-with-user-key
MALAPP_ADMIN_API_KEY=replace-with-separate-admin-key
MALAPP_USE_SERVER_MODELS=1
MALAPP_MODEL_A_API_URL=https://model-a.example/v1
MALAPP_MODEL_A_MODEL=model-a
MALAPP_MODEL_A_API_KEY=...
MALAPP_MODEL_B_API_URL=https://model-b.example/v1
MALAPP_MODEL_B_MODEL=model-b
MALAPP_MODEL_B_API_KEY=...
MALAPP_MODEL_ALLOWED_HOSTS=model-a.example,model-b.example
```

`MALAPP_API_KEY` 缺失时 production 会拒绝启动。普通 Key 可以调用研判、报告、RAG 和 Agent API；独立 Admin Key 用于模型配置、Decision 参数、数据集、Evaluation 和 Batch Job。

模型 API Key 只从环境变量读取，模型设置接口不会保存或回显它。生产 Secret 应由部署平台注入，不应提交 `.env`。公网部署还需要在反向代理或 API Gateway 后启用 TLS 和上游限流。

已内置的应用层限额：

```dotenv
MALAPP_MAX_JSON_BYTES=2097152
MALAPP_MAX_UPLOAD_BYTES=67108864
MALAPP_MAX_QUERY_LIMIT=1000
MALAPP_MAX_BATCH_ITEMS=1000
MALAPP_MAX_RAG_TOP_K=50
MALAPP_MAX_GRAPH_HOPS=3
MALAPP_MAX_EXCEL_ROWS=5000
```

认证请求示例：

```bash
curl -H "Authorization: Bearer ${MALAPP_API_KEY}" \
  http://127.0.0.1:8765/api/reports
```

## XGBoost

默认镜像保持轻量，不安装 XGBoost。需要时设置：

```dotenv
MALAPP_EXTRAS=[ml]
MALAPP_XGB_DIR=/artifacts/xgb
```

并将经过版本和 SHA256 校验的 Artifact 只读挂载到容器。

## 数据备份

运行数据保存在命名卷 `malapp-judgement-data`。升级镜像不会删除该卷；执行 `docker compose down -v` 会删除数据，操作前必须备份。

## 常用排查

```bash
docker compose logs --tail 200 malapp
docker compose config
docker inspect malapp-judgement
docker volume inspect malapp-judgement-data
```
