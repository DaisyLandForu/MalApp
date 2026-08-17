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
MALAPP_USE_SERVER_MODELS=1
MALAPP_MODEL_A_API_URL=https://model-a.example/v1
MALAPP_MODEL_A_MODEL=model-a
MALAPP_MODEL_A_API_KEY=...
MALAPP_MODEL_B_API_URL=https://model-b.example/v1
MALAPP_MODEL_B_MODEL=model-b
MALAPP_MODEL_B_API_KEY=...
```

生产 Secret 应由部署平台注入，不应提交 `.env`。公网部署还需要在反向代理或 API Gateway 后启用 TLS、认证、限流和请求大小限制。

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
