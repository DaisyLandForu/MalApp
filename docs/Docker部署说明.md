# Docker部署说明

## 容器结构

当前部署包含一个业务服务容器：

```text
浏览器/业务APP
      ↓ 8765
malapp-judgement容器
      ├─ Web工作台和JSON API
      ├─ 四智能体确定性分析工具
      ├─ 双模型辩论与三引擎裁决
      └─ Hermes MCP项目侧文件
```

数据和样本不写入镜像：

```text
malapp-judgement-data卷 → SQLite、缓存、资产库、评估参数
docker/workspace目录    → 待分析APK、图标及其他输入文件
外部模型API             → 模型甲、模型乙或Hermes主管模型
```

Hermes核心运行时没有打入当前镜像。当前机器无法连接GitHub安装官方Hermes，
因此这里只包含已经实现并验证的MCP服务、Skills和主管配置。后续应将官方Hermes
作为独立容器运行，并通过受控API或MCP访问本服务。

## 设计作用

- 代码进入不可变镜像，服务器环境保持一致。
- 约1.9GB的现有数据库不进入镜像，避免构建缓慢和数据泄漏。
- 数据卷独立存在，升级或删除容器不会删除研判历史。
- 未知APK只挂载到`/workspace`，与应用代码分离。
- 模型服务独立扩容，不必随着Web服务重复加载模型。
- 业务容器使用非root用户、只读根文件系统并删除Linux capabilities。

## 首次启动

确认Docker Desktop已经启动：

```powershell
docker info
docker compose version
```

创建环境文件并检查模型配置：

```powershell
Copy-Item .env.docker.example .env
```

Windows宿主机上的模型服务使用：

```text
http://host.docker.internal:端口/v1
```

启动：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\docker-start.ps1
```

或者直接执行：

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f malapp
```

访问：

```text
http://127.0.0.1:8765
http://127.0.0.1:8765/api/health
```

## 不接大模型时运行

保留以下设置：

```dotenv
MALAPP_USE_LOCAL_QWEN=0
MALAPP_MODEL_A_API_URL=
MALAPP_MODEL_B_API_URL=
```

系统会使用现有规则回退完成研判，适合验证页面、API和确定性分析工具。

## 连接两个自有模型

模型服务必须提供OpenAI-compatible接口：

```text
GET  /v1/models
POST /v1/chat/completions
```

`.env`示例：

```dotenv
MALAPP_MODEL_A_API_URL=http://host.docker.internal:8001/v1
MALAPP_MODEL_A_API_KEY=model-a-key
MALAPP_MODEL_A_MODEL=model-a

MALAPP_MODEL_B_API_URL=http://host.docker.internal:8002/v1
MALAPP_MODEL_B_API_KEY=model-b-key
MALAPP_MODEL_B_MODEL=model-b
```

业务代码会在模型URL存在时使用`openai_compatible` Provider。

## 分析APK

将APK放到：

```text
docker/workspace/
```

容器内路径为：

```text
/workspace/文件名.apk
```

请求示例：

```json
{
  "sample_id": "case-001",
  "apk_path": "/workspace/sample.apk",
  "engine_a_score": 80,
  "engine_b_score": 75
}
```

系统只做静态解析，不执行APK。

## 使用现有数据库

默认Compose创建新的命名卷，不会复制当前`data/mvp.db`。

需要迁移现有数据时，推荐先停止服务，再将数据库复制进命名卷。不要把数据库
写进Dockerfile或提交到镜像仓库。也可以把Compose卷改成受控宿主机目录：

```yaml
volumes:
  - ./persistent-data:/var/lib/malapp
```

然后将以下文件放入`persistent-data`：

```text
mvp.db
sample_seen.bloom
schema.json
field_mapping.json
sample_conflict.json
eval/best_params.json
```

## 备份

停止写入后备份命名卷：

```powershell
docker compose stop malapp
docker run --rm `
  -v malapp-judgement-data:/data `
  -v ${PWD}:/backup `
  alpine sh -c "tar czf /backup/malapp-data-backup.tar.gz -C /data ."
docker compose start malapp
```

生产环境建议使用数据库自身的在线备份机制。

## 更新

```powershell
docker compose build --pull
docker compose up -d
docker compose ps
```

命名卷不会因镜像更新而删除。

## 停止和删除

只停止并删除容器：

```powershell
docker compose down
```

同时删除数据卷：

```powershell
docker compose down -v
```

`down -v`会永久删除容器内研判数据库，执行前必须备份。

## 本地Qwen说明

轻量业务镜像没有安装`torch`和`transformers`，因此默认：

```dotenv
MALAPP_USE_LOCAL_QWEN=0
```

生产上推荐把Qwen部署为独立vLLM服务，然后通过模型API连接。这样可以独立分配
GPU、扩缩容和升级模型，也避免构建包含数GB权重的业务镜像。

`docker-compose.model-example.yaml`提供了Linux NVIDIA GPU服务器的结构示例，
需要替换模型路径、镜像版本和显存参数后再使用。

## 常用排查命令

```powershell
docker compose ps
docker compose logs --tail 200 malapp
docker inspect malapp-judgement
docker volume inspect malapp-judgement-data
docker compose config
```

健康状态持续为`unhealthy`时，检查端口、数据卷写权限、初始化配置文件、模型API
响应时间以及Docker Desktop分配的内存。
