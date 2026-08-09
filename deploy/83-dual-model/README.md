# 83 单卡双模型部署

目标服务器：`10.0.11.83`，单张 RTX 4090 24GB。

当前 APP 已经配置为访问：

- 模型甲：`http://10.0.11.83:8011/v1`，模型名 `malapp-model-a`
- 模型乙：`http://10.0.11.83:8012/v1`，模型名 `malapp-model-b`

现在失败的原因不是 APP，而是 83 上没有服务监听 `8011/8012`。本目录用于把两个 OpenAI-compatible vLLM 服务启动起来。

## 1. 先判断 83 是否有外网

在 83 上执行：

```bash
ping -c 3 223.5.5.5
curl -I https://registry-1.docker.io/v2/
```

如果失败，就不能在线拉 Docker 镜像，也不能在线下载 HuggingFace 模型，需要走离线部署。

## 2. 在线部署

如果 83 能访问 Docker Hub 和 HuggingFace：

```bash
mkdir -p /opt/malapp-dual-model
cd /opt/malapp-dual-model
# 上传本目录下所有文件到这里
cp .env.example .env
chmod +x deploy.sh check.sh
./deploy.sh
```

等待日志显示模型加载完成：

```bash
docker compose --env-file .env -f compose.yaml logs -f
```

测试：

```bash
./check.sh
```

## 3. 离线部署

如果 83 无外网，需要准备两类文件。

第一类：vLLM Docker 镜像。

在一台能联网、能运行 Docker 的机器上执行：

```bash
docker pull vllm/vllm-openai:latest
docker save vllm/vllm-openai:latest -o vllm-openai.tar
```

把 `vllm-openai.tar` 传到 83：

```bash
scp vllm-openai.tar root@10.0.11.83:/opt/malapp-dual-model/
```

第二类：模型文件。

把两个 AWQ 4-bit 模型目录放到 83：

```text
/opt/models/Qwen2.5-14B-Instruct-AWQ
/opt/models/Qwen2.5-7B-Instruct-AWQ
```

然后在 83 上修改 `.env`：

```dotenv
VLLM_IMAGE=vllm/vllm-openai:latest
HF_HOME=/opt/malapp-models/huggingface
MODEL_DIR=/opt/models

MODEL_A_ID=/models/Qwen2.5-14B-Instruct-AWQ
MODEL_A_NAME=malapp-model-a
MODEL_A_PORT=8011
MODEL_A_GPU_MEMORY_UTILIZATION=0.56

MODEL_B_ID=/models/Qwen2.5-7B-Instruct-AWQ
MODEL_B_NAME=malapp-model-b
MODEL_B_PORT=8012
MODEL_B_GPU_MEMORY_UTILIZATION=0.34

MAX_MODEL_LEN=4096
MAX_NUM_SEQS=1
```

启动：

```bash
cd /opt/malapp-dual-model
chmod +x deploy.sh check.sh
./deploy.sh
```

## 4. 如果显存不够

先把上下文降低：

```dotenv
MAX_MODEL_LEN=2048
```

如果还不够，先只启动一个服务：

```bash
docker compose --env-file .env -f compose.yaml up -d model-a
```

单张 4090 同时跑 14B 4-bit + 7B 4-bit 是紧凑方案，可以跑，但并发必须低。

## 5. APP 侧配置

APP 里保持：

```text
模型甲接口：http://10.0.11.83:8011/v1
模型甲名称：malapp-model-a
模型乙接口：http://10.0.11.83:8012/v1
模型乙名称：malapp-model-b
接口密钥：留空
```

本部署默认不启用 vLLM API key，目的是先打通内网联通。后续如果要加密钥，需要同时修改 vLLM 启动参数和 APP 里的接口密钥。

## 6. 成功标准

83 本机执行：

```bash
curl http://127.0.0.1:8011/v1/models
curl http://127.0.0.1:8012/v1/models
```

Windows 本机执行：

```powershell
Invoke-RestMethod http://10.0.11.83:8011/v1/models
Invoke-RestMethod http://10.0.11.83:8012/v1/models
```

两边都能返回模型列表后，APP 才能进行真实双模型研判。
