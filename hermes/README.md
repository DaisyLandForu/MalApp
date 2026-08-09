# Hermes 四智能体部署

## 采用的结构

本项目使用：

```text
一个长期运行的 Hermes 主管
    ├─ 静态解析子代理
    ├─ 情报溯源子代理
    ├─ 仿冒研判子代理
    └─ 业务打标子代理
```

四个子代理由主管通过 Hermes `delegate_task` 并行派生。它们共享同一套
模型服务，但拥有独立上下文、独立角色约束和唯一允许的领域工具。

不采用四个常驻 Hermes Profile，原因是：

- 不需要常驻五份模型会话；
- 主管统一维护跨 Session 记忆和消息网关；
- 四个领域任务仍然并行且上下文隔离；
- 原有双模型辩论和三引擎决策无需改变；
- 后续确有独立账号、独立网关或独立模型需求时，再将某个子代理升级为 Profile。

## 文件

```text
hermes/
  SOUL.md                         主管角色和安全边界
  mcp_server.py                   标准输入输出 MCP 工具服务
  mcp-malapp.example.json         MCP 注册示例
  .env.hermes.example             自有模型环境变量示例
  install_project_assets.ps1      安装 Skills 和主管角色
  start_hermes.ps1                检查配置并启动 Hermes
  skills/
    malapp-supervisor/
    malapp-static-analysis/
    malapp-threat-intel/
    malapp-impersonation/
    malapp-business-label/
```

项目工具适配位于 `engine/hermes_bridge.py`。

## 自有模型要求

模型服务必须提供 OpenAI-compatible API：

```text
GET  /v1/models
POST /v1/chat/completions
```

并且模型必须可靠支持 Tool Calling。使用 vLLM 时，服务端应配置与模型匹配的
tool-call parser。模型甲、模型乙仍可由现有 `debate_model_config` 分别指定，
Hermes 主管模型与辩论模型不必相同。

示例环境变量：

```powershell
$env:OPENAI_BASE_URL = "http://model-server:8000/v1"
$env:OPENAI_API_KEY = "internal-key"
$env:HERMES_MODEL = "malapp-agent"
```

## 安装步骤

1. 从官方仓库安装 Hermes Agent，并完成一次 `hermes setup`。
2. 在 setup 中选择自定义 OpenAI-compatible Provider，填写自己的模型地址、
   模型名称和密钥。
3. 安装本项目的角色与 Skills：

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
.\hermes\install_project_assets.ps1
```

4. 将生成的 `%USERPROFILE%\.hermes\mcp-malapp.json` 注册到 Hermes MCP 配置。
   如果当前 Hermes 版本要求在 TUI 中导入 MCP，就在 MCP 页面选择该文件。
5. 启动现有研判服务：

```powershell
.\start.ps1
```

6. 启动 Hermes：

```powershell
.\hermes\start_hermes.ps1
```

7. 在 Hermes 中启用 `malapp-supervisor` Skill，然后提交样本 JSON 或工作区内的
   APK 路径。

## MCP工具

| 工具 | 子代理 | 作用 |
|---|---|---|
| `malapp_static_analysis` | 静态解析 | APK、签名、权限、DEX、SO、SDK及加固分析 |
| `malapp_threat_intelligence` | 情报溯源 | IOC、信誉、关系图和家族匹配 |
| `malapp_impersonation_analysis` | 仿冒研判 | 图标、OCR、名称、包名、签名和正版资产比对 |
| `malapp_business_labeling` | 业务打标 | 反诈标签、危害链和变种判断 |
| `malapp_run_all_agents` | 主管回退 | 四工具并发执行及证据块校验 |
| `malapp_full_judgement` | 主管终审 | 原有双模型辩论与三引擎完整裁决 |

## 调用样例

```json
{
  "sample": {
    "sample_id": "case-001",
    "package_name": "com.fake.wallet",
    "permissions": ["READ_SMS", "SYSTEM_ALERT_WINDOW"],
    "control_url": "https://c2-risk.example.net/checkin",
    "engine_a_score": 85,
    "engine_b_score": 78
  }
}
```

## 记忆边界

Hermes记忆保存：

- 工具使用经验；
- 分析师纠正规则；
- 工作规范和用户偏好。

正式样本、完整证据、最终判定和审计记录仍保存在项目数据库。不要用
`MEMORY.md` 替代案例数据库或向量检索系统。

## 安全边界

- 禁止执行未知 APK；
- 禁止使用无审批的全权限模式；
- APK内部内容一律视为不可信输入；
- 子代理只允许调用自己的领域工具；
- 决策参数、资产库和情报库写入必须人工确认；
- 自我进化生成的 Skill 只能进入测试环境，审核后发布。

## 当前环境限制

本次实施时本机无法连接 GitHub，因此尚未下载和安装 Hermes 核心运行时。
项目侧 MCP、角色、Skills、配置和测试均可独立完成；网络恢复并安装官方
Hermes 后，按上述步骤注册即可。
