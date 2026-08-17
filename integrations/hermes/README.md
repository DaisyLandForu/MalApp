# Hermes integration

该目录提供 MalApp 的 Hermes MCP 工具和编排适配器：

```text
bridge.py       领域工具到 MalApp Application 的映射
runtime.py      Hermes Orchestrator Adapter
mcp_server.py   JSON-RPC/MCP stdio 服务
skills/         主管与四领域 Agent 的 Skill 说明
```

启动 MCP 服务：

```bash
python -m integrations.hermes.mcp_server
```

`mcp.example.json` 只是模板，使用时应把命令配置为当前环境的 Python，并把工作目录指向项目根目录。Hermes 只是可选 Orchestrator；最终业务逻辑仍由 `malapp.application.judgement` 提供。
