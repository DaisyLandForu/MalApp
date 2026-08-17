# Hermes integration

该目录只提供 MalApp 的 Hermes MCP 传输适配器：

```text
adapter.py      MCP 请求到 JudgementRequest 的转换
bridge.py       唯一权威研判工具声明
mcp_server.py   JSON-RPC/MCP stdio 服务
skills/         权威研判工具的调用说明
```

启动 MCP 服务：

```bash
python -m integrations.hermes.mcp_server
```

`mcp.example.json` 只是模板，使用时应把命令配置为当前环境的 Python，并把工作目录指向项目根目录。Hermes 不调度领域 Agent；它只把 MCP 请求转换为 `JudgementRequest`，再调用与 Web、Batch 相同的 `JudgementService`。
