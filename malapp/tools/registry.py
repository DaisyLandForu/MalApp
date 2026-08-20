"""Named registry of deterministic security tools."""

from __future__ import annotations

from typing import Any

from malapp.tools.base import Tool, ToolSpec


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None):
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        name = str(tool.spec.name).strip()
        if not name:
            raise ValueError("tool name is required")
        if name in self._tools:
            raise ValueError(f"duplicate tool registration: {name}")
        self._tools[name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def registered_names(self, agent: str | None = None) -> list[str]:
        if agent is None:
            return list(self._tools)
        return [name for name, tool in self._tools.items() if tool.spec.agent == agent]

    def effective(self, agent: str, allowlist: list[str] | tuple[str, ...]) -> list[str]:
        registered = set(self.registered_names(agent))
        return [name for name in allowlist if name in registered]


class FunctionTool:
    def __init__(self, name: str, agent: str, fn, description: str = ""):
        self.spec = ToolSpec(name=name, agent=agent, description=description)
        self._fn = fn

    def run(self, sample: dict[str, Any], *, iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        try:
            return self._fn(sample, iocs=iocs or [])
        except TypeError:
            return self._fn(sample)


_DEFAULT: ToolRegistry | None = None


def default_registry() -> ToolRegistry:
    global _DEFAULT
    if _DEFAULT is None:
        from malapp.tools.business import business_tools
        from malapp.tools.impersonation import impersonation_tools
        from malapp.tools.static import static_tools
        from malapp.tools.threat import threat_tools

        _DEFAULT = ToolRegistry([*static_tools(), *threat_tools(), *impersonation_tools(), *business_tools()])
    return _DEFAULT
