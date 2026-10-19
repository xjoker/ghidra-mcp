"""任务导向 MCP 工具的唯一注册入口。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from mcp.types import ToolAnnotations


class RegistryError(ValueError):
    """工具注册违反唯一性或命名契约。"""


class DescriptionError(ValueError):
    """工具说明缺少调用决策所需的信息。"""


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    handler: Callable[..., object]
    group: str = "default"
    contract_version: int = 1
    annotations: ToolAnnotations | None = None
    # 默认按写操作对待，使忘记标注的工具退化为串行而不是并发写坏程序。
    mutates: bool = True

    def __post_init__(self) -> None:
        if self.contract_version < 1:
            raise RegistryError("contract_version 必须大于或等于 1")
        for required in ("输入输出与副作用：", "何时使用："):
            if required not in self.description:
                raise DescriptionError(f"工具 {self.name} 的说明缺少“{required.rstrip('：')}”段")


class ToolRegistry:
    def __init__(self, enabled_groups: tuple[str, ...] = ()) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self._enabled_groups = frozenset(("default", *enabled_groups))

    def register(self, tool: ToolDefinition) -> None:
        lowered = tool.name.lower()
        if lowered.endswith("_batch") or lowered.endswith("_bulk"):
            raise RegistryError("batch/bulk 别名不允许注册；由任务工具直接接受数组")
        if tool.name in self._tools:
            raise RegistryError(f"tool {tool.name!r} already registered")
        self._tools[tool.name] = tool
        if len(self.enabled_tools()) > 40 and tool.group == "default":
            del self._tools[tool.name]
            raise RegistryError("默认工具不得超过 40 个")

    def enabled_tools(self) -> tuple[ToolDefinition, ...]:
        return tuple(tool for tool in self._tools.values() if tool.group in self._enabled_groups)
