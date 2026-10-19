"""程序会话生命周期工具。"""

from pathlib import Path

from mcp.types import ToolAnnotations

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace


def register_program_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def program_open(binary_path: str, analyze: bool = True) -> dict[str, str]:
        program_id = workspace.open(Path(binary_path), analyze=analyze)
        return {"program_id": program_id, "path": str(Path(binary_path).resolve())}

    def program_list() -> list[dict[str, str]]:
        return workspace.list_open()

    def program_info(program_id: str) -> dict[str, str]:
        return workspace.describe(program_id)

    def program_close(program_id: str) -> dict[str, str]:
        workspace.close(program_id)
        return {"closed": program_id}

    definitions = (
        ToolDefinition(
            "program_open",
            """打开二进制并建立独立程序会话。

输入输出与副作用：输入本地二进制路径和是否分析；返回程序会话标识与规范路径；会创建或打开 Ghidra 项目数据。

何时使用：分析任何二进制前首先调用；已有会话时改用 program_list，不要重复打开。
""",
            program_open,
        ),
        ToolDefinition(
            "program_list",
            """列出当前进程拥有的程序会话。

输入输出与副作用：无输入；返回程序会话标识与二进制路径列表；只读。

何时使用：恢复上下文或选择目标程序时调用；需要程序架构详情时改用 program_info。
""",
            program_list,
            mutates=False,
        ),
        ToolDefinition(
            "program_info",
            """读取一个程序的格式、语言和地址范围。

输入输出与副作用：输入程序会话标识；返回名称、语言、编译器、格式和地址边界；只读。

何时使用：开始分析时建立程序级上下文；只需寻找现有会话时改用 program_list。
""",
            program_info,
            mutates=False,
        ),
        ToolDefinition(
            "program_close",
            """关闭程序会话并释放对应 Ghidra 上下文。

输入输出与副作用：输入程序会话标识；返回已关闭标识；先保存项目，保存成功后才关闭并释放资源；保存失败时保留会话并返回错误。

何时使用：完成该程序的全部操作后调用；仍需继续读取或修改时不要关闭。
""",
            program_close,
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=True,
                idempotentHint=False,
                openWorldHint=False,
            ),
        ),
    )
    for definition in definitions:
        registry.register(definition)
