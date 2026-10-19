"""数据、注释、变量、中间表示与标记的只读检查工具。"""

from itertools import islice
from typing import Any, Iterable

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from .navigation import ToolInputError


def _page(values: Iterable[Any], offset: int, limit: int) -> list[Any]:
    if offset < 0 or not 1 <= limit <= 1000:
        raise ToolInputError("offset 不得小于 0，limit 必须在 1 到 1000 之间")
    return list(islice(values, offset, offset + limit))


def _address(api: Any, value: str) -> Any:
    resolved = api.toAddr(value)
    if resolved is None:
        raise ToolInputError(f"无法解析地址：{value}")
    return resolved


def _function(api: Any, value: str) -> Any:
    function = api.getFunctionContaining(_address(api, value))
    if function is None:
        raise ToolInputError(f"地址未包含在函数中：{value}")
    return function


def _data_json(data: Any) -> dict[str, object]:
    return {
        "address": str(data.getAddress()),
        "length": int(data.getLength()),
        "data_type": str(data.getDataType()),
        "value": str(data.getDefaultValueRepresentation()),
    }


def _comment_types() -> dict[str, Any]:
    from ghidra.program.model.listing import CommentType

    return {
        "eol": CommentType.EOL,
        "pre": CommentType.PRE,
        "post": CommentType.POST,
        "plate": CommentType.PLATE,
        "repeatable": CommentType.REPEATABLE,
    }


def _is_parameter(variable: Any) -> bool:
    from ghidra.program.model.listing import Parameter

    return isinstance(variable, Parameter)


def register_inspection_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def data_list(
        program_id: str, contains_type: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        values = workspace.get(program_id).getCurrentProgram().getListing().getDefinedData(True)
        if contains_type is not None:
            needle = contains_type.casefold()
            values = (item for item in values if needle in str(item.getDataType()).casefold())
        return [_data_json(item) for item in _page(values, offset, limit)]

    def data_get(program_id: str, address: str) -> dict[str, object]:
        api = workspace.get(program_id)
        data = api.getCurrentProgram().getListing().getDefinedDataContaining(_address(api, address))
        if data is None:
            raise ToolInputError(f"地址没有已定义数据：{address}")
        return _data_json(data)

    def comments_list(program_id: str, offset: int = 0, limit: int = 100) -> list[dict[str, str]]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        listing = program.getListing()
        addresses = listing.getCommentAddressIterator(program.getMemory(), True)

        def comments() -> Iterable[dict[str, str]]:
            for address in addresses:
                for name, kind in _comment_types().items():
                    text = listing.getComment(kind, address)
                    if text is not None:
                        yield {"address": str(address), "kind": name, "text": str(text)}

        return _page(comments(), offset, limit)

    def variables_list(program_id: str, address: str) -> list[dict[str, object]]:
        api = workspace.get(program_id)
        return [
            {
                "name": str(variable.getName()),
                "data_type": str(variable.getDataType()),
                "storage": str(variable.getVariableStorage()),
                "role": "parameter" if _is_parameter(variable) else "local",
                "comment": None if variable.getComment() is None else str(variable.getComment()),
            }
            for variable in _function(api, address).getAllVariables()
        ]

    def pcode_list(program_id: str, address: str, limit: int = 1000) -> list[dict[str, object]]:
        if not 1 <= limit <= 10_000:
            raise ToolInputError("limit 必须在 1 到 10000 之间")
        api = workspace.get(program_id)
        function = _function(api, address)
        instructions = (
            api.getCurrentProgram().getListing().getInstructions(function.getBody(), True)
        )
        return [
            {
                "address": str(instruction.getAddress()),
                "ops": [str(op) for op in instruction.getPcode()],
            }
            for instruction in islice(instructions, limit)
        ]

    def data_types_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        values = (
            workspace.get(program_id).getCurrentProgram().getDataTypeManager().getAllDataTypes()
        )
        if contains is not None:
            needle = contains.casefold()
            values = (item for item in values if needle in str(item.getPathName()).casefold())
        return [
            {
                "name": str(item.getName()),
                "path": str(item.getPathName()),
                "length": int(item.getLength()),
                "description": str(item.getDescription()),
            }
            for item in _page(values, offset, limit)
        ]

    def function_tags(program_id: str, address: str) -> list[dict[str, str]]:
        api = workspace.get(program_id)
        tags = sorted(_function(api, address).getTags(), key=lambda item: str(item.getName()))
        return [{"name": str(tag.getName()), "comment": str(tag.getComment())} for tag in tags]

    def bookmarks_list(program_id: str, offset: int = 0, limit: int = 100) -> list[dict[str, str]]:
        values = (
            workspace.get(program_id)
            .getCurrentProgram()
            .getBookmarkManager()
            .getBookmarksIterator()
        )
        return [
            {
                "address": str(item.getAddress()),
                "type": str(item.getTypeString()),
                "category": str(item.getCategory()),
                "comment": str(item.getComment()),
            }
            for item in _page(values, offset, limit)
        ]

    definitions = (
        ToolDefinition(
            "data_list",
            """分页列出已定义数据并可按类型过滤。\n\n输入输出与副作用：输入程序会话、可选类型片段和分页参数；返回地址、长度、类型和值；只读。\n\n何时使用：浏览结构化数据定义时调用；只看字符串用 strings_list，读取原始字节用 memory_read。\n""",
            data_list,
            mutates=False,
        ),
        ToolDefinition(
            "data_get",
            """读取包含指定地址的已定义数据。\n\n输入输出与副作用：输入程序会话和地址；返回数据起点、长度、类型和值；只读。\n\n何时使用：已知数据内地址并需完整定义时调用；批量浏览时改用 data_list。\n""",
            data_get,
            mutates=False,
        ),
        ToolDefinition(
            "comments_list",
            """分页列出程序中的全部标准注释。\n\n输入输出与副作用：输入程序会话和分页参数；返回地址、注释类型与文本；只读。\n\n何时使用：恢复既有分析笔记时调用；新增或删除注释用 comment_set。\n""",
            comments_list,
            mutates=False,
        ),
        ToolDefinition(
            "variables_list",
            """列出函数参数与局部变量。\n\n输入输出与副作用：输入程序会话和函数内地址；返回名称、类型、存储、角色与注释；只读。\n\n何时使用：检查函数原型和局部状态时调用；函数级身份信息用 function_get。\n""",
            variables_list,
            mutates=False,
        ),
        ToolDefinition(
            "pcode_list",
            """读取函数指令对应的 Ghidra P-code。\n\n输入输出与副作用：输入程序会话、函数内地址和指令上限；返回每条指令地址及 P-code 操作；只读。\n\n何时使用：做架构无关语义分析时调用；高层 C 文本用 decompile_function，机器指令用 instructions_list。\n""",
            pcode_list,
            mutates=False,
        ),
        ToolDefinition(
            "data_types_list",
            """分页列出程序数据类型并可按路径过滤。\n\n输入输出与副作用：输入程序会话、可选路径片段和分页参数；返回名称、路径、长度与说明；只读。\n\n何时使用：查找可应用的现有类型时调用；查看某地址当前数据定义用 data_get。\n""",
            data_types_list,
            mutates=False,
        ),
        ToolDefinition(
            "function_tags",
            """列出指定函数已分配的标签。\n\n输入输出与副作用：输入程序会话和函数内地址；返回标签名称与说明；只读。\n\n何时使用：读取函数分类状态时调用；名称语义本身用 function_get。\n""",
            function_tags,
            mutates=False,
        ),
        ToolDefinition(
            "bookmarks_list",
            """分页列出程序书签。\n\n输入输出与副作用：输入程序会话和分页参数；返回地址、类型、分类与说明；只读。\n\n何时使用：浏览人工标记的待办和关注点时调用；程序注释应使用 comments_list。\n""",
            bookmarks_list,
            mutates=False,
        ),
    )
    for definition in definitions:
        registry.register(definition)
