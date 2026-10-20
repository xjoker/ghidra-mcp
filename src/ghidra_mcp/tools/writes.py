"""函数、符号和注释的事务写工具。"""

from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from ..transaction import program_transaction
from .navigation import ToolInputError


def _user_defined_source() -> Any:
    from ghidra.program.model.symbol import SourceType

    return SourceType.USER_DEFINED


def _comment_type(value: str) -> Any:
    from ghidra.program.model.listing import CommentType

    try:
        return getattr(CommentType, value.upper())
    except AttributeError as error:
        raise ToolInputError("kind 必须是 eol、pre、post、plate 或 repeatable") from error


def _address_set(start: Any, end: Any) -> Any:
    from ghidra.program.model.address import AddressSet

    return AddressSet(start, end)


def _body_ranges(body: Any) -> list[dict[str, str]]:
    return [
        {"start": str(address_range.getMinAddress()), "end": str(address_range.getMaxAddress())}
        for address_range in body.getAddressRanges()
    ]


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"无法解析地址：{value}")
    return address


def _computed_function_body(program: Any, entry: Any) -> Any:
    """Return the body that ``createFunction(entry, name)`` would compute for a new function.

    FlatProgramAPI.createFunction runs ``CreateFunctionCmd`` with no body, which computes the body
    with this exact call (follow flow from the entry, excluding calls and other functions' entries).
    """
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.util.task import TaskMonitor

    return CreateFunctionCmd.getFunctionBody(program, entry, False, TaskMonitor.DUMMY)


def _first_overlapping_function(program: Any, body: Any) -> Any:
    functions = program.getFunctionManager().getFunctionsOverlapping(body)
    return functions.next() if functions.hasNext() else None


def _function_identity(function: Any) -> tuple[str, str]:
    """Name and entry point of an existing function, for client-facing errors (program data)."""
    return str(function.getName()), str(function.getEntryPoint())


def _name(value: str) -> str:
    name = value.strip()
    if not name:
        raise ToolInputError("name 不得为空")
    return name


def register_write_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def function_rename(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionContaining(resolved)
        if function is None:
            raise ToolInputError(f"地址未包含在函数中：{address}")
        program = api.getCurrentProgram()
        old_name = str(function.getName())
        new_name = _name(name)
        with program_transaction(
            program, "Rename function", persist=lambda: workspace.save(program_id)
        ):
            function.setName(new_name, _user_defined_source())
        return {
            "entry_point": str(function.getEntryPoint()),
            "old_name": old_name,
            "name": new_name,
        }

    def symbol_rename(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        symbol = program.getSymbolTable().getPrimarySymbol(resolved)
        if symbol is None:
            raise ToolInputError(f"地址没有主符号：{address}")
        old_name = str(symbol.getName())
        new_name = _name(name)
        with program_transaction(
            program, "Rename symbol", persist=lambda: workspace.save(program_id)
        ):
            symbol.setName(new_name, _user_defined_source())
        return {
            "address": str(symbol.getAddress()),
            "old_name": old_name,
            "name": new_name,
        }

    def comment_set(
        program_id: str, address: str, kind: str, text: str | None
    ) -> dict[str, str | None]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        normalized_kind = kind.lower()
        comment_type = _comment_type(normalized_kind)
        with program_transaction(
            program, "Set comment", persist=lambda: workspace.save(program_id)
        ):
            program.getListing().setComment(resolved, comment_type, text)
        return {"address": str(resolved), "kind": normalized_kind, "text": text}

    def function_create(program_id: str, address: str, name: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        if api.getFunctionAt(resolved) is not None:
            raise ToolInputError(f"地址已有函数：{address}")
        # CreateFunctionCmd does not refuse an entry inside another function, or a computed body
        # that runs into one: it silently carves the overlap out of the existing function, and
        # deleting the new function later leaves that range unassigned (issue #4).
        containing = api.getFunctionContaining(resolved)
        if containing is not None:
            function_name, entry_point = _function_identity(containing)
            raise ToolInputError(
                f"地址位于已有函数 {function_name}（入口 {entry_point}）的函数体内：{address}"
            )
        program = api.getCurrentProgram()
        overlapping = _first_overlapping_function(
            program, _computed_function_body(program, resolved)
        )
        if overlapping is not None:
            function_name, entry_point = _function_identity(overlapping)
            raise ToolInputError(
                f"新函数体将与已有函数 {function_name}（入口 {entry_point}）重叠：{address}"
            )
        new_name = _name(name)
        with program_transaction(
            program, "Create function", persist=lambda: workspace.save(program_id)
        ):
            function = api.createFunction(resolved, new_name)
            if function is None:
                raise RuntimeError(f"Ghidra 未能在 {address} 创建函数")
        return {"name": str(function.getName()), "entry_point": str(function.getEntryPoint())}

    def function_delete(program_id: str, address: str) -> dict[str, str]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionAt(resolved)
        if function is None:
            raise ToolInputError(f"地址不是函数入口：{address}")
        entry_point = str(function.getEntryPoint())
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Delete function", persist=lambda: workspace.save(program_id)
        ):
            api.removeFunction(function)
        return {"deleted": entry_point}

    def function_body_add(
        program_id: str, entry_point: str, start: str, end: str
    ) -> dict[str, object]:
        api = workspace.get(program_id)
        resolved_entry = _address(api, entry_point)
        resolved_start = _address(api, start)
        resolved_end = _address(api, end)
        if resolved_start.compareTo(resolved_end) > 0:
            raise ToolInputError("start 不得大于 end")
        function = api.getFunctionAt(resolved_entry)
        if function is None:
            raise ToolInputError(f"地址不是函数入口：{entry_point}")
        previous_body = function.getBody()
        previous_ranges = _body_ranges(previous_body)
        new_body = previous_body.union(_address_set(resolved_start, resolved_end))
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Add function body range", persist=lambda: workspace.save(program_id)
        ):
            function.setBody(new_body)
        return {
            "entry_point": str(function.getEntryPoint()),
            "added_range": {"start": str(resolved_start), "end": str(resolved_end)},
            "previous_body_ranges": previous_ranges,
            "body_ranges": _body_ranges(function.getBody()),
        }

    definitions = (
        ToolDefinition(
            "function_rename",
            """重命名包含指定地址的函数。

输入输出与副作用：输入程序会话、函数内地址和新名称；返回入口与新旧名称；在单个 Ghidra 事务中修改并在失败时回滚。

何时使用：已确认函数语义后赋予稳定名称；只需改非函数标签时改用 symbol_rename。
""",
            function_rename,
        ),
        ToolDefinition(
            "symbol_rename",
            """重命名指定地址的主符号。

输入输出与副作用：输入程序会话、符号地址和新名称；返回地址与新旧名称；在单个事务中修改并在失败时回滚。

何时使用：修改标签、数据或外部符号名称；目标是函数语义名称时优先使用 function_rename。
""",
            symbol_rename,
        ),
        ToolDefinition(
            "comment_set",
            """设置或删除指定地址的一类注释。

输入输出与副作用：输入程序会话、地址、注释类型和文本；返回写入内容，text 为 null 时删除；事务失败自动回滚。

何时使用：保存可验证分析结论；重命名实体时改用 function_rename 或 symbol_rename。
""",
            comment_set,
        ),
        ToolDefinition(
            "function_create",
            """在尚无函数的入口地址创建命名函数。

输入输出与副作用：输入程序会话、入口地址和名称；返回新函数名称与入口；事务失败自动回滚。入口位于已有函数体内，或 Ghidra 从入口推算的函数体会与已有函数重叠时拒绝且不修改任何函数。

何时使用：分析遗漏但已确认代码入口时调用；入口已有函数时改用 function_rename；要把地址并入已有函数时改用 function_body_add。
""",
            function_create,
        ),
        ToolDefinition(
            "function_delete",
            """删除入口地址精确匹配的函数定义。

输入输出与副作用：输入程序会话和函数入口；返回删除的入口；事务失败自动回滚，不删除底层字节。

何时使用：确认函数定义错误或误识别时调用；仅需改名时不要删除，改用 function_rename。
""",
            function_delete,
        ),
        ToolDefinition(
            "function_body_add",
            """向入口地址精确匹配的函数体添加一个已确认的地址范围。

输入输出与副作用：输入程序会话、函数入口和闭区间起止地址；返回新增范围及修改前后的完整函数体范围；在单个事务中修改并保存，范围与其他函数重叠时由 Ghidra 拒绝并回滚。

何时使用：已用控制流证据确认 detached continuation 属于目标函数时调用；归属尚不确定时先用 function_get，不得凭邻近地址猜测。
""",
            function_body_add,
        ),
    )
    for definition in definitions:
        registry.register(definition)
