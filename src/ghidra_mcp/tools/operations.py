"""搜索、分析和分类写入工具。"""

from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from ..transaction import program_transaction
from .navigation import ToolInputError


def _address(api: Any, value: str) -> Any:
    resolved = api.toAddr(value)
    if resolved is None:
        raise ToolInputError(f"无法解析地址：{value}")
    return resolved


def _data_type(program: Any, path: str) -> Any:
    value = program.getDataTypeManager().getDataType(path)
    if value is None:
        raise ToolInputError(f"数据类型不存在：{path}")
    return value


def _data_type_json(value: Any) -> dict[str, object]:
    return {
        "name": str(value.getName()),
        "path": str(value.getPathName()),
        "length": int(value.getLength()),
        "description": str(value.getDescription()),
    }


def register_operation_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def memory_search(program_id: str, hex_pattern: str, max_results: int = 100) -> list[str]:
        try:
            pattern = bytes.fromhex(hex_pattern)
        except ValueError as error:
            raise ToolInputError("hex_pattern 必须是偶数位十六进制字节") from error
        if not pattern or len(pattern) > 4096:
            raise ToolInputError("十六进制模式长度必须在 1 到 4096 字节之间")
        if not 1 <= max_results <= 1000:
            raise ToolInputError("max_results 必须在 1 到 1000 之间")
        api = workspace.get(program_id)
        results: list[str] = []
        scanned = 0
        scan_limit = 64 * 1024 * 1024
        chunk_size = 1024 * 1024
        for block in api.getCurrentProgram().getMemory().getBlocks():
            if not block.isInitialized():
                continue
            offset = 0
            carry = b""
            size = int(block.getSize())
            while offset < size and scanned < scan_limit:
                length = min(chunk_size, size - offset, scan_limit - scanned)
                raw = bytes(
                    (int(item) & 0xFF)
                    for item in api.getBytes(block.getStart().add(offset), length)
                )
                data = carry + raw
                cursor = 0
                while (found := data.find(pattern, cursor)) >= 0:
                    absolute = offset - len(carry) + found
                    results.append(str(block.getStart().add(absolute)))
                    if len(results) >= max_results:
                        return results
                    cursor = found + 1
                carry = data[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
                offset += length
                scanned += length
        return results

    def analysis_run(program_id: str) -> dict[str, int]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        manager = program.getFunctionManager()
        before = int(manager.getFunctionCount())
        with program_transaction(
            program, "Run analysis", persist=lambda: workspace.save(program_id)
        ):
            workspace.analyze(program_id)
        return {"functions_before": before, "functions_after": int(manager.getFunctionCount())}

    def data_type_get(program_id: str, path: str) -> dict[str, object]:
        program = workspace.get(program_id).getCurrentProgram()
        return _data_type_json(_data_type(program, path))

    def data_type_apply(program_id: str, address: str, path: str) -> dict[str, object]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        resolved = _address(api, address)
        value = _data_type(program, path)
        with program_transaction(
            program, "Apply data type", persist=lambda: workspace.save(program_id)
        ):
            data = program.getListing().createData(resolved, value)
        return {
            "address": str(data.getAddress()),
            "length": int(data.getLength()),
            "data_type": str(data.getDataType()),
        }

    def function_tag_update(
        program_id: str, address: str, action: str, name: str
    ) -> dict[str, object]:
        if action not in {"add", "remove"}:
            raise ToolInputError("action 必须是 add 或 remove")
        normalized = name.strip()
        if not normalized:
            raise ToolInputError("name 不得为空")
        api = workspace.get(program_id)
        function = api.getFunctionContaining(_address(api, address))
        if function is None:
            raise ToolInputError(f"地址未包含在函数中：{address}")
        program = api.getCurrentProgram()
        with program_transaction(
            program, "Update function tag", persist=lambda: workspace.save(program_id)
        ):
            if action == "add":
                function.addTag(normalized)
            else:
                function.removeTag(normalized)
        tags = sorted(function.getTags(), key=lambda item: str(item.getName()))
        return {
            "tags": [{"name": str(tag.getName()), "comment": str(tag.getComment())} for tag in tags]
        }

    def bookmark_set(
        program_id: str, address: str, kind: str, category: str, comment: str | None
    ) -> dict[str, str | None]:
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        resolved = _address(api, address)
        manager = program.getBookmarkManager()
        with program_transaction(
            program, "Set bookmark", persist=lambda: workspace.save(program_id)
        ):
            if comment is None:
                existing = manager.getBookmark(resolved, kind, category)
                if existing is not None:
                    manager.removeBookmark(existing)
            else:
                manager.setBookmark(resolved, kind, category, comment)
        return {"address": str(resolved), "type": kind, "category": category, "comment": comment}

    definitions = (
        ToolDefinition(
            "memory_search",
            """在已初始化内存中搜索精确字节模式。\n\n输入输出与副作用：输入程序会话、十六进制模式和结果上限；返回匹配地址，单次最多扫描 64 MiB；只读。\n\n何时使用：按机器码、常量或文件签名定位地址时调用；已知地址读取内容用 memory_read，文本线索用 strings_list。\n""",
            memory_search,
            mutates=False,
        ),
        ToolDefinition(
            "analysis_run",
            """对已打开程序同步运行 Ghidra 自动分析。\n\n输入输出与副作用：输入程序会话；返回分析前后函数数；按配置期限执行，超时或持久化失败时回滚本次分析。\n\n何时使用：以 analyze=false 打开后补分析或修改定义后重分析；首次打开通常直接让 program_open 执行分析。\n""",
            analysis_run,
        ),
        ToolDefinition(
            "data_type_get",
            """按完整路径读取一个数据类型。\n\n输入输出与副作用：输入程序会话和类型路径；返回名称、路径、长度与说明；只读。\n\n何时使用：应用类型前核对精确定义；按片段发现候选类型用 data_types_list。\n""",
            data_type_get,
            mutates=False,
        ),
        ToolDefinition(
            "data_type_apply",
            """在指定地址创建现有数据类型定义。\n\n输入输出与副作用：输入程序会话、地址和完整类型路径；返回创建的数据定义；事务失败自动回滚且不主动清除冲突代码单元。\n\n何时使用：已确认地址与类型且无冲突定义时调用；先发现类型用 data_types_list，查看现有定义用 data_get。\n""",
            data_type_apply,
        ),
        ToolDefinition(
            "function_tag_update",
            """精确添加或移除函数标签。\n\n输入输出与副作用：输入程序会话、函数内地址、add/remove 和完整标签名；返回更新后标签；事务失败自动回滚。\n\n何时使用：维护客观函数分类时调用；读取标签用 function_tags，修改函数名用 function_rename。\n""",
            function_tag_update,
        ),
        ToolDefinition(
            "bookmark_set",
            """设置或删除指定地址的书签。\n\n输入输出与副作用：输入程序会话、地址、类型、分类和注释；comment 为 null 时删除精确匹配书签；事务失败自动回滚。\n\n何时使用：记录待办或审查锚点时调用；保存分析正文用 comment_set。\n""",
            bookmark_set,
        ),
    )
    for definition in definitions:
        registry.register(definition)
