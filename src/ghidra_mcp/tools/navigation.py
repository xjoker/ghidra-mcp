"""内存与函数的只读导航工具。"""

from itertools import islice
from typing import Any

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace


class ToolInputError(ValueError):
    """工具输入不能解析或超出公开边界。"""


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"无法解析地址：{value}")
    return address


def _function_json(function: Any) -> dict[str, object]:
    return {
        "name": str(function.getName()),
        "entry_point": str(function.getEntryPoint()),
        "signature": str(function.getSignature()),
        "external": bool(function.isExternal()),
        "thunk": bool(function.isThunk()),
    }


def register_navigation_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def memory_blocks_list(program_id: str) -> list[dict[str, object]]:
        memory = workspace.get(program_id).getCurrentProgram().getMemory()
        return [
            {
                "name": str(block.getName()),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": int(block.getSize()),
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
                "initialized": bool(block.isInitialized()),
            }
            for block in memory.getBlocks()
        ]

    def memory_read(
        program_id: str,
        address: str,
        length: int,
        interpret: bool = False,
        unit_size: int = 8,
        byte_order: str = "little",
    ) -> dict[str, object]:
        if not 1 <= length <= 1_048_576:
            raise ToolInputError("length 必须在 1 到 1048576 之间")
        if unit_size not in {1, 2, 4, 8}:
            raise ToolInputError("unit_size 必须是 1、2、4 或 8")
        if byte_order not in {"little", "big"}:
            raise ToolInputError("byte_order 必须是 little 或 big")
        if interpret and length > 4096:
            raise ToolInputError("解释型 memory_read 的 length 不得超过 4096")
        api = workspace.get(program_id)
        resolved = _address(api, address)
        data = bytes((int(value) & 0xFF) for value in api.getBytes(resolved, length))
        result: dict[str, object] = {
            "address": str(resolved),
            "length": len(data),
            "hex": data.hex(),
        }
        if not interpret:
            return result
        complete_length = len(data) - (len(data) % unit_size)
        result.update(
            {
                "ascii": "".join(chr(value) if 32 <= value < 127 else "." for value in data),
                "unit_size": unit_size,
                "byte_order": byte_order,
                "unsigned_values": [
                    int.from_bytes(data[offset : offset + unit_size], byte_order)
                    for offset in range(0, complete_length, unit_size)
                ],
                "trailing_hex": data[complete_length:].hex(),
            }
        )
        return result

    def functions_list(
        program_id: str, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        if offset < 0:
            raise ToolInputError("offset 不得小于 0")
        if not 1 <= limit <= 1000:
            raise ToolInputError("limit 必须在 1 到 1000 之间")
        program = workspace.get(program_id).getCurrentProgram()
        functions = program.getFunctionManager().getFunctions(True)
        return [_function_json(function) for function in islice(functions, offset, offset + limit)]

    def function_get(program_id: str, address: str) -> dict[str, object]:
        api = workspace.get(program_id)
        resolved = _address(api, address)
        function = api.getFunctionContaining(resolved)
        if function is None:
            return {
                "requested_address": str(resolved),
                "resolution": "unassigned",
                "function": None,
                "reason": "address_not_in_ghidra_function_body",
            }
        return {
            "requested_address": str(resolved),
            "resolution": "contained",
            "function": _function_json(function),
            "reason": None,
        }

    definitions = (
        ToolDefinition(
            "memory_blocks_list",
            """列出程序的全部内存块及访问属性。

输入输出与副作用：输入程序会话标识；返回块名、地址范围、大小和读写执行属性；只读。

何时使用：判断代码与数据布局或选择读取范围时调用；读取实际字节时改用 memory_read。
""",
            memory_blocks_list,
            mutates=False,
        ),
        ToolDefinition(
            "memory_read",
            """从程序内存读取有界字节序列。

输入输出与副作用：输入程序会话标识、地址和长度；默认返回十六进制字节；可选解释最多 4096 字节为 ASCII 和指定字节序的 1/2/4/8 字节无符号值；只读，原始读取最多 1 MiB。

何时使用：需要原始字节、字符串线索、整数或指针候选时调用；只需查看内存布局时改用 memory_blocks_list，机器指令用 instructions_list。
""",
            memory_read,
            mutates=False,
        ),
        ToolDefinition(
            "functions_list",
            """按地址顺序分页列出已定义函数。

输入输出与副作用：输入程序会话标识、偏移和数量；返回名称、入口、签名及外部或 thunk 属性；只读。

何时使用：浏览函数集合或寻找候选目标时调用；已知函数内地址并需单项详情时改用 function_get。
""",
            functions_list,
            mutates=False,
        ),
        ToolDefinition(
            "function_get",
            """读取包含指定地址的函数详情。

输入输出与副作用：输入程序会话标识和地址；返回 contained 或 unassigned 解析状态，命中时包含函数详情，未命中时明确说明地址不在 Ghidra Function body；只读。

何时使用：已知地址并需要所属函数时调用；需要遍历或分页发现函数时改用 functions_list。
            """,
            function_get,
            contract_version=2,
            mutates=False,
        ),
    )
    for definition in definitions:
        registry.register(definition)
