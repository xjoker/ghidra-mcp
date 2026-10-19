"""指令、符号、引用与字符串只读工具。"""

from itertools import chain, islice
from typing import Any, Iterable

from ..registry import ToolDefinition, ToolRegistry
from ..runtime import ProgramWorkspace
from .navigation import ToolInputError


def _page(values: Iterable[Any], *, offset: int, limit: int) -> list[Any]:
    if offset < 0:
        raise ToolInputError("offset 不得小于 0")
    if not 1 <= limit <= 1000:
        raise ToolInputError("limit 必须在 1 到 1000 之间")
    return list(islice(values, offset, offset + limit))


def _address(api: Any, value: str) -> Any:
    address = api.toAddr(value)
    if address is None:
        raise ToolInputError(f"无法解析地址：{value}")
    return address


def _reference_json(reference: Any, direction: str, listing: Any) -> dict[str, object]:
    source_instruction = listing.getInstructionContaining(reference.getFromAddress())
    inferred = bool(
        source_instruction is not None
        and source_instruction.getFlowType().isComputed()
        and reference.getReferenceType().isFlow()
    )
    return {
        "from": str(reference.getFromAddress()),
        "to": str(reference.getToAddress()),
        "type": str(reference.getReferenceType()),
        "operand_index": int(reference.getOperandIndex()),
        "primary": bool(reference.isPrimary()),
        "direction": direction,
        "provenance": "ghidra_reference_manager",
        "source": str(reference.getSource()),
        "confidence": "inferred" if inferred else "high",
    }


def _new_pseudo_disassembler(program: Any) -> Any:
    from ghidra.app.util import PseudoDisassembler

    return PseudoDisassembler(program)


def register_listing_tools(registry: ToolRegistry, workspace: ProgramWorkspace) -> None:
    def instructions_list(
        program_id: str,
        address: str | None = None,
        offset: int = 0,
        limit: int = 100,
        require_exact_start: bool = False,
    ) -> dict[str, object]:
        api = workspace.get(program_id)
        listing = api.getCurrentProgram().getListing()
        requested = None if address is None else _address(api, address)
        iterator = iter(
            listing.getInstructions(True)
            if requested is None
            else listing.getInstructions(requested, True)
        )
        first = next(iterator, None)
        effective = None if first is None else first.getAddress()
        exact_start = None if requested is None else effective == requested
        skipped_bytes = (
            None
            if requested is None
            or effective is None
            or effective.getAddressSpace() != requested.getAddressSpace()
            else int(effective.subtract(requested))
        )
        if require_exact_start and exact_start is not True:
            next_address = "无" if effective is None else str(effective)
            raise ToolInputError(f"请求地址不是已定义指令起点；下一条已定义指令：{next_address}")
        instructions = _page(
            () if first is None else chain((first,), iterator), offset=offset, limit=limit
        )
        instruction_json = [
            {
                "address": str(instruction.getAddress()),
                "mnemonic": str(instruction.getMnemonicString()),
                "operands": [
                    str(instruction.getDefaultOperandRepresentation(index))
                    for index in range(instruction.getNumOperands())
                ],
                "length": int(instruction.getLength()),
            }
            for instruction in instructions
        ]
        return {
            "requested_address": None if requested is None else str(requested),
            "effective_address": None if effective is None else str(effective),
            "returned_start_address": (
                None if not instructions else str(instructions[0].getAddress())
            ),
            "exact_start": exact_start,
            "skipped_bytes": skipped_bytes,
            "instructions": instruction_json,
        }

    def symbols_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        program = workspace.get(program_id).getCurrentProgram()
        symbols = program.getSymbolTable().getAllSymbols(True)
        if contains is not None:
            symbols = (symbol for symbol in symbols if contains in str(symbol.getName()))
        return [
            {
                "name": str(symbol.getName()),
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource()),
                "primary": bool(symbol.isPrimary()),
            }
            for symbol in _page(symbols, offset=offset, limit=limit)
        ]

    def references_list(
        program_id: str,
        address: str,
        direction: str = "both",
        limit: int = 100,
        scan_start: str | None = None,
        scan_end: str | None = None,
    ) -> dict[str, object]:
        if direction not in {"from", "to", "both"}:
            raise ToolInputError("direction 必须是 from、to 或 both")
        if not 1 <= limit <= 1000:
            raise ToolInputError("limit 必须在 1 到 1000 之间")
        api = workspace.get(program_id)
        resolved = _address(api, address)
        program = api.getCurrentProgram()
        manager = program.getReferenceManager()
        listing = program.getListing()

        def references() -> Iterable[dict[str, object]]:
            if direction in {"from", "both"}:
                for reference in manager.getReferencesFrom(resolved):
                    yield _reference_json(reference, "from", listing)
            if direction in {"to", "both"}:
                for reference in manager.getReferencesTo(resolved):
                    yield _reference_json(reference, "to", listing)

        found = list(islice(references(), limit + 1))
        truncated = len(found) > limit
        found = found[:limit]
        scan = None
        if (scan_start is None) != (scan_end is None):
            raise ToolInputError("scan_start 与 scan_end 必须同时提供")
        if scan_start is not None and direction == "from":
            raise ToolInputError("伪反汇编扫描仅用于 to 或 both 方向")
        if scan_start is not None and scan_end is not None:
            start = _address(api, scan_start)
            end = _address(api, scan_end)
            if start.getAddressSpace() != end.getAddressSpace() or end.subtract(start) < 0:
                raise ToolInputError("扫描范围必须位于同一地址空间且 scan_end 不小于 scan_start")
            alignment = int(program.getLanguage().getInstructionAlignment())
            if start.getOffset() % alignment or end.getOffset() % alignment:
                raise ToolInputError("scan_start 与 scan_end 必须满足语言指令对齐")
            candidate_count = int(end.subtract(start)) // alignment + 1
            if candidate_count > 4_096:
                raise ToolInputError("扫描范围最多包含 4096 个对齐地址；更大范围请分块查询")
            pseudo = _new_pseudo_disassembler(program)
            existing_pairs = {(item["from"], item["to"]) for item in found}
            decoded = 0
            failures = 0
            scanned = 0
            for index in range(candidate_count):
                if len(found) >= limit:
                    truncated = True
                    break
                candidate = start.add(index * alignment)
                scanned += 1
                if (
                    listing.getInstructionContaining(candidate) is not None
                    or listing.getDefinedDataContaining(candidate) is not None
                ):
                    continue
                try:
                    instruction = pseudo.disassemble(candidate)
                except Exception:
                    failures += 1
                    continue
                if instruction is None:
                    failures += 1
                    continue
                decoded += 1
                if direction not in {"to", "both"}:
                    continue
                flows = instruction.getDefaultFlows() or ()
                if resolved not in flows:
                    continue
                pair = (str(candidate), str(resolved))
                if pair in existing_pairs:
                    continue
                existing_pairs.add(pair)
                found.append(
                    {
                        "from": pair[0],
                        "to": pair[1],
                        "type": str(instruction.getFlowType()),
                        "operand_index": -1,
                        "primary": False,
                        "direction": "to",
                        "provenance": "pseudo_disassembly",
                        "source": "PSEUDO_DISASSEMBLY",
                        "confidence": "inferred",
                    }
                )
            if len(found) > limit:
                truncated = True
                found = found[:limit]
            scan = {
                "start": str(start),
                "end": str(end),
                "instruction_alignment": alignment,
                "candidate_addresses": candidate_count,
                "scanned_addresses": scanned,
                "decoded_instructions": decoded,
                "decode_failures": failures,
                "complete": failures == 0 and scanned == candidate_count,
            }
        return {
            "requested_address": str(resolved),
            "references": found,
            "coverage": {
                "mode": ("listing_only" if scan is None else "listing_and_pseudo_disassembly"),
                "scan": scan,
            },
            "incomplete": True,
            "incomplete_reasons": [
                "ghidra_reference_manager_depends_on_defined_listing",
                *(["pseudo_scan_is_explicit_range_only"] if scan is not None else []),
            ],
            "truncated": truncated,
        }

    def strings_list(
        program_id: str, contains: str | None = None, offset: int = 0, limit: int = 100
    ) -> list[dict[str, object]]:
        listing = workspace.get(program_id).getCurrentProgram().getListing()
        values = (data for data in listing.getDefinedData(True) if data.hasStringValue())
        if contains is not None:
            values = (
                data for data in values if contains in str(data.getDefaultValueRepresentation())
            )
        return [
            {
                "address": str(data.getAddress()),
                "length": int(data.getLength()),
                "data_type": str(data.getDataType()),
                "value": str(data.getDefaultValueRepresentation()),
            }
            for data in _page(values, offset=offset, limit=limit)
        ]

    definitions = (
        ToolDefinition(
            "instructions_list",
            """从程序起点或指定地址分页读取指令。

输入输出与副作用：输入程序会话、可选起始地址和分页参数；返回请求起点、Ghidra 实际起点、跳过字节数和指令列表；require_exact_start 为 true 时拒绝未定义指令起点；只读。

何时使用：检查具体机器指令或验证反编译结果时调用；只需原始字节时改用 memory_read。
            """,
            instructions_list,
            contract_version=2,
            mutates=False,
        ),
        ToolDefinition(
            "symbols_list",
            """分页列出符号并可按名称片段过滤。

输入输出与副作用：输入程序会话、可选名称片段和分页参数；返回名称、地址、类型、来源与主符号状态；只读。

何时使用：按名称发现函数、标签或外部符号时调用；只需函数集合时优先使用 functions_list。
""",
            symbols_list,
            mutates=False,
        ),
        ToolDefinition(
            "references_list",
            """读取指定地址的入向、出向或双向引用。

输入输出与副作用：输入程序会话、地址、方向、数量上限及可选伪反汇编扫描范围；返回引用、来源/置信度、覆盖范围、不完整与截断状态；只读，不修改 Listing。

何时使用：追踪调用者、被调用者或数据交叉引用时调用；需要完整函数集合时改用 functions_list。
""",
            references_list,
            contract_version=2,
            mutates=False,
        ),
        ToolDefinition(
            "strings_list",
            """分页列出已定义字符串并可按内容过滤。

输入输出与副作用：输入程序会话、可选内容片段和分页参数；返回地址、长度、数据类型与显示值；只读。

何时使用：从文本线索定位行为和引用时调用；搜索任意原始字节模式时不应使用本工具。
""",
            strings_list,
            mutates=False,
        ),
    )
    for definition in definitions:
        registry.register(definition)
