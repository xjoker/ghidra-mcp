import asyncio
import sys
import types
from dataclasses import dataclass, field

import pytest

from ghidra_mcp.registry import ToolRegistry
from ghidra_mcp.tools.navigation import ToolInputError


class FakeAddress(str):
    def compareTo(self, other: object) -> int:
        return (self > str(other)) - (self < str(other))

    def isMemoryAddress(self) -> bool:
        return True


@dataclass
class FakeFlowType:
    call: bool = False

    def isCall(self) -> bool:
        return self.call


@dataclass
class FakeInstruction:
    """Listing or pseudo-disassembled instruction; addresses are fixed-width hex strings."""

    start: str
    end: str
    fall_through: str | None = None
    flows: tuple[str, ...] = ()
    call: bool = False

    def getMinAddress(self) -> FakeAddress:
        return FakeAddress(self.start)

    def getMaxAddress(self) -> FakeAddress:
        return FakeAddress(self.end)

    def getFallThrough(self) -> FakeAddress | None:
        return None if self.fall_through is None else FakeAddress(self.fall_through)

    def getFlows(self) -> list[FakeAddress]:
        return [FakeAddress(flow) for flow in self.flows]

    def getFlowType(self) -> FakeFlowType:
        return FakeFlowType(self.call)


class FakePseudoDisassembler:
    """Decodes every address as a one-byte terminal instruction unless the program says else."""

    def __init__(self, program: "FakeProgram") -> None:
        self.program = program

    def disassemble(self, address: str) -> FakeInstruction:
        self.program.pseudo_requests.append(str(address))
        if address in self.program.undecodable:
            raise RuntimeError("UnknownInstructionException")
        return self.program.pseudo.get(address, FakeInstruction(address, address))


@dataclass
class FakeCreateFunctionCmd:
    """Stands in for ghidra.app.cmd.function.CreateFunctionCmd and records its arguments."""

    calls: list[tuple[object, ...]] = field(default_factory=list)

    def getFunctionBody(
        self, program: "FakeProgram", entry: str, include_other_functions: object, monitor: object
    ) -> "FakeBody":
        self.calls.append((program, entry, include_other_functions, monitor))
        return program.computed_body(entry)


DUMMY_MONITOR = object()


class FakeProgram:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []
        self.listing = FakeListing(self)
        self.symbol_table = FakeSymbolTable(self)
        self.undo_name: str | None = None
        self.function_manager: FakeFunctionManager | None = None
        # Bodies that CreateFunctionCmd.getFunctionBody would compute; default is one byte.
        self.computed_bodies: dict[str, FakeBody] = {}
        self.computed_body_requests: list[str] = []
        # Pseudo-disassembly of not yet disassembled bytes (see FakePseudoDisassembler).
        self.pseudo: dict[str, FakeInstruction] = {}
        self.undecodable: set[str] = set()
        self.pseudo_requests: list[str] = []

    def startTransaction(self, description: str) -> int:
        self.events.append(("start", description))
        return len(self.events)

    def endTransaction(self, transaction_id: int, commit: bool) -> None:
        self.events.append(("end", transaction_id, commit))
        if commit:
            self.undo_name = str(self.events[transaction_id - 1][1])

    def canUndo(self) -> bool:
        return self.undo_name is not None

    def getUndoName(self) -> str:
        return self.undo_name or ""

    def undo(self) -> None:
        self.events.append(("undo", self.undo_name))
        self.undo_name = None

    def getListing(self) -> "FakeListing":
        return self.listing

    def getSymbolTable(self) -> "FakeSymbolTable":
        return self.symbol_table

    def getFunctionManager(self) -> "FakeFunctionManager":
        assert self.function_manager is not None
        return self.function_manager

    def computed_body(self, entry: str) -> "FakeBody":
        self.computed_body_requests.append(entry)
        return self.computed_bodies.get(entry, FakeBody([(entry, entry)]))


@dataclass
class FakeFunction:
    program: FakeProgram
    name: str = "FUN_00400010"
    entry: str = "00400010"
    fail_rename: bool = False
    body: "FakeBody | None" = None

    def getName(self) -> str:
        return self.name

    def getEntryPoint(self) -> str:
        return self.entry

    def setName(self, name: str, source: object) -> None:
        if self.fail_rename:
            raise RuntimeError("rename failed")
        self.program.events.append(("function_name", name, source))
        self.name = name

    def getBody(self) -> "FakeBody":
        return self.body or FakeBody([("00400010", "0040001f")])

    def setBody(self, body: "FakeBody") -> None:
        self.program.events.append(("function_body", body.ranges))
        self.body = body


@dataclass
class FakeRange:
    start: str
    end: str

    def getMinAddress(self) -> str:
        return self.start

    def getMaxAddress(self) -> str:
        return self.end


@dataclass
class FakeBody:
    ranges: list[tuple[str, str]]

    def getAddressRanges(self) -> list[FakeRange]:
        return [FakeRange(start, end) for start, end in self.ranges]

    def union(self, other: "FakeBody") -> "FakeBody":
        return FakeBody([*self.ranges, *other.ranges])

    def addRange(self, start: str, end: str) -> None:
        self.ranges.append((str(start), str(end)))

    def intersects(self, other: "FakeBody") -> bool:
        return any(
            start <= other_end and other_start <= end
            for start, end in self.ranges
            for other_start, other_end in other.ranges
        )


class FakeIterator:
    """Java-style iterator, as returned by FunctionManager.getFunctionsOverlapping."""

    def __init__(self, items: list[object]) -> None:
        self.items = list(items)

    def hasNext(self) -> bool:
        return bool(self.items)

    def next(self) -> object:
        return self.items.pop(0)


class FakeFunctionManager:
    def __init__(self, api: "FakeAPI") -> None:
        self.api = api

    def getFunctionAt(self, address: str) -> "FakeFunction | None":
        return self.api.getFunctionAt(address)

    def getFunctionsOverlapping(self, body: FakeBody) -> FakeIterator:
        functions = [self.api.function] if self.api.function is not None else []
        return FakeIterator(
            [function for function in functions if function.getBody().intersects(body)]
        )


class FakeSymbol:
    def __init__(self, program: FakeProgram) -> None:
        self.program = program
        self.name = "label_1"

    def getName(self) -> str:
        return self.name

    def getAddress(self) -> str:
        return "00400020"

    def setName(self, name: str, source: object) -> None:
        self.program.events.append(("symbol_name", name, source))
        self.name = name


class FakeSymbolTable:
    def __init__(self, program: FakeProgram) -> None:
        self.symbol = FakeSymbol(program)

    def getPrimarySymbol(self, address: str) -> FakeSymbol | None:
        return self.symbol if address == "00400020" else None


class FakeListing:
    def __init__(self, program: FakeProgram) -> None:
        self.program = program
        self.instructions: dict[str, FakeInstruction] = {}
        self.defined_data: set[str] = set()

    def getInstructionAt(self, address: str) -> FakeInstruction | None:
        return self.instructions.get(address)

    def getInstructionContaining(self, address: str) -> FakeInstruction | None:
        return next(
            (item for item in self.instructions.values() if item.start <= address <= item.end),
            None,
        )

    def getDefinedDataContaining(self, address: str) -> str | None:
        return address if address in self.defined_data else None

    def setComment(self, address: str, kind: object, text: str | None) -> None:
        self.program.events.append(("comment", address, kind, text))


class FakeAPI:
    def __init__(self, *, fail_rename: bool = False, forget_deleted: bool = False) -> None:
        self.program = FakeProgram()
        self.program.function_manager = FakeFunctionManager(self)
        self.function: FakeFunction | None = FakeFunction(self.program, fail_rename=fail_rename)
        self.forget_deleted = forget_deleted

    def getCurrentProgram(self) -> FakeProgram:
        return self.program

    def toAddr(self, address: str) -> str | None:
        return FakeAddress(address) if address.startswith("0040") else None

    def getFunctionContaining(self, address: str) -> FakeFunction | None:
        return self.function if address in {"00400010", "00400011", "0040001f"} else None

    def getFunctionAt(self, address: str) -> FakeFunction | None:
        return self.function if address == "00400010" else None

    def createFunction(self, address: str, name: str) -> FakeFunction:
        self.program.events.append(("create", address, name))
        return FakeFunction(self.program, name=name, entry=address)

    def removeFunction(self, function: FakeFunction) -> None:
        self.program.events.append(("delete", function.entry))
        if self.forget_deleted:
            self.function = None


class FakeWorkspace:
    def __init__(
        self, *, fail_rename: bool = False, fail_save: bool = False, forget_deleted: bool = False
    ) -> None:
        self.api = FakeAPI(fail_rename=fail_rename, forget_deleted=forget_deleted)
        self.saved: list[str] = []
        self.fail_save = fail_save

    def get(self, program_id: str) -> FakeAPI:
        assert program_id == "program-1"
        return self.api

    def save(self, program_id: str) -> None:
        self.saved.append(program_id)
        if self.fail_save:
            raise RuntimeError("disk unavailable")


def _install_fake_ghidra(monkeypatch: pytest.MonkeyPatch) -> FakeCreateFunctionCmd:
    """Fake only the Ghidra modules, so the real _computed_function_body and the real
    _predicted_function_body run against the fakes and their arguments are observable."""
    from ghidra_mcp.tools import writes

    command = FakeCreateFunctionCmd()
    modules = {
        name: types.ModuleType(name)
        for name in ("ghidra", "ghidra.app", "ghidra.app.cmd", "ghidra.util")
    }
    modules["ghidra.app.cmd.function"] = types.ModuleType("ghidra.app.cmd.function")
    modules["ghidra.app.cmd.function"].CreateFunctionCmd = command  # type: ignore[attr-defined]
    modules["ghidra.util.task"] = types.ModuleType("ghidra.util.task")
    modules["ghidra.util.task"].TaskMonitor = types.SimpleNamespace(  # type: ignore[attr-defined]
        DUMMY=DUMMY_MONITOR
    )
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(writes, "_user_defined_source", lambda: "USER_DEFINED")
    monkeypatch.setattr(writes, "_new_address_set", lambda: FakeBody([]))
    monkeypatch.setattr(writes, "_new_pseudo_disassembler", FakePseudoDisassembler)
    return command


def _tools(workspace: FakeWorkspace, monkeypatch: pytest.MonkeyPatch):
    from ghidra_mcp.tools import writes

    workspace.api.program.create_function_cmd = _install_fake_ghidra(monkeypatch)
    monkeypatch.setattr(writes, "_comment_type", lambda value: value.upper())
    monkeypatch.setattr(writes, "_address_set", lambda start, end: FakeBody([(start, end)]))
    registry = ToolRegistry()
    writes.register_write_tools(registry, workspace)
    return {tool.name: tool.handler for tool in registry.enabled_tools()}


def test_write_tools_commit_successful_transactions(monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = FakeWorkspace()
    tools = _tools(workspace, monkeypatch)

    assert list(tools) == [
        "function_rename",
        "symbol_rename",
        "comment_set",
        "function_create",
        "function_delete",
        "function_body_add",
    ]
    assert tools["function_rename"]("program-1", "00400011", "worker")["name"] == "worker"
    assert tools["symbol_rename"]("program-1", "00400020", "target")["name"] == "target"
    assert tools["comment_set"]("program-1", "00400020", "eol", "checked") == {
        "address": "00400020",
        "kind": "eol",
        "text": "checked",
    }
    assert tools["function_create"]("program-1", "00400030", "created") == {
        "name": "created",
        "entry_point": "00400030",
    }
    assert tools["function_delete"]("program-1", "00400010") == {"deleted": "00400010"}
    assert tools["function_body_add"]("program-1", "00400010", "00400030", "0040003f") == {
        "entry_point": "00400010",
        "added_range": {"start": "00400030", "end": "0040003f"},
        "previous_body_ranges": [{"start": "00400010", "end": "0040001f"}],
        "body_ranges": [
            {"start": "00400010", "end": "0040001f"},
            {"start": "00400030", "end": "0040003f"},
        ],
    }
    ends = [event for event in workspace.api.program.events if event[0] == "end"]
    assert len(ends) == 6
    assert all(event[2] is True for event in ends)
    assert workspace.saved == ["program-1"] * 6


def test_function_body_add_requires_exact_function_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _tools(FakeWorkspace(), monkeypatch)

    with pytest.raises(Exception, match="函数入口"):
        tools["function_body_add"]("program-1", "00400011", "00400030", "0040003f")


def test_write_tool_rolls_back_when_mutation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = FakeWorkspace(fail_rename=True)
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(RuntimeError, match="rename failed"):
        tools["function_rename"]("program-1", "00400010", "worker")

    assert workspace.api.program.events[-1][0] == "end"
    assert workspace.api.program.events[-1][2] is False
    assert workspace.saved == []


def test_write_tool_rolls_back_when_persistence_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = FakeWorkspace(fail_save=True)
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(RuntimeError, match="disk unavailable"):
        tools["function_rename"]("program-1", "00400010", "worker")

    assert workspace.api.program.events[-1] == ("undo", "Rename function")
    assert workspace.saved == ["program-1"]


def _created(workspace: FakeWorkspace) -> list[tuple[object, ...]]:
    return [event for event in workspace.api.program.events if event[0] == "create"]


@pytest.mark.parametrize("address", ["00400011", "0040001f"])
def test_function_create_rejects_an_address_inside_an_existing_function_body(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    workspace = FakeWorkspace()
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(ToolInputError) as raised:
        tools["function_create"]("program-1", address, "inner")

    message = str(raised.value)
    assert message == f"地址位于已有函数 FUN_00400010（入口 00400010）的函数体内：{address}"
    assert "/" not in message
    assert workspace.api.program.events == []
    assert workspace.saved == []


def test_function_create_still_rejects_an_existing_entry_with_the_old_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = FakeWorkspace()
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(ToolInputError, match="^地址已有函数：00400010$"):
        tools["function_create"]("program-1", "00400010", "again")

    assert workspace.api.program.events == []


def test_function_create_succeeds_at_a_free_address(monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = FakeWorkspace()
    workspace.api.program.computed_bodies["00400030"] = FakeBody([("00400030", "0040003f")])
    tools = _tools(workspace, monkeypatch)

    assert tools["function_create"]("program-1", "00400030", "created") == {
        "name": "created",
        "entry_point": "00400030",
    }
    assert workspace.api.program.computed_body_requests == ["00400030"]
    assert _created(workspace) == [("create", "00400030", "created")]
    assert workspace.saved == ["program-1"]


def test_function_create_succeeds_when_the_computed_body_ends_just_before_a_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = FakeWorkspace()
    workspace.api.program.computed_bodies["00400000"] = FakeBody([("00400000", "0040000f")])
    tools = _tools(workspace, monkeypatch)

    assert tools["function_create"]("program-1", "00400000", "before")["entry_point"] == "00400000"
    assert _created(workspace) == [("create", "00400000", "before")]


def test_function_create_succeeds_at_the_entry_of_a_deleted_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = FakeWorkspace(forget_deleted=True)
    workspace.api.program.computed_bodies["00400010"] = FakeBody([("00400010", "0040001f")])
    tools = _tools(workspace, monkeypatch)

    assert tools["function_delete"]("program-1", "00400010") == {"deleted": "00400010"}
    assert tools["function_create"]("program-1", "00400010", "recreated") == {
        "name": "recreated",
        "entry_point": "00400010",
    }
    assert _created(workspace) == [("create", "00400010", "recreated")]
    assert workspace.saved == ["program-1", "program-1"]


@pytest.mark.parametrize(
    "computed",
    [
        [("00400008", "00400013")],
        [("00400008", "0040000b"), ("0040001c", "00400024")],
        [("00400004", "0040002f")],
    ],
    ids=["runs-into-body", "non-contiguous-tail", "covers-whole-function"],
)
def test_function_create_rejects_a_computed_body_that_overlaps_an_existing_function(
    monkeypatch: pytest.MonkeyPatch, computed: list[tuple[str, str]]
) -> None:
    workspace = FakeWorkspace()
    entry = computed[0][0]
    workspace.api.program.computed_bodies[entry] = FakeBody(computed)
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(ToolInputError) as raised:
        tools["function_create"]("program-1", entry, "overlapping")

    assert str(raised.value) == f"新函数体将与已有函数 FUN_00400010（入口 00400010）重叠：{entry}"
    assert workspace.api.program.computed_body_requests == [entry]
    assert workspace.api.program.events == []
    assert workspace.saved == []


def test_function_create_containment_errors_reach_mcp_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session

    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app
    from ghidra_mcp.tools import writes

    workspace = FakeWorkspace()
    workspace.api.program.computed_bodies["00400008"] = FakeBody([("00400008", "00400013")])
    _install_fake_ghidra(monkeypatch)
    registry = ToolRegistry()
    writes.register_write_tools(registry, workspace)
    executor = GhidraToolExecutor()
    app = create_mcp_app(registry, host="127.0.0.1", port=8765, tool_executor=executor)

    async def exercise() -> list[object]:
        async with create_connected_server_and_client_session(app._mcp_server) as client:
            return [
                await client.call_tool(
                    "function_create",
                    {"program_id": "program-1", "address": address, "name": "probe"},
                )
                for address in ("00400011", "00400008", "00400030")
            ]

    try:
        inside, overlap, free = asyncio.run(exercise())
    finally:
        executor.shutdown()

    def text(result: object) -> str:
        return "\n".join(getattr(item, "text", "") for item in result.content)  # type: ignore[attr-defined]

    assert inside.isError is True
    assert "地址位于已有函数 FUN_00400010（入口 00400010）的函数体内：00400011" in text(inside)
    assert overlap.isError is True
    assert "新函数体将与已有函数 FUN_00400010（入口 00400010）重叠：00400008" in text(overlap)
    assert free.isError is False
    assert free.structuredContent == {"name": "probe", "entry_point": "00400030"}
    assert _created(workspace) == [("create", "00400030", "probe")]
    assert workspace.saved == ["program-1"]


def test_function_create_computes_the_body_exactly_like_create_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FlatProgramAPI.createFunction -> CreateFunctionCmd(name, entry, null, ...) computes the body
    # with getFunctionBody(program, entry, false, monitor): flow must stop at other functions.
    workspace = FakeWorkspace()
    tools = _tools(workspace, monkeypatch)

    tools["function_create"]("program-1", "00400030", "created")

    (call,) = workspace.api.program.create_function_cmd.calls
    program, entry, include_other_functions, monitor = call
    assert program is workspace.api.program
    assert entry == "00400030"
    assert include_other_functions is False
    assert monitor is DUMMY_MONITOR


@pytest.mark.parametrize(
    ("pseudo", "listing"),
    [
        ({"00400008": FakeInstruction("00400008", "0040000b", flows=("00400014",))}, True),
        (
            {
                "00400008": FakeInstruction("00400008", "0040000b", fall_through="0040000c"),
                "0040000c": FakeInstruction("0040000c", "0040000e", fall_through="00400011"),
            },
            False,
        ),
    ],
    ids=["jmp-into-disassembled-body", "falls-into-undisassembled-body"],
)
def test_function_create_rejects_an_undisassembled_entry_whose_flow_reaches_a_function(
    monkeypatch: pytest.MonkeyPatch, pseudo: dict[str, FakeInstruction], listing: bool
) -> None:
    # Issue #4 review M1: the entry is not disassembled, so getFunctionBody sees one byte, but
    # the next analysis_run would grow the function into FUN_00400010 and carve it.
    workspace = FakeWorkspace()
    workspace.api.program.pseudo.update(pseudo)
    if listing:
        workspace.api.program.listing.instructions["00400014"] = FakeInstruction(
            "00400014", "00400017", fall_through="00400018"
        )
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(ToolInputError) as raised:
        tools["function_create"]("program-1", "00400008", "missed_entry")

    assert str(raised.value) == "新函数体将与已有函数 FUN_00400010（入口 00400010）重叠：00400008"
    assert workspace.api.program.pseudo_requests[0] == "00400008"
    assert workspace.api.program.events == []
    assert workspace.saved == []


@pytest.mark.parametrize(
    ("pseudo", "data", "undecodable", "not_decoded"),
    [
        (
            {"00400008": FakeInstruction("00400008", "0040000f", fall_through="00400010")},
            (),
            (),
            "00400010",
        ),
        (
            {
                "00400000": FakeInstruction(
                    "00400000", "00400004", fall_through="00400005", flows=("00400014",), call=True
                )
            },
            (),
            (),
            "00400014",
        ),
        (
            {"00400000": FakeInstruction("00400000", "00400003", fall_through="00400004")},
            ("00400004",),
            (),
            "00400004",
        ),
        (
            {"00400000": FakeInstruction("00400000", "00400003", fall_through="00400004")},
            (),
            ("00400004",),
            None,
        ),
    ],
    ids=["stops-at-function-entry", "does-not-follow-calls", "stops-at-data", "stops-at-bad-bytes"],
)
def test_function_create_allows_an_undisassembled_entry_whose_flow_stays_clear(
    monkeypatch: pytest.MonkeyPatch,
    pseudo: dict[str, FakeInstruction],
    data: tuple[str, ...],
    undecodable: tuple[str, ...],
    not_decoded: str | None,
) -> None:
    workspace = FakeWorkspace()
    workspace.api.program.pseudo.update(pseudo)
    workspace.api.program.listing.defined_data.update(data)
    workspace.api.program.undecodable.update(undecodable)
    entry = next(iter(pseudo))
    tools = _tools(workspace, monkeypatch)

    assert tools["function_create"]("program-1", entry, "clear")["entry_point"] == entry
    assert _created(workspace) == [("create", entry, "clear")]
    if not_decoded is not None:
        assert not_decoded not in workspace.api.program.pseudo_requests


@pytest.mark.parametrize("blocker", ["undecodable", "data", "inside-instruction"])
def test_function_create_rejects_an_entry_that_is_not_decodable_code(
    monkeypatch: pytest.MonkeyPatch, blocker: str
) -> None:
    workspace = FakeWorkspace()
    program = workspace.api.program
    if blocker == "undecodable":
        program.undecodable.add("00400031")
    elif blocker == "data":
        program.listing.defined_data.add("00400031")
    else:
        program.listing.instructions["00400030"] = FakeInstruction("00400030", "00400033")
    tools = _tools(workspace, monkeypatch)

    with pytest.raises(ToolInputError, match="^入口处的字节无法解码为指令：00400031$"):
        tools["function_create"]("program-1", "00400031", "not_code")

    assert program.events == []
    assert program.pseudo_requests == (["00400031"] if blocker == "undecodable" else [])


def test_function_create_rejects_a_predicted_body_over_the_instruction_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ghidra_mcp.tools import writes

    workspace = FakeWorkspace()
    workspace.api.program.pseudo.update(
        {
            "00400030": FakeInstruction("00400030", "00400030", fall_through="00400031"),
            "00400031": FakeInstruction("00400031", "00400031", fall_through="00400032"),
        }
    )
    tools = _tools(workspace, monkeypatch)
    monkeypatch.setattr(writes, "_MAX_PREDICTED_INSTRUCTIONS", 2)

    with pytest.raises(
        ToolInputError, match="^从入口推算的函数体超过指令数上限，拒绝创建：00400030$"
    ):
        tools["function_create"]("program-1", "00400030", "huge")

    assert workspace.api.program.events == []
