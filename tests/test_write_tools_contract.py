import asyncio
from dataclasses import dataclass

import pytest

from ghidra_mcp.registry import ToolRegistry
from ghidra_mcp.tools.navigation import ToolInputError


class FakeAddress(str):
    def compareTo(self, other: object) -> int:
        return (self > str(other)) - (self < str(other))


class FakeProgram:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []
        self.listing = FakeListing(self)
        self.symbol_table = FakeSymbolTable(self)
        self.undo_name: str | None = None
        self.function_manager: FakeFunctionManager | None = None
        # Bodies that Ghidra would compute for a new function at an entry; default is one byte.
        self.computed_bodies: dict[str, FakeBody] = {}
        self.computed_body_requests: list[str] = []

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


def _tools(workspace: FakeWorkspace, monkeypatch: pytest.MonkeyPatch):
    from ghidra_mcp.tools import writes

    monkeypatch.setattr(writes, "_user_defined_source", lambda: "USER_DEFINED")
    monkeypatch.setattr(writes, "_comment_type", lambda value: value.upper())
    monkeypatch.setattr(writes, "_address_set", lambda start, end: FakeBody([(start, end)]))
    monkeypatch.setattr(
        writes, "_computed_function_body", lambda program, entry: program.computed_body(entry)
    )
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
    monkeypatch.setattr(writes, "_user_defined_source", lambda: "USER_DEFINED")
    monkeypatch.setattr(
        writes, "_computed_function_body", lambda program, entry: program.computed_body(entry)
    )
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
