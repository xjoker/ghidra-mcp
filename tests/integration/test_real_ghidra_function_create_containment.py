import os
from pathlib import Path

import pytest

from ghidra_mcp.catalog import build_default_registry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace
from ghidra_mcp.tools.navigation import ToolInputError


FIXTURE = Path(__file__).parents[1] / "fixtures" / "generated" / "libsymbolic.so"


def _ranges(workspace: ProgramWorkspace, program_id: str, entry: str) -> list[tuple[str, str]]:
    api = workspace.get(program_id)
    function = api.getFunctionAt(api.toAddr(entry))
    assert function is not None, f"no function at {entry}"
    return [
        (str(item.getMinAddress()), str(item.getMaxAddress()))
        for item in function.getBody().getAddressRanges()
    ]


def _containing(workspace: ProgramWorkspace, program_id: str, address: str) -> str | None:
    api = workspace.get(program_id)
    function = api.getFunctionContaining(api.toAddr(address))
    return None if function is None else str(function.getEntryPoint())


def _instructions(workspace: ProgramWorkspace, program_id: str, entry: str) -> list[object]:
    api = workspace.get(program_id)
    function = api.getFunctionAt(api.toAddr(entry))
    body = function.getBody()
    found = []
    instruction = api.getInstructionAt(api.toAddr(entry))
    while instruction is not None and body.contains(instruction.getMinAddress()):
        found.append(instruction)
        instruction = instruction.getNext()
    return found


@pytest.mark.integration
def test_real_function_create_refuses_to_split_or_overlap_existing_functions(
    tmp_path: Path,
) -> None:
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not FIXTURE.is_file():
        pytest.skip("先运行 scripts/build_fixtures.py")

    workspace = ProgramWorkspace(
        GhidraRuntime(Path(install_value)), project_location=tmp_path / "projects"
    )
    tools = {tool.name: tool.handler for tool in build_default_registry(workspace).enabled_tools()}
    try:
        program_id = tools["program_open"](str(FIXTURE), analyze=True)["program_id"]
        functions = tools["functions_list"](program_id, offset=0, limit=1000)

        # 1. An entry inside an existing body (issue #4) is rejected and the body stays whole.
        target = next(item for item in functions if item["name"] == "fixture_symbolic")
        entry = target["entry_point"]
        target_body = _ranges(workspace, program_id, entry)
        inner = str(_instructions(workspace, program_id, entry)[2].getAddress())
        with pytest.raises(ToolInputError) as inside:
            tools["function_create"](program_id, inner, "issue4_inner")
        assert str(inside.value) == (
            f"地址位于已有函数 fixture_symbolic（入口 {entry}）的函数体内：{inner}"
        )
        assert _ranges(workspace, program_id, entry) == target_body
        assert _containing(workspace, program_id, inner) == entry

        # 2. An entry outside every function whose computed body runs into an existing
        #    function is rejected too; Ghidra would otherwise carve the overlap out of it.
        donor = next(
            item
            for item in functions
            if item["name"] != "fixture_symbolic"
            and not item["external"]
            and not item["thunk"]
            and len(_instructions(workspace, program_id, item["entry_point"])) >= 6
            and _instructions(workspace, program_id, item["entry_point"])[3].getFallThrough()
            is not None
        )
        donor_entry = donor["entry_point"]
        gap = _instructions(workspace, program_id, donor_entry)[3]
        gap_address = str(gap.getAddress())
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        donor_function = api.getFunctionAt(api.toAddr(donor_entry))
        from ghidra.program.model.address import AddressSet

        carved = AddressSet(donor_function.getBody())
        carved.delete(gap.getMinAddress(), gap.getMaxAddress())
        transaction = program.startTransaction("test setup: carve a gap into a function body")
        donor_function.setBody(carved)
        program.endTransaction(transaction, True)
        workspace.save(program_id)
        donor_body = _ranges(workspace, program_id, donor_entry)
        assert _containing(workspace, program_id, gap_address) is None
        with pytest.raises(ToolInputError) as overlap:
            tools["function_create"](program_id, gap_address, "issue4_gap")
        assert str(overlap.value) == (
            f"新函数体将与已有函数 {donor['name']}（入口 {donor_entry}）重叠：{gap_address}"
        )
        assert _ranges(workspace, program_id, donor_entry) == donor_body
        assert _containing(workspace, program_id, gap_address) is None

        tools["program_close"](program_id)
        reopened = tools["program_open"](str(FIXTURE), analyze=False)["program_id"]
        assert _ranges(workspace, reopened, entry) == target_body
        assert _containing(workspace, reopened, inner) == entry
        assert _ranges(workspace, reopened, donor_entry) == donor_body
        assert _containing(workspace, reopened, gap_address) is None

        # 3. Recreating a deleted function at its own entry keeps working.
        tools["function_delete"](reopened, entry)
        assert tools["function_create"](reopened, entry, "issue4_recreated") == {
            "name": "issue4_recreated",
            "entry_point": entry,
        }
        assert _containing(workspace, reopened, inner) == entry

        # 4. Flow that only reaches another function's entry is not an overlap: Ghidra stops the
        #    computed body there, so creating in front of a function is still allowed.
        tools["function_delete"](reopened, entry)
        tools["function_create"](reopened, inner, "issue4_tail")
        tail_body = _ranges(workspace, reopened, inner)
        assert tools["function_create"](reopened, entry, "issue4_head")["entry_point"] == entry
        assert _ranges(workspace, reopened, inner) == tail_body
        head_body = _ranges(workspace, reopened, entry)
        assert head_body[0][0] == entry
        assert all(end < inner for _, end in head_body)
        tools["program_close"](reopened)
    finally:
        workspace.close_all()


def _all_bodies(workspace: ProgramWorkspace, program_id: str) -> dict[str, list[tuple[str, str]]]:
    manager = workspace.get(program_id).getCurrentProgram().getFunctionManager()
    bodies = {}
    functions = manager.getFunctions(True)
    while functions.hasNext():
        function = functions.next()
        bodies[str(function.getEntryPoint())] = [
            (str(item.getMinAddress()), str(item.getMaxAddress()))
            for item in function.getBody().getAddressRanges()
        ]
    return bodies


@pytest.mark.integration
def test_real_function_create_on_undisassembled_bytes_cannot_carve_a_function_later(
    tmp_path: Path,
) -> None:
    # Review M1: on bytes that are not disassembled yet, getFunctionBody sees a one-byte body;
    # the next analysis_run then grows the new function and carves its neighbour.
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not FIXTURE.is_file():
        pytest.skip("先运行 scripts/build_fixtures.py")

    workspace = ProgramWorkspace(
        GhidraRuntime(Path(install_value)), project_location=tmp_path / "projects"
    )
    tools = {tool.name: tool.handler for tool in build_default_registry(workspace).enabled_tools()}
    try:
        program_id = tools["program_open"](str(FIXTURE), analyze=True)["program_id"]
        functions = tools["functions_list"](program_id, offset=0, limit=1000)
        mix = next(item for item in functions if item["name"] == "mix")["entry_point"]
        gap = _instructions(workspace, program_id, mix)[3]
        gap_address = str(gap.getAddress())
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        from ghidra.program.model.address import AddressSet

        mix_function = api.getFunctionAt(api.toAddr(mix))
        carved = AddressSet(mix_function.getBody())
        carved.delete(gap.getMinAddress(), gap.getMaxAddress())
        transaction = program.startTransaction("test setup: code that analysis missed")
        mix_function.setBody(carved)
        api.clearListing(gap.getMinAddress(), gap.getMaxAddress())
        program.endTransaction(transaction, True)
        workspace.save(program_id)
        assert api.getInstructionAt(gap.getMinAddress()) is None
        before = _all_bodies(workspace, program_id)

        # 1. The would-be body is predicted by pseudo-disassembly, so the create is rejected.
        with pytest.raises(ToolInputError) as overlap:
            tools["function_create"](program_id, gap_address, "missed_entry")
        assert str(overlap.value) == f"新函数体将与已有函数 mix（入口 {mix}）重叠：{gap_address}"
        assert api.getInstructionAt(gap.getMinAddress()) is None, "the check must not disassemble"
        assert _all_bodies(workspace, program_id) == before

        # 2. ... and analysis afterwards does not change any function either, also after reopen.
        tools["analysis_run"](program_id)
        assert _all_bodies(workspace, program_id) == before
        tools["program_close"](program_id)
        reopened = tools["program_open"](str(FIXTURE), analyze=False)["program_id"]
        assert _all_bodies(workspace, reopened) == before
        assert _containing(workspace, reopened, gap_address) is None

        # 3. A whole function that analysis "missed" (deleted and its code cleared) can still be
        #    created on undisassembled bytes; analysis grows it without touching the others.
        target = next(item for item in functions if item["name"] == "fixture_symbolic")
        entry = target["entry_point"]
        api = workspace.get(reopened)
        program = api.getCurrentProgram()
        original = api.getFunctionAt(api.toAddr(entry)).getBody()
        others = {key: value for key, value in _all_bodies(workspace, reopened).items()}
        others.pop(entry)
        transaction = program.startTransaction("test setup: a function analysis missed")
        api.removeFunction(api.getFunctionAt(api.toAddr(entry)))
        api.clearListing(original)
        program.endTransaction(transaction, True)
        workspace.save(reopened)
        assert api.getInstructionAt(api.toAddr(entry)) is None
        assert tools["function_create"](reopened, entry, "issue4_missed")["entry_point"] == entry
        tools["analysis_run"](reopened)
        after = _all_bodies(workspace, reopened)
        assert after.pop(entry)[0][0] == entry
        assert after == others
        tools["program_close"](reopened)
    finally:
        workspace.close_all()


_BLOCK = 0x300000
_VICTIM = 0x100
_MIDDLE = _VICTIM + 0x09  # an instruction boundary (a nop) in the middle of V
_NORETURN = 0x300


def _rel32(at: int, size: int, to: int) -> bytes:
    import struct

    return struct.pack("<i", to - (at + size))


def _call_layout() -> dict[int, bytes]:
    """Code at 0x300000 + offset; everything else in the block is int3 (0xcc)."""
    import struct

    middle = _BLOCK + _MIDDLE
    return {
        # V: push rbp; mov rbp,rsp; mov eax,imm32; 11 nops; pop rbp; ret (0x100-0x115).
        _VICTIM: b"\x55\x48\x89\xe5" + b"\xb8\x90\x90\x90\x90" + b"\x90" * 11 + b"\x5d\xc3",
        # direct: call <middle of V>; ret
        0x000: b"\xe8" + _rel32(_BLOCK, 5, middle) + b"\xc3",
        # indirect: call qword ptr [rip+disp] -> pointer at 0x080 (undefined bytes); ret
        0x010: b"\xff\x15" + struct.pack("<i", 0x080 - (0x010 + 6)) + b"\xc3",
        0x080: struct.pack("<Q", middle),
        # conditional: test edi,edi; jz +5; call <middle of V>; ret
        0x020: b"\x85\xff\x74\x05" + b"\xe8" + _rel32(_BLOCK + 0x024, 5, middle) + b"\xc3",
        # noreturn (review N2): call N; jmp <middle of V>, never reached because N does not return
        0x040: b"\xe8"
        + _rel32(_BLOCK + 0x040, 5, _BLOCK + _NORETURN)
        + b"\xe9"
        + _rel32(_BLOCK + 0x045, 5, middle),
        # control: call <V's entry>; ret
        0x060: b"\xe8" + _rel32(_BLOCK + 0x060, 5, _BLOCK + _VICTIM) + b"\xc3",
        # N: hlt; ret, marked noreturn
        _NORETURN: b"\xf4\xc3",
    }


@pytest.mark.integration
def test_real_function_create_checks_call_targets_without_following_calls(
    tmp_path: Path,
) -> None:
    # Review round 2 N1: an entry on undisassembled bytes that calls into the middle of V is
    # created, and the next analysis_run creates a function at the call target and splits V.
    # N2: a call to a noreturn function, followed by bytes that jump into V, must stay allowed.
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not FIXTURE.is_file():
        pytest.skip("先运行 scripts/build_fixtures.py")

    workspace = ProgramWorkspace(
        GhidraRuntime(Path(install_value)), project_location=tmp_path / "projects"
    )
    tools = {tool.name: tool.handler for tool in build_default_registry(workspace).enabled_tools()}
    try:
        program_id = tools["program_open"](str(FIXTURE), analyze=True)["program_id"]
        api = workspace.get(program_id)
        program = api.getCurrentProgram()
        from ghidra.app.cmd.disassemble import DisassembleCommand
        from ghidra.util.task import TaskMonitor

        def at(offset: int) -> object:
            return api.toAddr(_BLOCK + offset)

        raw = bytearray(b"\xcc" * 0x1000)
        for offset, code in _call_layout().items():
            raw[offset : offset + len(code)] = code
        transaction = program.startTransaction("test setup: synthetic code block")
        try:
            memory = program.getMemory()
            block = memory.createInitializedBlock(
                "probe", at(0), 0x1000, 0, TaskMonitor.DUMMY, False
            )
            block.setExecute(True)
            memory.setBytes(at(0), bytes(raw))
            for offset in (_VICTIM, _NORETURN):
                DisassembleCommand(at(offset), None, True).applyTo(program, TaskMonitor.DUMMY)
            api.createFunction(at(_VICTIM), "V")
            api.createFunction(at(_NORETURN), "N").setNoReturn(True)
        finally:
            program.endTransaction(transaction, True)
        workspace.save(program_id)
        tools["analysis_run"](program_id)
        victim = str(at(_VICTIM))
        victim_body = _ranges(workspace, program_id, victim)
        assert victim_body == [(victim, str(at(_VICTIM + 0x15)))]
        entries = {"direct": 0x000, "indirect": 0x010, "conditional": 0x020}
        allowed = {"noreturn": 0x040, "control": 0x060}
        for offset in [*entries.values(), *allowed.values()]:
            assert api.getInstructionAt(at(offset)) is None, "entries must be undisassembled"
        before = _all_bodies(workspace, program_id)

        # 1. A call whose target is inside V (not its entry) is rejected: direct, through a
        #    pointer in memory, and behind a conditional branch. The check writes nothing.
        for name, offset in entries.items():
            address = str(at(offset))
            with pytest.raises(ToolInputError) as rejected:
                tools["function_create"](program_id, address, f"n1_{name}")
            assert str(rejected.value) == (
                f"新函数中的调用目标位于已有函数 V（入口 {victim}）的函数体中部：{address}"
            ), name
            assert api.getInstructionAt(at(offset)) is None, "the check must not disassemble"
        assert _all_bodies(workspace, program_id) == before

        # 2. A call to V's entry, and a noreturn call whose dead fall-through jumps into V, are
        #    allowed: calls are not followed into the callee, and nothing after N is reached.
        for name, offset in allowed.items():
            address = str(at(offset))
            created = tools["function_create"](program_id, address, f"ok_{name}")
            assert created == {"name": f"ok_{name}", "entry_point": address}

        # 3. Analysis afterwards does not touch V (no function at the middle), also after reopen.
        tools["analysis_run"](program_id)
        after = _all_bodies(workspace, program_id)
        for offset in allowed.values():
            assert after.pop(str(at(offset)))[0][0] == str(at(offset))
        assert after == before
        assert _containing(workspace, program_id, str(at(_MIDDLE))) == victim
        tools["program_close"](program_id)
        reopened = tools["program_open"](str(FIXTURE), analyze=False)["program_id"]
        assert _ranges(workspace, reopened, victim) == victim_body
        assert workspace.get(reopened).getFunctionAt(at(_MIDDLE)) is None
        reopened_bodies = _all_bodies(workspace, reopened)
        for offset in allowed.values():
            reopened_bodies.pop(str(at(offset)))
        assert reopened_bodies == before
        tools["program_close"](reopened)
    finally:
        workspace.close_all()
