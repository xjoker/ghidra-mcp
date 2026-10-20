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
