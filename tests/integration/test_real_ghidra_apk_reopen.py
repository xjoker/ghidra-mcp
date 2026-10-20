"""Real-Ghidra check that an APK reopens the program its import stored (issue #3).

Ghidra's ``ApkLoader`` stores the program as ``/classes.dex`` (one program per DEX file),
not under the import name, so reopening used to miss it and import an unanalysed copy.
Needs ``GHIDRA_INSTALL_DIR`` and the F-Droid sample described in tests/fixtures/README.md;
the test is skipped when either is missing.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import zipfile

import pytest

from ghidra_mcp.catalog import build_default_registry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace, _persistent_project_name

SAMPLE = (
    Path(__file__).parents[1] / "fixtures" / "generated" / "org.fdroid.fdroid.privileged_2130.apk"
)
SAMPLE_SHA256 = "1008525a17b4f6a93ac690f9c50dcb675b6bebf53d2879dbc98ba65a1cb2e28d"


@pytest.fixture
def setup(tmp_path: Path):
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not SAMPLE.is_file():
        pytest.skip("APK 样本不存在：按 tests/fixtures/README.md 下载")
    assert sha256(SAMPLE.read_bytes()).hexdigest() == SAMPLE_SHA256, "APK 样本的 SHA-256 不符"
    workspace = ProgramWorkspace(
        GhidraRuntime(Path(install_value)), project_location=tmp_path / "projects"
    )
    tools = {tool.name: tool.handler for tool in build_default_registry(workspace).enabled_tools()}
    yield workspace, tools
    workspace.close_all()


def _project_files(workspace: ProgramWorkspace, binary: Path) -> list[str]:
    pyghidra = workspace.runtime.pyghidra
    project = pyghidra.open_project(
        workspace.project_location, _persistent_project_name(binary.resolve())
    )
    try:
        return sorted(str(item.getPathname()) for item in project.getProjectData())
    finally:
        project.close()


def _mutations(tools, program_id: str, entry: str) -> dict[str, bool]:
    return {
        "comment": any(
            item["address"] == entry and item["text"] == "issue3 comment"
            for offset in range(0, 20000, 1000)
            for item in tools["comments_list"](program_id, offset=offset, limit=1000)
        ),
        "tag": any(
            item["name"] == "issue3_tag" for item in tools["function_tags"](program_id, entry)
        ),
        "bookmark": any(
            item["address"] == entry and item["comment"] == "issue3 bookmark"
            for offset in range(0, 20000, 1000)
            for item in tools["bookmarks_list"](program_id, offset=offset, limit=1000)
        ),
    }


@pytest.mark.integration
def test_apk_reopen_restores_functions_and_mutations(setup, tmp_path: Path) -> None:
    workspace, tools = setup
    binary = tmp_path / SAMPLE.name
    binary.write_bytes(SAMPLE.read_bytes())

    program_id = tools["program_open"](str(binary), analyze=True)["program_id"]
    assert tools["program_info"](program_id)["name"] == "classes.dex"
    functions = tools["functions_list"](program_id, offset=0, limit=1000)
    assert functions
    entry = functions[0]["entry_point"]
    tools["comment_set"](program_id, entry, "eol", "issue3 comment")
    tools["function_tag_update"](program_id, entry, "add", "issue3_tag")
    tools["bookmark_set"](program_id, entry, "Analysis", "Review", "issue3 bookmark")
    tools["program_close"](program_id)
    assert _project_files(workspace, binary) == ["/classes.dex"]

    for _ in range(2):
        reopened = tools["program_open"](str(binary), analyze=False)["program_id"]
        assert len(tools["functions_list"](reopened, offset=0, limit=1000)) == len(functions)
        assert _mutations(tools, reopened, entry) == {
            "comment": True,
            "tag": True,
            "bookmark": True,
        }
        tools["program_close"](reopened)
        assert _project_files(workspace, binary) == ["/classes.dex"]

    # A project from an older ghidra-mcp: every reopen imported an unanalysed copy the way
    # the old code did (same ProgramLoader calls), which Ghidra saved as /classes.dex.0.
    pyghidra = workspace.runtime.pyghidra
    project = pyghidra.open_project(
        workspace.project_location, _persistent_project_name(binary.resolve())
    )
    try:
        results = (
            pyghidra.program_loader().source(str(binary)).project(project).name(binary.name).load()
        )
        try:
            results.save(pyghidra.task_monitor())
        finally:
            results.close()
    finally:
        project.close()
    assert _project_files(workspace, binary) == ["/classes.dex", "/classes.dex.0"]

    reopened = tools["program_open"](str(binary), analyze=False)["program_id"]
    assert len(tools["functions_list"](reopened, offset=0, limit=1000)) == len(functions)
    assert _mutations(tools, reopened, entry) == {"comment": True, "tag": True, "bookmark": True}
    tools["program_close"](reopened)
    assert _project_files(workspace, binary) == ["/classes.dex", "/classes.dex.0"]


@pytest.mark.integration
def test_multidex_apk_reopens_the_primary_classes_dex(setup, tmp_path: Path) -> None:
    workspace, tools = setup
    # Synthetic multi-DEX APK built from the sample: classes2.dex is a copy of classes.dex.
    binary = tmp_path / "multidex.apk"
    with zipfile.ZipFile(SAMPLE) as source:
        entries = {name: source.read(name) for name in source.namelist()}
    entries["classes2.dex"] = entries["classes.dex"]
    with zipfile.ZipFile(binary, "w", zipfile.ZIP_DEFLATED) as target:
        for name, data in entries.items():
            target.writestr(name, data)

    program_id = tools["program_open"](str(binary), analyze=False)["program_id"]
    assert tools["program_info"](program_id)["name"] == "classes.dex"
    address = tools["memory_blocks_list"](program_id)[0]["start"]
    tools["comment_set"](program_id, address, "eol", "primary dex")
    tools["program_close"](program_id)
    assert _project_files(workspace, binary) == ["/classes.dex", "/classes2.dex"]

    reopened = tools["program_open"](str(binary), analyze=False)["program_id"]
    assert tools["program_info"](reopened)["name"] == "classes.dex"
    assert any(
        item["address"] == address and item["text"] == "primary dex"
        for item in tools["comments_list"](reopened, limit=1000)
    )
    tools["program_close"](reopened)
    assert _project_files(workspace, binary) == ["/classes.dex", "/classes2.dex"]
