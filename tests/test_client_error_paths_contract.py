"""Errors that reach an MCP client must not show absolute host paths (SAF-48).

FastMCP returns ``str(error)`` of any exception raised by a tool as the tool result text,
over stdio and Streamable HTTP alike. Each test below drives one client-reachable error
path and checks that the client text holds no install, input, project or tmp_path fragment
and no absolute-path-looking fragment, while the server log still names the path.

Inventory (IDs are used in the PR description and in evidence/saf-48):
  P1  install dir missing                         runtime.GhidraRuntime.ensure_started
  P2  application.properties unreadable/undecodable runtime._read_ghidra_version
  P3  application.properties without a valid version runtime._read_ghidra_version
  P4  Ghidra older than the minimum (fixed in #16)  runtime.GhidraRuntime.ensure_started
  P5  input path outside GHIDRA_MCP_INPUT_ROOT      runtime.ProgramWorkspace.open
  P6  input binary does not exist                  runtime.ProgramWorkspace.open
  P7  input binary unreadable (OSError)            runtime._persistent_project_name
  P8  PyGhidra / JVM start-up failure              runtime.GhidraRuntime.ensure_started
  P9  Ghidra project open / import failure         runtime.ProgramWorkspace.open
  P10 Ghidra save failure (program_close, writes)   runtime.GhidraRuntime.save
  P11 foreign error inside a tool (decompiler message, Java exception, OSError)
  P12 resource key failure with max_workers > 1 (Path.resolve symlink loop)
  P13 Streamable HTTP transport carries the same path-free text
Unchanged and path-free (kept verbatim): session not found, ToolInputError, timeouts,
transaction errors, executor shutdown, FastMCP argument validation.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
from typing import Any

import pytest

from ghidra_mcp.registry import ToolDefinition, ToolRegistry


# Deliberately independent of the production regex in ghidra_mcp.server: an absolute POSIX
# path (a "/" that does not continue an ASCII word or a "./" segment), a Windows drive, or
# a UNC prefix. Relative fragments such as "a/b" are allowed.
ABSOLUTE_PATH_FRAGMENT = re.compile(
    r"(?<![A-Za-z0-9_.])/(?=[^\s/])|(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\\\\"
)

DESCRIPTION = """触发错误。

输入输出与副作用：无输入；总是抛出错误；只读。

何时使用：验证错误文本如何返回 MCP 客户端；真实分析不要调用。
"""

TOKEN = "saf48-test-token-0123456789abcdef"


def assert_path_free(text: str, *fragments: object) -> None:
    for fragment in fragments:
        assert str(fragment) not in text, (fragment, text)
    assert ABSOLUTE_PATH_FRAGMENT.search(text) is None, text


def logged(caplog: pytest.LogCaptureFixture, logger: str) -> list[str]:
    lines = []
    for record in caplog.records:
        if record.name != logger:
            continue
        lines.append(record.getMessage())
        if record.exc_info:
            lines.append(str(record.exc_info[1]))
    return lines


def write_ghidra_version(install_dir: Path, version: str = "12.1.4") -> None:
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True, exist_ok=True)
    properties.write_text(f"application.version={version}\n", encoding="utf-8")


class FakeProgram:
    def __init__(self, save_error: Exception | None = None) -> None:
        self.save_error = save_error

    def save(self, _: str, __: object) -> None:
        if self.save_error is not None:
            raise self.save_error


class FakeAPI:
    def __init__(self, program: FakeProgram) -> None:
        self.program = program

    def getCurrentProgram(self) -> FakeProgram:
        return self.program


class FakePyGhidra:
    def __init__(
        self,
        *,
        start_error: Exception | None = None,
        open_error: Exception | None = None,
        save_error: Exception | None = None,
    ) -> None:
        self.start_error = start_error
        self.open_error = open_error
        self.save_error = save_error
        self.start_calls: list[Path] = []

    def start(self, *, install_dir: Path) -> object:
        self.start_calls.append(install_dir)
        if self.start_error is not None:
            raise self.start_error
        return object()

    def task_monitor(self, timeout: int | None = None) -> object:
        return type("Monitor", (), {"isCancelled": lambda monitor: False})()

    def analyze(self, program: object, *, monitor: object) -> None:
        return None

    @contextmanager
    def _program_context_factory(self, binary_path: Path, **options: object):
        if self.open_error is not None:
            raise self.open_error
        yield FakeAPI(FakeProgram(self.save_error))


def make_service(
    tmp_path: Path,
    fake: FakePyGhidra,
    *,
    install_dir: Path | None = None,
    input_root: Path | None = None,
    max_workers: int = 1,
) -> Any:
    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    if install_dir is None:
        install_dir = tmp_path / "private-host-location" / "ghidra"
        write_ghidra_version(install_dir)
    return create_service(
        Settings(
            install_dir=install_dir,
            storage_root=tmp_path / "private-projects",
            input_root=input_root,
            max_workers=max_workers,
        ),
        pyghidra_module=fake,
    )


def call_tools(service: Any, *calls: tuple[str, dict[str, Any]]) -> list[Any]:
    """Run tool calls through an in-memory MCP client session, the way stdio clients see them."""

    from mcp.shared.memory import create_connected_server_and_client_session

    async def run() -> list[Any]:
        async with create_connected_server_and_client_session(service.app._mcp_server) as client:
            return [await client.call_tool(name, arguments) for name, arguments in calls]

    try:
        return asyncio.run(run())
    finally:
        service.tool_executor.close(service.workspace.close_all)


def text_of(result: Any) -> str:
    return "\n".join(getattr(item, "text", "") for item in result.content)


# ---------------------------------------------------------------- P1-P4: install checks


def broken_install(tmp_path: Path, case: str) -> Path:
    install_dir = tmp_path / "private-host-location" / "ghidra_install"
    properties = install_dir / "Ghidra" / "application.properties"
    if case == "missing-install-dir":
        return install_dir
    properties.parent.mkdir(parents=True)
    if case == "properties-is-directory":
        properties.mkdir()
    elif case == "properties-not-utf8":
        properties.write_bytes(b"application.version=12.1.4\xff\xfe\n")
    elif case == "properties-missing":
        pass
    elif case == "version-missing":
        properties.write_text("application.name=Ghidra\n", encoding="utf-8")
    elif case == "version-unparsable":
        properties.write_text("application.version=banana\n", encoding="utf-8")
    elif case == "version-too-old":
        properties.write_text("application.version=12.1.2\n", encoding="utf-8")
    else:  # pragma: no cover - test table typo
        raise AssertionError(case)
    return install_dir


INSTALL_CASES = {
    # case id: (inventory id, expected client text, path fragment expected in the log)
    "missing-install-dir": (
        "P1",
        "Ghidra 安装目录不存在：请将 GHIDRA_INSTALL_DIR 指向有效的 Ghidra 安装目录",
        "install",
    ),
    "properties-is-directory": (
        "P2",
        "无法确认 Ghidra 版本：未能读取安装目录中的 application.properties",
        "properties",
    ),
    "properties-not-utf8": (
        "P2",
        "无法确认 Ghidra 版本：未能读取安装目录中的 application.properties",
        "properties",
    ),
    "properties-missing": (
        "P2",
        "无法确认 Ghidra 版本：未能读取安装目录中的 application.properties",
        "properties",
    ),
    "version-missing": (
        "P3",
        "无法确认 Ghidra 版本：安装目录中的 application.properties 缺少有效的 application.version",
        "properties",
    ),
    "version-unparsable": (
        "P3",
        "无法确认 Ghidra 版本：安装目录中的 application.properties 缺少有效的 application.version",
        "properties",
    ),
    "version-too-old": ("P4", "Ghidra 12.1.2 低于最低支持版本 12.1.3：", "install"),
}


@pytest.mark.parametrize("case", sorted(INSTALL_CASES))
def test_install_check_errors_keep_paths_in_the_server_log(
    tmp_path: Path, case: str, caplog: pytest.LogCaptureFixture
) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, WorkspaceError

    _, expected, log_fragment = INSTALL_CASES[case]
    install_dir = broken_install(tmp_path, case)
    properties = install_dir.resolve() / "Ghidra" / "application.properties"
    fake = FakePyGhidra()

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.runtime"):
        with pytest.raises(WorkspaceError) as raised:
            GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    message = str(raised.value)
    assert message.startswith(expected), message
    assert_path_free(message, install_dir.resolve(), tmp_path, "private-host-location")
    expected_in_log = str(properties if log_fragment == "properties" else install_dir.resolve())
    assert any(expected_in_log in line for line in logged(caplog, "ghidra_mcp.runtime"))
    assert fake.start_calls == []


@pytest.mark.parametrize("case", sorted(INSTALL_CASES))
def test_install_check_errors_reach_the_mcp_client_without_paths(
    tmp_path: Path, case: str, caplog: pytest.LogCaptureFixture
) -> None:
    _, expected, _ = INSTALL_CASES[case]
    install_dir = broken_install(tmp_path, case)
    binary = tmp_path / "inputs" / "sample.so"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF")
    fake = FakePyGhidra()
    service = make_service(tmp_path, fake, install_dir=install_dir)

    with caplog.at_level(logging.ERROR):
        (result,) = call_tools(
            service, ("program_open", {"binary_path": str(binary), "analyze": False})
        )

    assert result.isError is True
    client_text = text_of(result)
    assert expected in client_text
    # The user-supplied binary path is the only path the client sent; strip it before the
    # generic check so the assertion is about host paths the server added.
    assert str(binary) not in client_text
    assert_path_free(client_text, install_dir.resolve(), "private-host-location")
    assert any(str(install_dir.resolve()) in line for line in logged(caplog, "ghidra_mcp.runtime"))
    assert fake.start_calls == []


# ---------------------------------------------------------------- P5: input root


def test_input_root_escape_does_not_reveal_the_input_root(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    input_root = tmp_path / "private-input-root"
    input_root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (input_root / "escape.bin").symlink_to(outside)
    fake = FakePyGhidra()
    service = make_service(tmp_path, fake, input_root=input_root)

    with caplog.at_level(logging.WARNING, logger="ghidra_mcp.runtime"):
        results = call_tools(
            service,
            ("program_open", {"binary_path": "../outside.bin", "analyze": False}),
            ("program_open", {"binary_path": str(input_root / "escape.bin"), "analyze": False}),
        )

    relative, symlink = (text_of(result) for result in results)
    assert all(result.isError for result in results)
    for client_text in (relative, symlink):
        assert "输入路径超出允许的输入根目录（GHIDRA_MCP_INPUT_ROOT）" in client_text
    assert_path_free(relative, input_root.resolve(), outside.resolve(), tmp_path)
    # The second call sent an absolute path inside the input root itself; the server must
    # not add the root or the symlink target to it.
    assert str(outside.resolve()) not in symlink
    assert symlink.count(str(input_root.resolve())) == 0
    log = logged(caplog, "ghidra_mcp.runtime")
    assert any(str(input_root.resolve()) in line and str(outside.resolve()) in line for line in log)
    assert fake.start_calls == []


# ---------------------------------------------------------------- P6: missing binary


def test_missing_binary_echoes_only_the_path_the_client_supplied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace, WorkspaceError

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir)
    monkeypatch.chdir(tmp_path)
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(GhidraRuntime(install_dir, pyghidra_module=fake))

    with caplog.at_level(logging.WARNING, logger="ghidra_mcp.runtime"):
        with pytest.raises(WorkspaceError) as relative:
            workspace.open(Path("inputs/missing.bin"))
        with pytest.raises(WorkspaceError) as absolute:
            workspace.open(tmp_path / "elsewhere" / "missing.bin")

    assert str(relative.value) == "输入二进制不存在：inputs/missing.bin"
    assert_path_free(str(relative.value), tmp_path)
    # Product decision kept: an absolute path the client sent is echoed back as sent.
    assert str(absolute.value) == f"输入二进制不存在：{tmp_path / 'elsewhere' / 'missing.bin'}"
    assert any(
        str(tmp_path.resolve() / "inputs" / "missing.bin") in line
        for line in logged(caplog, "ghidra_mcp.runtime")
    )
    assert fake.start_calls == []


def test_missing_relative_binary_reaches_the_mcp_client_without_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    service = make_service(tmp_path, FakePyGhidra())

    (result,) = call_tools(service, ("program_open", {"binary_path": "missing.bin"}))

    assert result.isError is True
    assert "输入二进制不存在：missing.bin" in text_of(result)
    assert_path_free(text_of(result), tmp_path)


# ---------------------------------------------------------------- P7: unreadable binary


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root can read mode 000 files"
)
def test_unreadable_binary_reports_the_reason_without_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "locked.bin"
    binary.write_bytes(b"locked")
    binary.chmod(0)
    fake = FakePyGhidra()
    service = make_service(tmp_path, fake)

    try:
        with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
            (result,) = call_tools(service, ("program_open", {"binary_path": "locked.bin"}))
    finally:
        binary.chmod(0o600)

    assert result.isError is True
    client_text = text_of(result)
    assert "PermissionError：Permission denied；错误详情包含服务端路径" in client_text
    assert_path_free(client_text, tmp_path)
    assert any(str(binary.resolve()) in line for line in logged(caplog, "ghidra_mcp.server"))
    assert fake.start_calls == []


# ---------------------------------------------------------------- P8-P10: Ghidra failures


def test_jvm_start_failure_reaches_the_mcp_client_without_the_install_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    install_dir = tmp_path / "private-host-location" / "ghidra"
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    failure = RuntimeError(
        f"Unable to start JVM: {install_dir.resolve()}/support/launch.properties is missing"
    )
    fake = FakePyGhidra(start_error=failure)
    service = make_service(tmp_path, fake, install_dir=install_dir)

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        (result,) = call_tools(service, ("program_open", {"binary_path": "sample.bin"}))

    assert result.isError is True
    client_text = text_of(result)
    assert (
        "RuntimeError：错误详情包含服务端路径，已对客户端隐去，完整信息见服务端日志" in client_text
    )
    assert_path_free(client_text, install_dir.resolve(), "private-host-location", "launch")
    assert any(str(install_dir.resolve()) in line for line in logged(caplog, "ghidra_mcp.server"))


def test_project_open_failure_reaches_the_mcp_client_without_project_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    projects = tmp_path / "private-projects"

    class LockException(Exception):
        pass

    fake = FakePyGhidra(open_error=LockException(f"Unable to lock project! {projects}/x.gpr"))
    service = make_service(tmp_path, fake)

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        (result,) = call_tools(service, ("program_open", {"binary_path": "sample.bin"}))

    assert result.isError is True
    client_text = text_of(result)
    assert "LockException：错误详情包含服务端路径" in client_text
    assert_path_free(client_text, projects, "private-projects")
    assert any(str(projects) in line for line in logged(caplog, "ghidra_mcp.server"))


def test_save_failure_on_close_reaches_the_mcp_client_without_project_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    projects = tmp_path / "private-projects"
    fake = FakePyGhidra(save_error=OSError(f"Unable to write {projects}/sample.rep/db.1.gbf"))
    service = make_service(tmp_path, fake)
    from mcp.shared.memory import create_connected_server_and_client_session

    async def run() -> tuple[Any, Any]:
        async with create_connected_server_and_client_session(service.app._mcp_server) as client:
            opened = await client.call_tool(
                "program_open", {"binary_path": "sample.bin", "analyze": False}
            )
            program_id = json.loads(text_of(opened))["program_id"]
            return opened, await client.call_tool("program_close", {"program_id": program_id})

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        try:
            opened, closed = asyncio.run(run())
        finally:
            # The fake keeps failing to save; drop the session instead of closing it.
            service.workspace._programs.clear()
            service.tool_executor.close()

    assert opened.isError is False
    assert closed.isError is True
    client_text = text_of(closed)
    assert "OSError：错误详情包含服务端路径" in client_text
    assert_path_free(client_text, projects, "private-projects")
    assert any(str(projects) in line for line in logged(caplog, "ghidra_mcp.server"))


# ---------------------------------------------------------------- P11-P12: generic guard


def failing_app(error: Exception, *, max_workers: int = 1, resource_namer: Any = None) -> Any:
    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    def fail() -> str:
        raise error

    registry = ToolRegistry()
    registry.register(ToolDefinition("fail", DESCRIPTION, fail, mutates=False))
    executor = GhidraToolExecutor(max_workers=max_workers)
    app = create_mcp_app(
        registry,
        host="127.0.0.1",
        port=8765,
        tool_executor=executor,
        resource_namer=resource_namer,
    )
    return app, executor


def call_failing(app: Any, executor: Any, arguments: dict[str, Any] | None = None) -> Any:
    from mcp.shared.memory import create_connected_server_and_client_session

    async def run() -> Any:
        async with create_connected_server_and_client_session(app._mcp_server) as client:
            return await client.call_tool("fail", arguments or {})

    try:
        return asyncio.run(run())
    finally:
        executor.close()


HOST_PATH_ERRORS = {
    "decompiler-message": (
        RuntimeError("反编译器无法打开程序：Could not find /opt/private/ghidra/decompile"),
        "RuntimeError：错误详情包含服务端路径",
        "/opt/private/ghidra/decompile",
    ),
    "oserror-with-filename": (
        PermissionError(13, "Permission denied", "/srv/private/projects/x.gpr"),
        "PermissionError：Permission denied；错误详情包含服务端路径",
        "/srv/private/projects/x.gpr",
    ),
    "file-url": (
        RuntimeError("cannot load file:///home/private/.ghidra/prefs"),
        "RuntimeError：错误详情包含服务端路径",
        "/home/private/.ghidra/prefs",
    ),
    "windows-drive": (
        RuntimeError(r"Unable to open C:\Users\private\ghidra\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"C:\Users\private",
    ),
    "unc-share": (
        RuntimeError(r"Unable to open \\fileserver\private\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"\\fileserver\private",
    ),
    "path-after-cjk": (
        TimeoutError("等待锁超时：/var/private/lock"),
        "TimeoutError：错误详情包含服务端路径",
        "/var/private/lock",
    ),
    "path-directly-after-cjk": (
        RuntimeError("无法写入项目目录/srv/private/projects"),
        "RuntimeError：错误详情包含服务端路径",
        "/srv/private/projects",
    ),
}


@pytest.mark.parametrize("case", sorted(HOST_PATH_ERRORS))
def test_foreign_errors_with_host_paths_are_replaced_for_the_client(
    case: str, caplog: pytest.LogCaptureFixture
) -> None:
    error, expected, fragment = HOST_PATH_ERRORS[case]
    app, executor = failing_app(error)

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        result = call_failing(app, executor)

    assert result.isError is True
    client_text = text_of(result)
    assert client_text.startswith("Error executing tool fail: "), client_text
    assert expected in client_text
    assert_path_free(client_text, fragment, "private")
    assert any(fragment in line for line in logged(caplog, "ghidra_mcp.server"))


def test_resource_key_failure_with_several_workers_is_replaced_for_the_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def namer(arguments: dict[str, Any]) -> str:
        # What Path.resolve raises for a symlink loop on Python 3.11 and 3.12.
        raise RuntimeError("Symlink loop from '/srv/private/inputs/loop'")

    app, executor = failing_app(ValueError("unreachable"), max_workers=2, resource_namer=namer)

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        result = call_failing(app, executor)

    assert result.isError is True
    assert "RuntimeError：错误详情包含服务端路径" in text_of(result)
    assert_path_free(text_of(result), "/srv/private")
    assert any("/srv/private/inputs/loop" in line for line in logged(caplog, "ghidra_mcp.server"))


def test_real_symlink_loop_with_several_workers_reaches_the_client_without_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "loop").symlink_to(tmp_path / "loop")
    service = make_service(tmp_path, FakePyGhidra(), max_workers=2)

    (result,) = call_tools(service, ("program_open", {"binary_path": "loop"}))

    # Python 3.11/3.12 raise from Path.resolve (replaced by the guard); 3.13 resolves the
    # loop and the workspace reports the binary as missing, echoing the relative name.
    assert result.isError is True
    assert_path_free(text_of(result), tmp_path)


# ---------------------------------------------------------------- unchanged, path-free


PASS_THROUGH_ERRORS = {
    "path-free-runtime-error": RuntimeError("反编译失败：bad instruction at ram:00401000"),
    "timeout": TimeoutError("Ghidra 自动分析超过 300 秒"),
    "relative-path": RuntimeError("missing Ghidra/application.properties"),
}


@pytest.mark.parametrize("case", sorted(PASS_THROUGH_ERRORS))
def test_path_free_foreign_errors_reach_the_client_unchanged(
    case: str, caplog: pytest.LogCaptureFixture
) -> None:
    error = PASS_THROUGH_ERRORS[case]
    app, executor = failing_app(error)

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        result = call_failing(app, executor)

    assert result.isError is True
    assert text_of(result) == f"Error executing tool fail: {error}"
    assert logged(caplog, "ghidra_mcp.server") == []


def test_own_errors_may_echo_values_the_client_supplied() -> None:
    from ghidra_mcp.runtime import WorkspaceError
    from ghidra_mcp.tools.navigation import ToolInputError

    for error in (
        ToolInputError("数据类型不存在：/int"),
        WorkspaceError("输入二进制不存在：/data/inputs/sample.bin"),
    ):
        app, executor = failing_app(error)
        result = call_failing(app, executor)
        assert text_of(result) == f"Error executing tool fail: {error}"


def test_unknown_session_and_bad_arguments_stay_path_free(tmp_path: Path) -> None:
    service = make_service(tmp_path, FakePyGhidra())

    unknown, invalid = call_tools(
        service,
        ("program_info", {"program_id": "no-such-session"}),
        ("program_open", {"binary_path": ["not", "a", "string"]}),
    )

    assert unknown.isError is True and invalid.isError is True
    assert "程序会话不存在：no-such-session" in text_of(unknown)
    # FastMCP's argument validation text links to the pydantic docs; that URL is not a
    # host path, so drop it before the generic absolute-path check.
    invalid_text = re.sub(r"https://errors\.pydantic\.dev/\S+", "<url>", text_of(invalid))
    assert "binary_path" in invalid_text
    for client_text in (text_of(unknown), invalid_text):
        assert_path_free(client_text, tmp_path, "private-host-location")


# ---------------------------------------------------------------- P13: Streamable HTTP


def test_streamable_http_client_sees_the_same_path_free_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from starlette.testclient import TestClient

    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "private-host-location" / "missing-ghidra"
    input_root = tmp_path / "private-input-root"
    input_root.mkdir()
    (input_root / "sample.bin").write_bytes(b"sample")
    service = create_service(
        Settings(
            install_dir=install_dir,
            transport="streamable-http",
            host="127.0.0.1",
            public_url="http://127.0.0.1:8765",
            auth_token=TOKEN,
            storage_root=tmp_path / "private-projects",
            input_root=input_root,
        ),
        pyghidra_module=FakePyGhidra(),
    )
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/json, text/event-stream",
        "Host": "127.0.0.1:8765",
    }

    def rpc(client: TestClient, payload: dict[str, Any], session: str | None = None) -> Any:
        extra = {"mcp-session-id": session} if session else {}
        response = client.post("/mcp", headers={**headers, **extra}, json=payload)
        assert response.status_code in (200, 202), response.text
        return response

    def body(response: Any) -> dict[str, Any]:
        if response.headers["content-type"].startswith("text/event-stream"):
            data = [
                line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")
            ]
            return json.loads(data[-1])
        return response.json()

    try:
        with caplog.at_level(logging.ERROR, logger="ghidra_mcp.runtime"):
            with TestClient(
                service.app.streamable_http_app(), base_url="http://127.0.0.1:8765"
            ) as client:
                initialized = rpc(
                    client,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "saf48-test", "version": "0"},
                        },
                    },
                )
                session = initialized.headers.get("mcp-session-id")
                rpc(client, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
                called = body(
                    rpc(
                        client,
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "program_open",
                                "arguments": {
                                    "binary_path": str(input_root / "sample.bin"),
                                    "analyze": False,
                                },
                            },
                        },
                        session,
                    )
                )
    finally:
        service.tool_executor.close(service.workspace.close_all)

    result = called["result"]
    assert result["isError"] is True
    client_text = "\n".join(item.get("text", "") for item in result["content"])
    assert (
        "Ghidra 安装目录不存在：请将 GHIDRA_INSTALL_DIR 指向有效的 Ghidra 安装目录" in client_text
    )
    assert_path_free(client_text, install_dir.resolve(), input_root.resolve(), tmp_path)
    assert any(str(install_dir.resolve()) in line for line in logged(caplog, "ghidra_mcp.runtime"))
