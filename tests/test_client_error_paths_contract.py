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

import ast
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
        RuntimeError(r"Unable to open \\fileserver\ghidra-share\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"\\fileserver\ghidra-share",
    ),
    "oserror-strerror-with-path": (
        OSError(5, "I/O error on /srv/private/projects/x.gpr"),
        "OSError：错误详情包含服务端路径",
        "/srv/private/projects",
    ),
    "windows-drive-root-only": (
        RuntimeError("cannot write to C:\\"),
        "RuntimeError：错误详情包含服务端路径",
        "C:\\",
    ),
    "windows-drive-unknown-root": (
        RuntimeError(r"Unable to open D:\ghidra-projects\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"D:\ghidra-projects",
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
    # PR #22 review L1: a well-known root right after an ASCII letter, digit, "_" or ".".
    "path-after-ascii-letter": (
        RuntimeError("cannot open projectdir/srv/private/projects/x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        "/srv/private/projects",
    ),
    "path-after-dot": (
        RuntimeError("see.../home/private/.ghidra/prefs"),
        "RuntimeError：错误详情包含服务端路径",
        "/home/private",
    ),
    "path-after-digit": (
        RuntimeError("v12/opt/private/ghidra"),
        "RuntimeError：错误详情包含服务端路径",
        "/opt/private",
    ),
    "path-after-underscore": (
        RuntimeError("tmp_dir_/tmp/private/lock"),
        "RuntimeError：错误详情包含服务端路径",
        "/tmp/private",
    ),
    "windows-users-after-letter": (
        RuntimeError(r"profile\Users\private\ghidra"),
        "RuntimeError：错误详情包含服务端路径",
        r"\Users\private",
    ),
    # PR #22 review L2: Windows root-relative paths and ~user home directories.
    "windows-root-relative": (
        RuntimeError(r"Unable to open \Users\private\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"\Users\private",
    ),
    "windows-root-relative-unknown-root": (
        RuntimeError(r"Unable to open \ghidra-projects\alice\x.gpr"),
        "RuntimeError：错误详情包含服务端路径",
        r"\ghidra-projects\alice",
    ),
    "tilde-user": (
        RuntimeError("cannot read ~alice/ghidra-notes/prefs"),
        "RuntimeError：错误详情包含服务端路径",
        "~alice/ghidra-notes",
    ),
    "tilde-user-windows-separator": (
        RuntimeError(r"cannot read ~alice\ghidra-notes\prefs"),
        "RuntimeError：错误详情包含服务端路径",
        r"~alice\ghidra-notes",
    ),
    # PR #22 review L3: deliberately conservative, URLs and Ghidra category paths in
    # foreign errors are hidden too (see CHANGELOG).
    "http-url-is-hidden-too": (
        RuntimeError("fetch failed: https://example.invalid/private/x"),
        "RuntimeError：错误详情包含服务端路径",
        "example.invalid/private",
    ),
    "ghidra-category-path-is-hidden-too": (
        RuntimeError("data type conflict in /Demangler/private_type"),
        "RuntimeError：错误详情包含服务端路径",
        "/Demangler/private_type",
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
    # Relative paths that merely contain a well-known root name as a word are kept.
    "relative-path-with-root-word": RuntimeError("missing data_files/homework/variables.txt"),
    "plain-slash-words": RuntimeError("read/write and input/output failed"),
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


# ---------------------------------------------------------------- configured roots (review L1)


def test_host_path_forms_cover_configured_absolute_and_resolved_spellings(tmp_path: Path) -> None:
    from ghidra_mcp.server import _host_path_forms

    real = tmp_path / "real-root"
    real.mkdir()
    link = tmp_path / "link-root"
    link.symlink_to(real)

    # A symlinked root: as configured (absolute) and resolved through the link.
    assert set(_host_path_forms([link])) == {str(link), str(real)}
    forms = _host_path_forms([Path("/"), None, f"{tmp_path}/a/../real-root/"])
    # The spelling as configured is kept even when it is not normalised, next to the
    # normalised one.
    assert f"{tmp_path}/a/../real-root" in forms
    assert str(real) in forms
    assert "/" not in forms and "" not in forms


def test_host_path_forms_skip_relative_spellings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp.server import _host_path_forms

    monkeypatch.chdir(tmp_path)
    forms = _host_path_forms([Path("data/projects")])

    assert "data/projects" not in forms
    assert forms == (str(tmp_path / "data" / "projects"),)


@pytest.mark.parametrize("spelling", ["configured", "resolved"])
def test_foreign_error_naming_a_configured_root_is_hidden_without_the_pattern(
    spelling: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The configured-root check stands on its own: with the pattern disabled, an error that
    # names the storage root (as configured, through a symlink, or resolved) is still hidden.
    import ghidra_mcp.server as server

    monkeypatch.setattr(server, "_ABSOLUTE_PATH", re.compile(r"(?!x)x"))
    real = tmp_path / "zz-real-projects"
    real.mkdir()
    link = tmp_path / "zz-link-projects"
    link.symlink_to(real)
    named = link if spelling == "configured" else real
    error = RuntimeError(f"Unable to lock project!project{named}/x.rep")

    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "private-host-location" / "ghidra"
    write_ghidra_version(install_dir)
    (tmp_path / "sample.bin").write_bytes(b"sample")
    monkeypatch.chdir(tmp_path)
    service = create_service(
        Settings(install_dir=install_dir, storage_root=link),
        pyghidra_module=FakePyGhidra(open_error=error),
    )

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.server"):
        (result,) = call_tools(service, ("program_open", {"binary_path": "sample.bin"}))

    assert result.isError is True
    client_text = text_of(result)
    assert "RuntimeError：错误详情包含服务端路径" in client_text
    assert str(named) not in client_text and "zz-" not in client_text
    assert any(str(named) in line for line in logged(caplog, "ghidra_mcp.server"))


@pytest.mark.parametrize("root", ["install", "storage", "input"])
def test_create_service_passes_every_configured_root_to_the_guard(
    root: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ghidra_mcp.server as server

    monkeypatch.setattr(server, "_ABSOLUTE_PATH", re.compile(r"(?!x)x"))
    install_dir = tmp_path / "zz-install"
    write_ghidra_version(install_dir)
    storage = tmp_path / "zz-storage"
    input_root = tmp_path / "zz-input"
    input_root.mkdir()
    (input_root / "sample.bin").write_bytes(b"sample")
    named = {"install": install_dir, "storage": storage, "input": input_root}[root]
    error = RuntimeError(f"failed near x{named}/x")

    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    service = create_service(
        Settings(install_dir=install_dir, storage_root=storage, input_root=input_root),
        pyghidra_module=FakePyGhidra(open_error=error),
    )
    (result,) = call_tools(
        service, ("program_open", {"binary_path": str(input_root / "sample.bin")})
    )

    assert result.isError is True
    assert "错误详情包含服务端路径" in text_of(result)
    assert str(named) not in text_of(result)


# ------------------------------------------- pass-through error types (review L4, no regression)

SRC = Path(__file__).resolve().parents[1] / "src" / "ghidra_mcp"
PASS_THROUGH_TYPES = {"WorkspaceError", "ToolInputError"}

# Every value interpolated into a WorkspaceError / ToolInputError message, with why it may
# reach the client. A new interpolation fails the test below until it is reviewed and added.
AUDITED_INTERPOLATIONS = {
    "address": "Ghidra address or the client's address argument",
    "next_address": "Ghidra address",
    "entry_point": "Ghidra address",
    "existing_function_name": (
        "Function.getName() of an existing function, bound only from _function_identity in"
        " tools/writes.py; functions_list already returns it"
    ),
    "value": "the client's argument value",
    "path": "the client's data type path argument",
    "program_id": "the client's program_id argument",
    "binary_path": "the client's binary_path, normalised by pathlib, never resolved",
    "detected": "detected Ghidra version string",
    "minimum": "minimum Ghidra version string",
    "_MINIMUM_GHIDRA_VERSION_REASON": "constant text",
}

# Names that hold host paths. They may never appear in a pass-through message, audited or not.
HOST_PATH_NAMES = re.compile(
    r"install_dir|project_location|storage_root|input_root|location|properties|binary\b"
    r"|resolve|cwd|home|abspath|realpath|__file__|launcher|record|settings"
)


def _pass_through_sites() -> list[tuple[str, int, ast.expr]]:
    sites = []
    for source in sorted(SRC.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in PASS_THROUGH_TYPES:
                continue
            where = f"{source.relative_to(SRC)}:{node.lineno}"
            arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
            assert arguments, f"{where}: {name}() without a message"
            sites.extend((where, node.lineno, argument) for argument in arguments)
    return sites


def test_pass_through_error_messages_only_interpolate_audited_client_values() -> None:
    sites = _pass_through_sites()
    assert len(sites) >= 50, len(sites)
    problems = []
    for where, _, argument in sites:
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            if HOST_PATH_NAMES.search(argument.value) and "/" in argument.value:
                problems.append(f"{where}: constant message looks like it names a host path")
            continue
        if not isinstance(argument, ast.JoinedStr):
            problems.append(
                f"{where}: message is not a literal or f-string: {ast.unparse(argument)}"
            )
            continue
        for part in argument.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            expression = ast.unparse(part.value)
            if HOST_PATH_NAMES.search(expression):
                problems.append(f"{where}: interpolates a host path: {{{expression}}}")
            elif expression not in AUDITED_INTERPOLATIONS:
                problems.append(f"{where}: unaudited interpolation {{{expression}}}")
    assert problems == []


def test_pass_through_error_types_have_no_subclasses_and_stay_the_only_trusted_ones() -> None:
    from ghidra_mcp import server

    assert {error.__name__ for error in server._CLIENT_SAFE_ERRORS} == PASS_THROUGH_TYPES
    for source in sorted(SRC.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name not in PASS_THROUGH_TYPES:
                bases = {ast.unparse(base).rsplit(".", 1)[-1] for base in node.bases}
                assert not bases & PASS_THROUGH_TYPES, f"{source.name}: {node.name}"


def test_pass_through_errors_never_show_configured_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Sentinel roots: every pass-through error a client can trigger before Ghidra runs must
    # leave them out (the client's own relative input is all that may be echoed).
    install_dir = tmp_path / "sentinel-install"
    write_ghidra_version(install_dir)
    storage = tmp_path / "sentinel-storage"
    input_root = tmp_path / "sentinel-input"
    (input_root / "dir").mkdir(parents=True)
    monkeypatch.chdir(input_root)

    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    service = create_service(
        Settings(install_dir=install_dir, storage_root=storage, input_root=input_root),
        pyghidra_module=FakePyGhidra(),
    )
    results = call_tools(
        service,
        ("program_open", {"binary_path": "missing.bin"}),
        ("program_open", {"binary_path": "dir"}),
        ("program_open", {"binary_path": "../outside.bin"}),
        ("program_open", {"binary_path": str(tmp_path / "outside.bin")}),
        ("program_info", {"program_id": "no-such-session"}),
        ("program_close", {"program_id": "no-such-session"}),
    )

    for result in results:
        assert result.isError is True
        client_text = text_of(result)
        for root in (install_dir, storage, input_root, tmp_path, Path.cwd()):
            assert str(root) not in client_text, (root, client_text)
        assert "sentinel" not in client_text, client_text
