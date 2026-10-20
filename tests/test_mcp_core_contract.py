import asyncio
from contextlib import contextmanager
from pathlib import Path
import threading
import time
import tomllib

import pytest
from starlette.testclient import TestClient

from ghidra_mcp.registry import ToolDefinition, ToolRegistry


DESCRIPTION = """回显输入文本。

输入输出与副作用：输入文本；返回相同文本；只读。

何时使用：验证 MCP 调用链；真实程序分析应使用对应任务工具。
"""


def write_ghidra_version(install_dir: Path, version: str = "12.1.4") -> None:
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True, exist_ok=True)
    properties.write_text(f"application.version={version}\n", encoding="utf-8")


def test_mcp_app_exposes_registry_tools_without_schema_relay() -> None:
    from ghidra_mcp.server import create_mcp_app

    registry = ToolRegistry()

    def echo(text: str) -> str:
        return text

    registry.register(ToolDefinition("echo", DESCRIPTION, echo))
    app = create_mcp_app(registry, host="127.0.0.1", port=8765)

    tools = asyncio.run(app.list_tools())

    assert [tool.name for tool in tools] == ["echo"]
    assert tools[0].description == DESCRIPTION
    assert tools[0].inputSchema["properties"]["text"]["type"] == "string"


def test_schema_version_changes_when_return_contract_changes() -> None:
    from ghidra_mcp.server import _schema_version

    def echo(text: str) -> str:
        return text

    first = ToolRegistry()
    first.register(ToolDefinition("echo", DESCRIPTION, echo, contract_version=1))
    second = ToolRegistry()
    second.register(ToolDefinition("echo", DESCRIPTION, echo, contract_version=2))

    assert _schema_version(first) != _schema_version(second)


def test_schema_version_changes_when_tool_annotations_change() -> None:
    from mcp.types import ToolAnnotations

    from ghidra_mcp.server import _schema_version

    def echo(text: str) -> str:
        return text

    first = ToolRegistry()
    first.register(
        ToolDefinition(
            "echo",
            DESCRIPTION,
            echo,
            annotations=ToolAnnotations(readOnlyHint=True),
        )
    )
    second = ToolRegistry()
    second.register(
        ToolDefinition(
            "echo",
            DESCRIPTION,
            echo,
            annotations=ToolAnnotations(readOnlyHint=False),
        )
    )

    assert _schema_version(first) != _schema_version(second)


def test_mcp_app_exposes_tool_risk_annotations() -> None:
    from mcp.types import ToolAnnotations

    from ghidra_mcp.server import create_mcp_app

    registry = ToolRegistry()

    def close_session() -> str:
        return "closed"

    registry.register(
        ToolDefinition(
            "close_session",
            DESCRIPTION,
            close_session,
            annotations=ToolAnnotations(
                readOnlyHint=False,
                destructiveHint=False,
                idempotentHint=False,
                openWorldHint=False,
            ),
        )
    )

    listed = asyncio.run(create_mcp_app(registry, host="127.0.0.1", port=8765).list_tools())

    assert listed[0].annotations == registry.enabled_tools()[0].annotations


def test_http_health_is_public_and_mcp_requires_the_configured_bearer_token() -> None:
    from ghidra_mcp.server import create_mcp_app

    registry = ToolRegistry()

    def echo(text: str) -> str:
        return text

    registry.register(ToolDefinition("echo", DESCRIPTION, echo))
    app = create_mcp_app(
        registry,
        host="0.0.0.0",
        port=8765,
        auth_token="private-test-token",
        public_url="https://mcp.example",
        version="20260720.1",
        git_commit="abc123def456",
    )

    with TestClient(app.streamable_http_app()) as client:
        health = client.get("/health")
        missing = client.post("/mcp", json={})
        wrong = client.post(
            "/mcp",
            headers={"Authorization": "Bearer wrong-token"},
            json={},
        )
        accepted = client.post(
            "/mcp",
            headers={"Authorization": "Bearer private-test-token"},
            json={},
        )

    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "version": "20260720.1",
        "git_commit": "abc123def456",
        "schema_version": health.json()["schema_version"],
    }
    assert len(health.json()["schema_version"]) == 16
    assert app.settings.auth.validate_token_resource is False
    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code != 401
    assert "https://mcp.example/" in missing.headers["www-authenticate"]
    assert "0.0.0.0" not in missing.headers["www-authenticate"]


def test_runtime_version_ignores_unrelated_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ghidra_mcp.server as server

    (tmp_path / "VERSION").write_text("unrelated-project-version\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(server, "package_version", lambda _: "20260722.1")

    assert server._runtime_version() == "20260722.1"


def test_runtime_version_uses_package_metadata_built_from_root_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ghidra_mcp.server as server

    root = Path(__file__).parents[1]
    pyproject = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert "version" not in pyproject["project"]
    assert "version" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["hatch"]["version"]["path"] == "VERSION"
    assert pyproject["project"]["license"] == "Apache-2.0"
    assert pyproject["project"]["license-files"] == ["LICENSE", "NOTICE"]
    assert pyproject["project"]["readme"] == "README.md"
    assert pyproject["project"]["urls"] == {
        "Homepage": "https://github.com/xjoker/ghidra-mcp",
        "Issues": "https://github.com/xjoker/ghidra-mcp/issues",
        "Container": "https://github.com/xjoker/ghidra-mcp/pkgs/container/ghidra-mcp",
    }
    assert (root / "LICENSE").is_file()
    assert (root / "NOTICE").read_text(encoding="utf-8").startswith(
        "Ghidra MCP\nCopyright 2026 xjoker\n"
    )

    monkeypatch.setattr(server, "package_version", lambda _: "package-metadata-version")

    assert server._runtime_version() == "package-metadata-version"


def test_token_verifier_rejects_unicode_without_raising() -> None:
    from ghidra_mcp.server import StaticTokenVerifier

    verifier = StaticTokenVerifier("ascii-test-token")

    assert asyncio.run(verifier.verify_token("令牌")) is None


def test_sync_tools_use_one_worker_without_blocking_event_loop() -> None:
    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    registry = ToolRegistry()
    worker_threads: list[int] = []

    def slow(value: int) -> int:
        worker_threads.append(threading.get_ident())
        time.sleep(0.1)
        return value

    registry.register(ToolDefinition("slow", DESCRIPTION, slow))
    executor = GhidraToolExecutor()
    app = create_mcp_app(
        registry,
        host="127.0.0.1",
        port=8765,
        tool_executor=executor,
    )
    tool = app._tool_manager._tools["slow"]

    async def exercise() -> None:
        first = asyncio.create_task(tool.run({"value": 1}))
        await asyncio.sleep(0.01)
        assert not first.done()
        assert await first == 1
        assert await tool.run({"value": 2}) == 2

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert len(set(worker_threads)) == 1
    assert worker_threads[0] != threading.get_ident()


class FakePyGhidra:
    def __init__(self) -> None:
        self.start_calls: list[Path] = []
        self.open_calls: list[Path] = []
        self.open_options: list[dict[str, object]] = []
        self.closed: list[Path] = []
        self.analysis_timeouts: list[int] = []
        self.analysis_calls: list[object] = []
        self.cancel_analysis = False
        self.cancel_after_analysis = False
        self.on_task_monitor = None

    def start(self, *, install_dir: Path) -> object:
        self.start_calls.append(install_dir)
        return object()

    def task_monitor(self, timeout: int | None = None) -> object:
        if self.on_task_monitor is not None:
            self.on_task_monitor()
        if timeout is not None:
            self.analysis_timeouts.append(timeout)
        return type(
            "Monitor",
            (),
            {"isCancelled": lambda monitor: self.cancel_analysis},
        )()

    def analyze(self, program: object, *, monitor: object) -> None:
        self.analysis_calls.append(program)
        if self.cancel_after_analysis:
            self.cancel_analysis = True

    @contextmanager
    def _program_context_factory(self, binary_path: Path, **options: object):
        self.open_calls.append(binary_path)
        self.open_options.append(options)
        try:
            yield FakeSavedAPI(binary_path)
        finally:
            self.closed.append(binary_path)


class FakeSavedProgram:
    def __init__(self) -> None:
        self.save_calls = 0

    def save(self, _: str, __: object) -> None:
        self.save_calls += 1


class FakeSavedAPI(dict[str, Path]):
    def __init__(self, binary: Path) -> None:
        super().__init__(binary=binary)
        self.program = FakeSavedProgram()

    def getCurrentProgram(self) -> FakeSavedProgram:
        return self.program


def test_workspace_starts_jvm_once_and_owns_program_lifecycle(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    fake = FakePyGhidra()
    runtime = GhidraRuntime(install_dir=install_dir, pyghidra_module=fake)
    workspace = ProgramWorkspace(runtime)

    first_id = workspace.open(binary)
    second_id = workspace.open(binary)

    assert fake.start_calls == [install_dir]
    assert workspace.get(first_id)["binary"] == binary.resolve()
    assert first_id != second_id

    workspace.close(first_id)
    assert fake.closed == [binary.resolve()]
    workspace.close_all()
    assert fake.closed == [binary.resolve(), binary.resolve()]


def test_workspace_resource_key_is_shared_across_sessions_of_one_binary(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    other = tmp_path / "other.bin"
    other.write_bytes(b"other")
    workspace = ProgramWorkspace(GhidraRuntime(install_dir, pyghidra_module=FakePyGhidra()))

    first_id = workspace.open(binary)
    second_id = workspace.open(binary)
    other_id = workspace.open(other)

    assert workspace.resource_key(first_id) == workspace.resource_key(second_id)
    assert workspace.resource_key(first_id) != workspace.resource_key(other_id)
    assert workspace.resource_key(first_id) == str(binary.resolve())
    assert workspace.resource_key("missing") == "missing"
    workspace.close_all()


def test_runtime_bounds_analysis_and_reports_monitor_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp.runtime import GhidraRuntime

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir)
    fake = FakePyGhidra()
    runtime = GhidraRuntime(
        install_dir=install_dir,
        pyghidra_module=fake,
        analysis_timeout_seconds=17,
    )
    runtime.ensure_started()
    program = object()

    runtime.analyze(program)

    assert fake.analysis_timeouts == [17]
    assert fake.analysis_calls == [program]

    fake.cancel_analysis = True
    clock = iter([0, 17])
    monkeypatch.setattr("ghidra_mcp.runtime.monotonic", lambda: next(clock))
    with pytest.raises(TimeoutError, match="17"):
        runtime.analyze(program)


def test_runtime_accepts_pyghidra_normal_completion_cancellation(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir)
    fake = FakePyGhidra()
    fake.cancel_after_analysis = True
    runtime = GhidraRuntime(
        install_dir=install_dir,
        pyghidra_module=fake,
        analysis_timeout_seconds=17,
    )

    runtime.analyze(object())


def test_runtime_deadline_includes_monitor_construction_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ghidra_mcp.runtime as runtime_module

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir)
    fake = FakePyGhidra()
    fake.cancel_analysis = True
    runtime = runtime_module.GhidraRuntime(
        install_dir=install_dir,
        pyghidra_module=fake,
        analysis_timeout_seconds=10,
    )
    clock = iter([0, 5, 10])
    monkeypatch.setattr(runtime_module, "monotonic", lambda: next(clock))
    fake.on_task_monitor = runtime_module.monotonic

    with pytest.raises(TimeoutError, match="10"):
        runtime.analyze(object())


@pytest.mark.parametrize(
    ("version", "detected"),
    [
        ("12.0.4", "12.0.4"),
        ("12.1", "12.1.0"),
        ("12.1.0", "12.1.0"),
        ("12.1.1", "12.1.1"),
        ("12.1.2", "12.1.2"),
        ("12.1.2-DEV", "12.1.2"),
        (" 12.1.2 ", "12.1.2"),
        ("11.99.99", "11.99.99"),
    ],
)
def test_runtime_rejects_ghidra_versions_with_known_reachable_vulnerabilities(
    tmp_path: Path, version: str, detected: str, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from ghidra_mcp.runtime import GhidraRuntime, WorkspaceError

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir, version)
    fake = FakePyGhidra()

    with caplog.at_level(logging.ERROR, logger="ghidra_mcp.runtime"):
        with pytest.raises(WorkspaceError) as raised:
            GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    message = str(raised.value)
    assert message.startswith(f"Ghidra {detected} 低于最低支持版本 12.1.3：")
    # 错误文本会经 MCP 工具结果返回客户端，不得包含宿主机路径；路径只进服务端日志。
    assert str(install_dir.resolve()) not in message
    assert str(tmp_path) not in message
    # Deliberately broad: this message's wording contains no "/" or "\\" at all, so any
    # separator means a path slipped back in. If the wording ever needs one (a URL, a
    # version range), switch to the absolute-path regex used in
    # tests/test_client_error_paths_contract.py instead of dropping the check.
    assert "/" not in message and "\\" not in message
    server_logs = [
        record.getMessage() for record in caplog.records if record.name == "ghidra_mcp.runtime"
    ]
    assert any(
        str(install_dir.resolve()) in line and f"Ghidra {detected}" in line for line in server_logs
    ), server_logs
    assert "最低支持版本 12.1.3" in message
    assert "路径穿越" in message and "GP-7064" in message
    assert "ELF 导入回归" in message and "GP-7061" in message
    assert "GHIDRA_INSTALL_DIR" in message
    assert fake.start_calls == []


@pytest.mark.parametrize("version", ["12.1.3", "12.1.4", "12.1.10", "12.1.4-DEV", "13.0"])
def test_runtime_accepts_ghidra_versions_at_or_above_the_minimum(
    tmp_path: Path, version: str
) -> None:
    from ghidra_mcp.runtime import GhidraRuntime

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir, version)
    fake = FakePyGhidra()

    GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    assert fake.start_calls == [install_dir]


@pytest.mark.parametrize("version", ["", "12", "12.x.4", "v12.1.4", "12..4"])
def test_runtime_rejects_unparseable_ghidra_versions(tmp_path: Path, version: str) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, WorkspaceError

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir, version)
    fake = FakePyGhidra()

    with pytest.raises(WorkspaceError, match="无法确认 Ghidra 版本"):
        GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    assert fake.start_calls == []


def test_dockerfile_bundles_an_official_ghidra_release_at_or_above_the_minimum() -> None:
    import re

    from ghidra_mcp.runtime import _MINIMUM_GHIDRA_VERSION

    dockerfile = (Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
    url = re.search(r"^ARG GHIDRA_URL=(\S+)$", dockerfile, re.MULTILINE)
    digest = re.search(r"^ARG GHIDRA_SHA256=([0-9a-f]{64})$", dockerfile, re.MULTILINE)
    assert url is not None and digest is not None
    match = re.fullmatch(
        r"https://github\.com/NationalSecurityAgency/ghidra/releases/download/"
        r"Ghidra_(\d+)\.(\d+)\.(\d+)_build/ghidra_\1\.\2\.\3_PUBLIC_\d{8}\.zip",
        url.group(1),
    )
    assert match is not None, url.group(1)
    assert tuple(int(part) for part in match.groups()) >= _MINIMUM_GHIDRA_VERSION
    # 必须与 NSA 官方 GitHub Release 资产的 SHA-256 digest 一致，而不只是 64 位 hex。
    # 升级捆绑的 Ghidra 时，把新资产名与 release API 的 digest 一并写入此表。
    official_sha256 = {
        "ghidra_12.1.4_PUBLIC_20260921.zip": (
            "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
        ),
    }
    asset = url.group(1).rsplit("/", 1)[1]
    assert asset in official_sha256, asset
    assert digest.group(1) == official_sha256[asset]


def test_runtime_accepts_future_two_component_ghidra_version(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime

    install_dir = tmp_path / "ghidra"
    write_ghidra_version(install_dir, "12.2")
    fake = FakePyGhidra()

    GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    assert fake.start_calls == [install_dir]


def test_runtime_rejects_installations_without_a_readable_version(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, WorkspaceError

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    fake = FakePyGhidra()

    with pytest.raises(WorkspaceError, match="无法确认 Ghidra 版本"):
        GhidraRuntime(install_dir, pyghidra_module=fake).ensure_started()

    assert fake.start_calls == []


def test_workspace_rejects_missing_binary_before_starting_jvm(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace, WorkspaceError

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(GhidraRuntime(install_dir, pyghidra_module=fake))

    with pytest.raises(WorkspaceError, match="不存在"):
        workspace.open(tmp_path / "missing.bin")

    assert fake.start_calls == []


def test_workspace_uses_configured_persistent_project_root(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    project_root = tmp_path / "projects"
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir, pyghidra_module=fake), project_location=project_root
    )

    program_id = workspace.open(binary)
    workspace.close(program_id)

    assert project_root.is_dir()
    assert fake.open_options[0]["project_location"] == project_root.resolve()


def test_workspace_saves_completed_analysis_before_open_returns(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(GhidraRuntime(install_dir, pyghidra_module=fake))

    program_id = workspace.open(binary, analyze=True)

    assert workspace.get(program_id).program.save_calls == 1
    workspace.close(program_id)


def test_workspace_rejects_paths_outside_input_root_and_symlink_escape(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace, WorkspaceError

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    input_root = tmp_path / "input"
    input_root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    escape = input_root / "escape.bin"
    escape.symlink_to(outside)
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir, pyghidra_module=fake), input_root=input_root
    )

    for path in (outside, escape):
        with pytest.raises(WorkspaceError, match="输入根目录"):
            workspace.open(path)

    assert fake.start_calls == []


def test_workspace_project_identity_uses_canonical_path_and_content(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first = first_dir / "same.bin"
    second = second_dir / "same.bin"
    first.write_bytes(b"same contents")
    second.write_bytes(b"same contents")
    fake = FakePyGhidra()
    workspace = ProgramWorkspace(GhidraRuntime(install_dir, pyghidra_module=fake))

    first_id = workspace.open(first)
    workspace.close(first_id)
    unchanged_id = workspace.open(first)
    workspace.close(unchanged_id)
    second_id = workspace.open(second)
    workspace.close(second_id)
    first.write_bytes(b"updated contents")
    updated_id = workspace.open(first)
    workspace.close(updated_id)

    project_names = [option["project_name"] for option in fake.open_options]
    assert len(set(project_names)) == 3
    assert project_names[0] == project_names[1]
    assert all(str(name).startswith("same.bin-") for name in project_names)


class RetryableCloseContext:
    def __init__(self, binary: Path) -> None:
        self.api = FakeSavedAPI(binary)
        self.fail = True

    def __enter__(self):
        return self.api

    def __exit__(self, *_: object) -> None:
        if self.fail:
            self.fail = False
            raise RuntimeError("save failed")


class RetryableClosePyGhidra(FakePyGhidra):
    def _program_context_factory(self, binary_path: Path, **options: object):
        self.open_calls.append(binary_path)
        self.open_options.append(options)
        return RetryableCloseContext(binary_path)


def test_workspace_close_removes_saved_session_when_context_exit_fails(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace, WorkspaceError

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir, pyghidra_module=RetryableClosePyGhidra())
    )
    program_id = workspace.open(binary)

    with pytest.raises(RuntimeError, match="save failed"):
        workspace.close(program_id)

    with pytest.raises(WorkspaceError, match="程序会话不存在"):
        workspace.get(program_id)
    assert workspace.list_open() == []


class RetryableSaveProgram(FakeSavedProgram):
    def save(self, _: str, __: object) -> None:
        self.save_calls += 1
        if self.save_calls == 1:
            raise RuntimeError("disk unavailable")


class RetryableSaveAPI(FakeSavedAPI):
    def __init__(self, binary: Path) -> None:
        super().__init__(binary)
        self.program = RetryableSaveProgram()


class RetryableSavePyGhidra(FakePyGhidra):
    @contextmanager
    def _program_context_factory(self, binary_path: Path, **options: object):
        self.open_calls.append(binary_path)
        self.open_options.append(options)
        yield RetryableSaveAPI(binary_path)


def test_workspace_save_failure_keeps_session_available_for_retry(tmp_path: Path) -> None:
    from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    write_ghidra_version(install_dir)
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    workspace = ProgramWorkspace(
        GhidraRuntime(install_dir, pyghidra_module=RetryableSavePyGhidra())
    )
    program_id = workspace.open(binary, analyze=False)

    with pytest.raises(RuntimeError, match="disk unavailable"):
        workspace.save(program_id)

    assert workspace.get(program_id)["binary"] == binary.resolve()
    workspace.save(program_id)
    workspace.close(program_id)


def test_workspace_close_all_attempts_every_session_after_one_fails() -> None:
    from threading import RLock

    from ghidra_mcp.runtime import ProgramWorkspace

    workspace = object.__new__(ProgramWorkspace)
    workspace._lock = RLock()
    workspace._programs = {"first": object(), "second": object(), "third": object()}
    closed: list[str] = []

    def close(program_id: str) -> None:
        closed.append(program_id)
        if program_id == "first":
            raise RuntimeError("first close failed")

    workspace.close = close  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="first close failed"):
        workspace.close_all()

    assert closed == ["first", "second", "third"]


def test_existing_program_file_error_after_enter_never_falls_back_to_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp.runtime import GhidraRuntime

    class ProjectData:
        def getFile(self, _path):
            return object()

    class Project:
        closed = False

        def getProjectData(self):
            return ProjectData()

        def close(self):
            self.closed = True

    class ModernPyGhidra:
        def __init__(self):
            self.project = Project()
            self.loader_calls = 0
            self.existing_closed = False

        def open_project(self, *_args, **_kwargs):
            return self.project

        @contextmanager
        def program_context(self, *_args):
            try:
                yield object()
            finally:
                self.existing_closed = True

        def program_loader(self):
            self.loader_calls += 1
            raise AssertionError("已进入现有程序后不得回退到导入")

    fake = ModernPyGhidra()
    runtime = GhidraRuntime(tmp_path, pyghidra_module=fake)
    monkeypatch.setattr(runtime, "_flat_api", lambda program: program)

    with pytest.raises(FileNotFoundError, match="disk unavailable"):
        with runtime._modern_program_context(
            tmp_path / "sample.bin",
            project_location=tmp_path,
            project_name="sample",
            analyze=False,
        ):
            raise FileNotFoundError("disk unavailable")

    assert fake.loader_calls == 0
    assert fake.existing_closed is True
    assert fake.project.closed is True
