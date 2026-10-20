"""Shutdown contract (SAF-19): stdin EOF and SIGTERM both drain running calls, then close_all.

Process-level tests run ``MCPService.run`` in a child process with a fake PyGhidra, so the
real signal handling, stdio transport and uvicorn shutdown are exercised; only Ghidra is
mocked. tests/integration/test_real_ghidra_shutdown.py repeats the key cases with a real JVM.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import signal
import sys
import threading
import time
import types
from typing import Any

import pytest

from shutdown_harness import (
    AFTER_RUN_SCRIPT,
    FAKE_SERVICE_SCRIPT,
    TEST_TOKEN,
    ServerProcess,
    free_port,
    start_server,
    wait_http_ready,
)

DEADLINE = 30.0
# Exit budget after SIGTERM or stdin EOF when nothing is in flight (generous for slow CI).
PROMPT_EXIT = 10.0
SIGTERM_STATUS = 128 + signal.SIGTERM

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals only")


def _write_ghidra_install(root: Path) -> Path:
    install_dir = root / "ghidra"
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.1.4\n", encoding="utf-8")
    return install_dir


def _environment(
    tmp_path: Path, *, transport: str, workers: int, slow_seconds: float = 0.0
) -> dict[str, str]:
    inputs = tmp_path / "inputs"
    inputs.mkdir(exist_ok=True)
    (inputs / "fast.bin").write_bytes(b"fast")
    (inputs / "slow.bin").write_bytes(b"slow")
    return {
        "HARNESS_TRANSPORT": transport,
        "HARNESS_INSTALL_DIR": str(_write_ghidra_install(tmp_path)),
        "HARNESS_STORAGE": str(tmp_path / "projects"),
        "HARNESS_WORKERS": str(workers),
        "HARNESS_INPUT_ROOT": str(inputs),
        "SLOW_SECONDS": str(slow_seconds),
    }


def _start_stdio(
    tmp_path: Path,
    *,
    workers: int = 1,
    slow_seconds: float = 0.0,
    script: str = FAKE_SERVICE_SCRIPT,
    extra_env: dict[str, str] | None = None,
) -> ServerProcess:
    env = _environment(tmp_path, transport="stdio", workers=workers, slow_seconds=slow_seconds)
    env.update(extra_env or {})
    server = start_server(script, env=env, cwd=tmp_path, stdio=True)
    try:
        server.stdio_initialize(DEADLINE)
        server.stdio_call(
            2,
            "program_open",
            {"binary_path": str(tmp_path / "inputs" / "fast.bin"), "analyze": False},
        )
        reply = server.wait_reply(2, DEADLINE)
        assert not reply["result"].get("isError"), f"{reply}\n{server.stderr}"
    except BaseException:
        server.kill()
        raise
    return server


def _assert_closed_after_drain(server: ServerProcess, *names: str) -> None:
    drained = server.line_index("draining running tool calls")
    for name in names:
        closed = server.line_index(f"PROGRAM_CLOSED {name}")
        assert closed > drained, server.stderr
    assert f"close_all: closing {len(names)} open program(s)" in server.stderr
    assert f"close_all: finished, {len(names)} closed, 0 failed" in server.stderr


# ------------------------------------------------------------------ stdio


def test_stdio_exits_promptly_on_stdin_eof_and_runs_close_all(tmp_path: Path) -> None:
    server = _start_stdio(tmp_path)
    try:
        started = time.monotonic()
        server.close_stdin()
        status = server.wait_exit(DEADLINE)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert status == 0, server.stderr
    assert elapsed < PROMPT_EXIT
    _assert_closed_after_drain(server, "fast.bin")
    assert "SIGTERM" not in server.stderr


def test_stdio_sigterm_with_stdin_still_open_drains_and_runs_close_all(tmp_path: Path) -> None:
    server = _start_stdio(tmp_path)
    try:
        started = server.terminate()
        status = server.wait_exit(DEADLINE)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert status == SIGTERM_STATUS, server.stderr
    assert elapsed < PROMPT_EXIT
    assert "SIGTERM received; stopping the transport" in server.stderr
    _assert_closed_after_drain(server, "fast.bin")


@pytest.mark.parametrize("workers", [1, 4])
def test_stdio_sigterm_lets_the_running_call_finish_before_close_all(
    tmp_path: Path, workers: int
) -> None:
    server = _start_stdio(tmp_path, workers=workers, slow_seconds=2.0)
    try:
        server.stdio_call(
            3,
            "program_open",
            {"binary_path": str(tmp_path / "inputs" / "slow.bin"), "analyze": False},
        )
        server.wait_stderr("SLOW_OPEN_STARTED", DEADLINE)
        server.terminate()
        server.wait_stderr("SIGTERM received; stopping the transport", DEADLINE)
        # A second SIGTERM during the drain must not cut it short.
        server.terminate()
        status = server.wait_exit(DEADLINE)
    finally:
        server.kill()
    assert status == SIGTERM_STATUS, server.stderr
    assert "SIGTERM received again; shutdown is already in progress" in server.stderr
    finished = server.line_index("SLOW_OPEN_FINISHED")
    assert server.line_index("PROGRAM_CLOSED fast.bin") > finished, server.stderr
    assert server.line_index("PROGRAM_CLOSED slow.bin") > finished, server.stderr
    _assert_closed_after_drain(server, "fast.bin", "slow.bin")


# ---------------------------------------------------------- streamable-http


def _start_http(tmp_path: Path, *, workers: int, slow_seconds: float = 0.0) -> tuple[Any, int]:
    port = free_port()
    env = _environment(
        tmp_path, transport="streamable-http", workers=workers, slow_seconds=slow_seconds
    )
    env.update(
        HARNESS_PORT=str(port),
        HARNESS_PUBLIC_URL=f"http://127.0.0.1:{port}",
        HARNESS_TOKEN=TEST_TOKEN,
    )
    server = start_server(FAKE_SERVICE_SCRIPT, env=env, cwd=tmp_path, stdio=False)
    try:
        wait_http_ready(port, DEADLINE)
    except BaseException:
        server.kill()
        raise
    return server, port


async def _http_session_then_sigterm(
    server: ServerProcess, port: int, inputs: Path, *, slow: bool
) -> float:
    """Open programs over a live MCP session, send SIGTERM while it is still open."""

    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    started = 0.0
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    try:
        async with httpx.AsyncClient(headers=headers, timeout=DEADLINE) as http:
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http) as (
                read,
                write,
                _,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    opened = await session.call_tool(
                        "program_open",
                        {"binary_path": str(inputs / "fast.bin"), "analyze": False},
                    )
                    assert not opened.isError, opened
                    pending = None
                    if slow:
                        pending = asyncio.create_task(
                            session.call_tool(
                                "program_open",
                                {"binary_path": str(inputs / "slow.bin"), "analyze": False},
                            )
                        )
                        await asyncio.to_thread(server.wait_stderr, "SLOW_OPEN_STARTED", DEADLINE)
                    started = server.terminate()
                    await asyncio.to_thread(server.wait_exit, DEADLINE)
                    if pending is not None:
                        pending.cancel()
    except Exception:
        # The server going away under a live session makes the client raise on exit; the
        # assertions below are about the server process, not the client.
        pass
    return started


@pytest.mark.parametrize(("workers", "slow"), [(1, False), (4, True)])
def test_streamable_http_sigterm_drains_and_runs_close_all(
    tmp_path: Path, workers: int, slow: bool
) -> None:
    server, port = _start_http(tmp_path, workers=workers, slow_seconds=2.0 if slow else 0.0)
    try:
        started = asyncio.run(
            _http_session_then_sigterm(server, port, tmp_path / "inputs", slow=slow)
        )
        status = server.wait_exit(DEADLINE)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert started > 0, server.stderr
    assert status == SIGTERM_STATUS, server.stderr
    assert "SIGTERM received; stopping the transport" in server.stderr
    if slow:
        finished = server.line_index("SLOW_OPEN_FINISHED")
        assert server.line_index("PROGRAM_CLOSED fast.bin") > finished, server.stderr
        _assert_closed_after_drain(server, "fast.bin", "slow.bin")
    else:
        assert elapsed < PROMPT_EXIT
        _assert_closed_after_drain(server, "fast.bin")


# ----------------------------------------------------------- interruptible stdin


def test_interruptible_stdin_delivers_all_input_before_a_real_eof() -> None:
    from ghidra_mcp.service import _InterruptibleStdin

    read_fd, write_fd = os.pipe()
    try:
        raw = _InterruptibleStdin(read_fd, max_chunks=2)
        payload = b"".join(f'{{"line": {index}}}\n'.encode() for index in range(5000))
        writer = threading.Thread(target=lambda: (os.write(write_fd, payload), os.close(write_fd)))
        writer.start()
        import io

        received = io.BufferedReader(raw).read()
        writer.join(DEADLINE)
    finally:
        os.close(read_fd)
    assert received == payload


def test_interruptible_stdin_stop_unblocks_a_reader_while_the_writer_stays_open() -> None:
    import io

    from ghidra_mcp.service import _InterruptibleStdin

    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b'{"first": 1}\n')
        raw = _InterruptibleStdin(read_fd)
        text = io.TextIOWrapper(io.BufferedReader(raw), encoding="utf-8")
        assert text.readline() == '{"first": 1}\n'
        result: list[str] = []
        reader = threading.Thread(target=lambda: result.append(text.readline()))
        reader.start()
        time.sleep(0.2)
        assert reader.is_alive()
        raw.stop()
        reader.join(5)
        assert not reader.is_alive()
        assert result == [""]
        # Input that arrives after stop() is not delivered.
        os.write(write_fd, b'{"late": 1}\n')
        assert text.readline() == ""
    finally:
        os.close(write_fd)
        os.close(read_fd)


def test_interruptible_stdin_leaves_input_that_arrives_during_the_last_poll_in_fd_0(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Input written after release() while the copying thread is still in a poll stays in fd 0.

    The first poll is gated so the order is fixed: the copying thread is inside the poll,
    then stop() runs, then input arrives, and only then does the poll report it readable.
    """

    import select

    from ghidra_mcp.service import _InterruptibleStdin

    if not hasattr(select, "poll"):
        pytest.skip("needs select.poll")
    in_first_poll = threading.Event()
    let_poll_return = threading.Event()
    real_wait_readable = _InterruptibleStdin._wait_readable
    gated = [True]

    def gated_wait_readable(self: Any) -> bool:
        if gated[0]:
            gated[0] = False
            in_first_poll.set()
            assert let_poll_return.wait(DEADLINE)
        return real_wait_readable(self)

    monkeypatch.setattr(_InterruptibleStdin, "_wait_readable", gated_wait_readable)
    read_fd, write_fd = os.pipe()
    try:
        raw = _InterruptibleStdin(read_fd)
        assert in_first_poll.wait(DEADLINE)
        raw.stop()
        os.write(write_fd, b'{"next_reader": 1}\n')
        let_poll_return.set()
        raw.release()
        assert not raw._pump.is_alive()
        os.set_blocking(read_fd, False)
        try:
            left_in_fd = os.read(read_fd, 1024)
        except BlockingIOError:
            left_in_fd = b""
        assert left_in_fd == b'{"next_reader": 1}\n'
    finally:
        let_poll_return.set()
        os.close(write_fd)
        os.close(read_fd)


# ------------------------------------------------------------- handler semantics


def _service(transport: str = "stdio") -> Any:
    from ghidra_mcp.config import Settings
    from ghidra_mcp.server import GhidraToolExecutor
    from ghidra_mcp.service import MCPService

    return MCPService(
        settings=Settings(transport=transport),
        app=object(),  # type: ignore[arg-type]
        workspace=object(),  # type: ignore[arg-type]
        tool_executor=GhidraToolExecutor(),
    )


def test_http_sigterm_handler_unwinds_the_main_thread_with_exit_status_143() -> None:
    service = _service("streamable-http")
    with pytest.raises(SystemExit) as raised:
        service._on_sigterm(signal.SIGTERM, None)
    assert raised.value.code == SIGTERM_STATUS
    # Already shutting down: later signals only log.
    service._on_sigterm(signal.SIGTERM, None)
    service.tool_executor.close()


def _call_on_another_thread(function: Any, *args: Any) -> Any:
    """Run function on a fresh non-main thread (like a JVM signal thread); return or raise."""

    outcome: dict[str, Any] = {}

    def call() -> None:
        try:
            outcome["result"] = function(*args)
        except BaseException as error:
            outcome["error"] = error

    thread = threading.Thread(target=call, name="fake-jvm-signal-thread")
    thread.start()
    thread.join(5)
    assert not thread.is_alive()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["result"]


@pytest.mark.parametrize("transport", ["stdio", "streamable-http"])
def test_sigterm_off_the_main_thread_with_nothing_to_stop_is_left_to_the_jvm(
    transport: str,
) -> None:
    """P4: no stdin wrapper to stop (stdio without a stdin fd, or HTTP) on a JVM thread.

    Recording the request there would swallow the signal, because only the main thread can
    unwind the event loop. The handler must not raise there either; it reports
    SIGTERM_NOT_HANDLED so the forwarder hands the signal to the JVM's own handler.
    """

    from ghidra_mcp.runtime import SIGTERM_NOT_HANDLED

    service = _service(transport)
    assert service._stdin is None
    result = _call_on_another_thread(service._on_sigterm, signal.SIGTERM, None)
    assert result is SIGTERM_NOT_HANDLED
    assert not service._terminate_requested.is_set()
    service.tool_executor.close()


def test_sigterm_off_the_main_thread_stops_the_stdin_wrapper_when_there_is_one() -> None:
    service = _service("stdio")
    stopped: list[str] = []
    service._stdin = types.SimpleNamespace(stop=lambda: stopped.append("stop"))  # type: ignore[assignment]
    result = _call_on_another_thread(service._on_sigterm, signal.SIGTERM, None)
    assert result is None
    assert stopped == ["stop"]
    assert service._terminate_requested.is_set()
    # During the drain a later SIGTERM is deliberately ignored, not handed to the JVM.
    assert _call_on_another_thread(service._on_sigterm, signal.SIGTERM, None) is None
    assert stopped == ["stop"]
    service._stdin = None
    service.tool_executor.close()


def test_run_restores_the_previous_sigterm_handler_and_stdin(tmp_path: Path) -> None:
    sentinel_handler = signal.getsignal(signal.SIGTERM)
    original_stdin = sys.stdin
    seen: dict[str, Any] = {}

    class App:
        def run(self, transport: str) -> None:
            seen["handler"] = signal.getsignal(signal.SIGTERM)

    from ghidra_mcp.config import Settings
    from ghidra_mcp.server import GhidraToolExecutor
    from ghidra_mcp.service import MCPService

    service = MCPService(
        settings=Settings(),
        app=App(),  # type: ignore[arg-type]
        workspace=types.SimpleNamespace(close_all=lambda: None),  # type: ignore[arg-type]
        tool_executor=GhidraToolExecutor(),
    )
    service.run()
    assert seen["handler"] == service._on_sigterm
    assert signal.getsignal(signal.SIGTERM) is sentinel_handler
    assert sys.stdin is original_stdin


def test_run_restores_the_default_when_the_previous_handler_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P5: signal.signal() returns None for a handler installed outside Python."""

    real_signal = signal.signal
    calls: list[Any] = []

    def fake_signal(signum: int, handler: Any) -> Any:
        calls.append(handler)
        real_signal(signum, handler)
        return None

    class App:
        def run(self, transport: str) -> None:
            pass

    from ghidra_mcp.config import Settings
    from ghidra_mcp.server import GhidraToolExecutor
    from ghidra_mcp.service import MCPService

    original = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(signal, "signal", fake_signal)
    service = MCPService(
        settings=Settings(),
        app=App(),  # type: ignore[arg-type]
        workspace=types.SimpleNamespace(close_all=lambda: None),  # type: ignore[arg-type]
        tool_executor=GhidraToolExecutor(),
    )
    try:
        service.run()
        assert calls == [service._on_sigterm, signal.SIG_DFL]
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
    finally:
        real_signal(signal.SIGTERM, original)


# --------------------------------------------- what run() leaves behind (subprocess)


@pytest.mark.parametrize("unknown_previous_handler", [True, False])
def test_sigterm_after_run_returned_takes_the_default_action(
    tmp_path: Path, unknown_previous_handler: bool
) -> None:
    """P5: once run() is over, SIGTERM must not hit a handler that ignores it forever."""

    server = _start_stdio(
        tmp_path,
        script=AFTER_RUN_SCRIPT,
        extra_env={
            "HARNESS_UNKNOWN_SIGTERM_HANDLER": "1" if unknown_previous_handler else "0",
            "HARNESS_AFTER_RUN": "wait_for_signal",
        },
    )
    try:
        server.close_stdin()
        server.wait_stderr("WAITING_FOR_SIGNAL", DEADLINE)
        server.terminate()
        status = server.wait_exit(PROMPT_EXIT)
    finally:
        server.kill()
    assert server.line_index("RUN_RETURNED") > server.line_index("PROGRAM_CLOSED fast.bin")
    assert status == -signal.SIGTERM, server.stderr
    assert "SIGTERM received again" not in server.stderr
    assert "STILL_ALIVE_AFTER_WAIT" not in server.stderr


def test_stdin_is_released_when_the_transport_fails(tmp_path: Path) -> None:
    """P6: after run() ends with an error, the copying thread must not keep reading fd 0."""

    env = _environment(tmp_path, transport="stdio", workers=1)
    env.update(HARNESS_APP_RUN_FAILS="1", HARNESS_AFTER_RUN="read_stdin")
    server = start_server(AFTER_RUN_SCRIPT, env=env, cwd=tmp_path, stdio=True)
    try:
        server.send_raw(b"first\n")
        server.wait_stderr("READING_STDIN", DEADLINE)
        server.send_raw(b"second\n")
        server.wait_stderr("AFTER_RUN_READ", DEADLINE)
        status = server.wait_exit(DEADLINE)
    finally:
        server.kill()
    assert "APP_RUN_READ 'first\\n'" in server.stderr
    assert "RUN_FAILED RuntimeError" in server.stderr
    assert "STDIN_PUMP_ALIVE False" in server.stderr
    assert "AFTER_RUN_READ b'second\\n'" in server.stderr
    assert status == 0, server.stderr


def test_stdin_is_released_when_close_all_fails_after_sigterm(tmp_path: Path) -> None:
    """P6 via the P3 path: SIGTERM, then close_all raises, so run() ends with an error."""

    server = _start_stdio(
        tmp_path,
        script=AFTER_RUN_SCRIPT,
        extra_env={"HARNESS_FAIL_SAVE": "1", "HARNESS_AFTER_RUN": "read_stdin"},
    )
    try:
        server.terminate()
        server.wait_stderr("READING_STDIN", DEADLINE)
        server.send_raw(b"second\n")
        server.wait_stderr("AFTER_RUN_READ", DEADLINE)
        status = server.wait_exit(DEADLINE)
    finally:
        server.kill()
    assert "close_all: finished, 0 closed, 1 failed" in server.stderr
    assert "RUN_FAILED RuntimeError" in server.stderr
    assert "STDIN_PUMP_ALIVE False" in server.stderr
    assert "AFTER_RUN_READ b'second\\n'" in server.stderr
    assert status == 0, server.stderr


_FAKE_RICH_LOGGING = """
import logging
import sys


class RichHandler(logging.Handler):
    # Stand-in for rich.logging.RichHandler: decorates and wraps every record.
    def __init__(self, *args, **kwargs):
        super().__init__()

    def emit(self, record):
        text = self.format(record)
        for start in range(0, len(text), 24):
            print("[rich] " + text[start : start + 24], file=sys.stderr, flush=True)
"""


def test_harness_log_lines_stay_plain_when_rich_is_installed(tmp_path: Path) -> None:
    """P8: FastMCP would install a RichHandler (wrapped lines) if rich were importable."""

    fake_rich = tmp_path / "fake-rich" / "rich"
    fake_rich.mkdir(parents=True)
    (fake_rich / "__init__.py").write_text("", encoding="utf-8")
    (fake_rich / "console.py").write_text(
        "class Console:\n    def __init__(self, *args, **kwargs):\n        pass\n",
        encoding="utf-8",
    )
    (fake_rich / "logging.py").write_text(_FAKE_RICH_LOGGING, encoding="utf-8")
    python_path = os.pathsep.join(
        part for part in (str(fake_rich.parent), os.environ.get("PYTHONPATH")) if part
    )
    server = _start_stdio(tmp_path, extra_env={"PYTHONPATH": python_path})
    try:
        server.close_stdin()
        status = server.wait_exit(DEADLINE)
    finally:
        server.kill()
    assert status == 0, server.stderr
    assert "[rich]" not in server.stderr
    _assert_closed_after_drain(server, "fast.bin")


# ----------------------------------------------------------------- JVM start-up


def test_jvm_starts_on_a_helper_thread_that_detaches_before_it_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The JVM creator thread must not be a tool worker that ends while still attached."""

    from ghidra_mcp import runtime as runtime_module

    calls: list[tuple[str, int, str]] = []

    def record(event: str) -> None:
        current = threading.current_thread()
        calls.append((event, threading.get_ident(), current.name))

    monkeypatch.setattr(runtime_module, "_detach_current_thread_from_jvm", lambda: record("detach"))
    monkeypatch.setattr(runtime_module, "_forward_jvm_sigterm_to_python", lambda: record("forward"))

    class FakePyGhidra:
        def start(self, *, install_dir: Path) -> object:
            record("start")
            return "launcher"

    runtime = runtime_module.GhidraRuntime(
        _write_ghidra_install(tmp_path), pyghidra_module=FakePyGhidra()
    )
    from ghidra_mcp.server import GhidraToolExecutor

    executor = GhidraToolExecutor()
    try:
        worker_ident = executor.run_sync(threading.get_ident)
        assert executor.run_sync(runtime.ensure_started) == "launcher"
        assert executor.run_sync(runtime.ensure_started) == "launcher"
    finally:
        executor.close()
    assert [event for event, _, _ in calls] == ["start", "forward", "detach"]
    helper_idents = {ident for _, ident, _ in calls}
    assert len(helper_idents) == 1
    assert worker_ident not in helper_idents
    assert threading.get_ident() not in helper_idents
    assert {name for _, _, name in calls} == {"ghidra-mcp-jvm-start"}


def test_jvm_start_failure_reaches_the_caller_and_still_detaches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp import runtime as runtime_module

    events: list[str] = []
    monkeypatch.setattr(
        runtime_module, "_detach_current_thread_from_jvm", lambda: events.append("detach")
    )
    monkeypatch.setattr(
        runtime_module, "_forward_jvm_sigterm_to_python", lambda: events.append("forward")
    )

    class BrokenPyGhidra:
        def __init__(self) -> None:
            self.calls = 0

        def start(self, *, install_dir: Path) -> object:
            self.calls += 1
            raise RuntimeError("JVM failed to start")

    fake = BrokenPyGhidra()
    runtime = runtime_module.GhidraRuntime(_write_ghidra_install(tmp_path), pyghidra_module=fake)
    with pytest.raises(RuntimeError, match="JVM failed to start"):
        runtime.ensure_started()
    assert events == ["detach"]
    # Nothing was recorded as started, so a later call tries again.
    with pytest.raises(RuntimeError, match="JVM failed to start"):
        runtime.ensure_started()
    assert fake.calls == 2


def test_jvm_hook_failures_do_not_fail_start_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp import runtime as runtime_module

    def boom() -> None:
        raise RuntimeError("hook failed")

    monkeypatch.setattr(runtime_module, "_detach_current_thread_from_jvm", boom)
    monkeypatch.setattr(runtime_module, "_forward_jvm_sigterm_to_python", boom)

    class FakePyGhidra:
        def start(self, *, install_dir: Path) -> object:
            return "launcher"

    runtime = runtime_module.GhidraRuntime(
        _write_ghidra_install(tmp_path), pyghidra_module=FakePyGhidra()
    )
    assert runtime.ensure_started() == "launcher"


class _FakeJavaSignalApi:
    """Just enough of jpype + sun.misc.Signal to exercise the SIGTERM forwarder."""

    def __init__(self) -> None:
        self.installed: list[tuple[str, Any]] = []
        self.previous_calls: list[Any] = []
        self.detached = 0
        self.refuse = False
        api = self

        class PreviousHandler:
            def handle(self, sig: Any) -> None:
                api.previous_calls.append(sig)

        class Signal:
            def __init__(self, name: str) -> None:
                self.name = name

            @staticmethod
            def handle(sig: Any, handler: Any) -> Any:
                if api.refuse:
                    raise ValueError("Signal already used by VM or OS: SIGTERM")
                api.installed.append((sig.name, handler))
                return PreviousHandler()

        class Thread:
            @staticmethod
            def detach() -> None:
                api.detached += 1

        self.module = types.SimpleNamespace(
            isJVMStarted=lambda: True,
            JClass=lambda name: {"sun.misc.Signal": Signal, "java.lang.Thread": Thread}[name],
            JImplements=lambda _interface: (lambda cls: cls),
            JOverride=lambda function: function,
        )


@pytest.fixture
def fake_jpype(monkeypatch: pytest.MonkeyPatch) -> _FakeJavaSignalApi:
    from ghidra_mcp import runtime as runtime_module

    api = _FakeJavaSignalApi()
    monkeypatch.setitem(sys.modules, "jpype", api.module)
    monkeypatch.setattr(runtime_module, "_JVM_SIGTERM_FORWARDER", [])
    return api


def _install_forwarder(api: _FakeJavaSignalApi) -> Any:
    from ghidra_mcp import runtime as runtime_module

    runtime_module._forward_jvm_sigterm_to_python()
    assert [name for name, _ in api.installed] == ["TERM"]
    return api.installed[0][1]


def test_jvm_sigterm_forwarder_calls_the_current_python_handler(
    fake_jpype: _FakeJavaSignalApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    received: list[tuple[int, Any]] = []
    monkeypatch.setattr(signal, "getsignal", lambda _: lambda *args: received.append(args))
    forwarder = _install_forwarder(fake_jpype)

    forwarder.handle("SIGTERM")

    assert received == [(signal.SIGTERM, None)]
    assert fake_jpype.previous_calls == []


@pytest.mark.parametrize(
    ("python_handler", "expect_previous"),
    [(signal.SIG_DFL, True), (None, True), (signal.SIG_IGN, False)],
)
def test_jvm_sigterm_forwarder_respects_python_default_and_ignore(
    fake_jpype: _FakeJavaSignalApi,
    monkeypatch: pytest.MonkeyPatch,
    python_handler: Any,
    expect_previous: bool,
) -> None:
    monkeypatch.setattr(signal, "getsignal", lambda _: python_handler)
    forwarder = _install_forwarder(fake_jpype)

    forwarder.handle("SIGTERM")

    assert fake_jpype.previous_calls == (["SIGTERM"] if expect_previous else [])


def test_jvm_sigterm_forwarder_hands_an_unhandled_sigterm_to_the_jvm(
    fake_jpype: _FakeJavaSignalApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P4 end to end through the forwarder: stdio service without a stdin fd, JVM started."""

    service = _service("stdio")
    monkeypatch.setattr(signal, "getsignal", lambda _: service._on_sigterm)
    forwarder = _install_forwarder(fake_jpype)

    _call_on_another_thread(forwarder.handle, "SIGTERM")

    assert fake_jpype.previous_calls == ["SIGTERM"]
    service.tool_executor.close()


def test_jvm_sigterm_forwarder_falls_back_to_the_jvm_when_the_python_handler_fails(
    fake_jpype: _FakeJavaSignalApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(*_: Any) -> None:
        raise SystemExit(143)

    monkeypatch.setattr(signal, "getsignal", lambda _: failing)
    forwarder = _install_forwarder(fake_jpype)

    forwarder.handle("SIGTERM")

    assert fake_jpype.previous_calls == ["SIGTERM"]


def test_jvm_sigterm_forwarder_is_installed_once_and_tolerates_a_refusing_jvm(
    fake_jpype: _FakeJavaSignalApi,
) -> None:
    from ghidra_mcp import runtime as runtime_module

    fake_jpype.refuse = True
    runtime_module._forward_jvm_sigterm_to_python()
    assert fake_jpype.installed == []

    fake_jpype.refuse = False
    runtime_module._forward_jvm_sigterm_to_python()
    runtime_module._forward_jvm_sigterm_to_python()
    assert len(fake_jpype.installed) == 1


def test_detach_uses_java_lang_thread_only_when_a_jvm_runs(
    fake_jpype: _FakeJavaSignalApi, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ghidra_mcp import runtime as runtime_module

    runtime_module._detach_current_thread_from_jvm()
    assert fake_jpype.detached == 1
    monkeypatch.setattr(fake_jpype.module, "isJVMStarted", lambda: False)
    runtime_module._detach_current_thread_from_jvm()
    runtime_module._forward_jvm_sigterm_to_python()
    assert fake_jpype.detached == 1
    assert fake_jpype.installed == []
