"""Subprocess harness for the shutdown tests: runs ``MCPService.run`` as a real process.

Used by tests/test_shutdown_contract.py (fake PyGhidra) and
tests/integration/test_real_ghidra_shutdown.py (real Ghidra). The child process owns its
main thread, so SIGTERM handling is exercised exactly as in the ``ghidra-mcp`` CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any

# Every child configures logging itself before FastMCP is imported, so the log lines the
# tests look for are plain "%(message)s" lines on stderr. FastMCP's own configure_logging()
# is then a no-op (basicConfig skips a configured root logger), even when rich is installed
# and would otherwise install a RichHandler that reformats and wraps lines.
LOGGING_PRELUDE = r"""
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
    force=True,
)
"""

# Child script for the fake-PyGhidra variant. Programs whose file name starts with "slow"
# take SLOW_SECONDS to open, so a call can be in flight when the process is stopped.
# HARNESS_FAIL_SAVE=1 makes every save fail, so close_all raises at shutdown.
_FAKE_SERVICE_SETUP = (
    LOGGING_PRELUDE
    + r"""
import os
import time
from contextlib import contextmanager
from pathlib import Path

from ghidra_mcp.config import Settings
from ghidra_mcp.service import create_service


def mark(message):
    print(message, file=sys.stderr, flush=True)


class Program:
    def save(self, *_):
        if os.environ.get("HARNESS_FAIL_SAVE") == "1":
            raise RuntimeError("HARNESS_FAIL_SAVE: save failed")


class Api:
    def __init__(self):
        self.program = Program()

    def getCurrentProgram(self):
        return self.program


class FakePyGhidra:
    def start(self, *, install_dir):
        return object()

    def task_monitor(self, timeout=None):
        return None

    @contextmanager
    def _program_context_factory(self, binary, **_):
        if binary.name.startswith("slow"):
            mark("SLOW_OPEN_STARTED")
            time.sleep(float(os.environ["SLOW_SECONDS"]))
            mark("SLOW_OPEN_FINISHED")
        try:
            yield Api()
        finally:
            mark(f"PROGRAM_CLOSED {binary.name}")


env = os.environ
http = env["HARNESS_TRANSPORT"] == "streamable-http"
settings = Settings(
    install_dir=Path(env["HARNESS_INSTALL_DIR"]),
    transport=env["HARNESS_TRANSPORT"],
    storage_root=Path(env["HARNESS_STORAGE"]),
    max_workers=int(env["HARNESS_WORKERS"]),
    host="127.0.0.1",
    port=int(env.get("HARNESS_PORT", "8765")),
    input_root=Path(env["HARNESS_INPUT_ROOT"]) if http else None,
    public_url=env.get("HARNESS_PUBLIC_URL") if http else None,
    auth_token=env.get("HARNESS_TOKEN") if http else None,
)
service = create_service(settings, pyghidra_module=FakePyGhidra())
"""
)

FAKE_SERVICE_SCRIPT = _FAKE_SERVICE_SETUP + "service.run()\n"

# Lets a child keep running after MCPService.run() returns or fails, to check what run()
# leaves behind. HARNESS_UNKNOWN_SIGTERM_HANDLER=1 makes the SIGTERM handler that run()
# replaces look like one installed outside Python (signal.signal() returns None, as it does
# under an embedding application). HARNESS_APP_RUN_FAILS=1 makes the transport read one
# line from stdin and then fail. HARNESS_AFTER_RUN is "wait_for_signal" or "read_stdin".
_AFTER_RUN_TAIL = r"""
import select
import signal
import threading

if env.get("HARNESS_UNKNOWN_SIGTERM_HANDLER") == "1":
    _real_signal = signal.signal
    _reported = []

    def _signal(signum, handler):
        previous = _real_signal(signum, handler)
        if signum == signal.SIGTERM and not _reported:
            _reported.append(previous)
            return None
        return previous

    signal.signal = _signal

if env.get("HARNESS_APP_RUN_FAILS") == "1":

    def _failing_run(transport):
        mark(f"APP_RUN_READ {sys.stdin.readline()!r}")
        raise RuntimeError("HARNESS_APP_RUN_FAILS: transport failed")

    service.app.run = _failing_run

try:
    service.run()
    mark("RUN_RETURNED")
except BaseException as error:
    mark(f"RUN_FAILED {type(error).__name__}")
pump_alive = any(t.name == "ghidra-mcp-stdin" and t.is_alive() for t in threading.enumerate())
mark(f"STDIN_PUMP_ALIVE {pump_alive}")
if env["HARNESS_AFTER_RUN"] == "wait_for_signal":
    mark("WAITING_FOR_SIGNAL")
    time.sleep(60)
    mark("STILL_ALIVE_AFTER_WAIT")
else:
    mark("READING_STDIN")
    ready, _, _ = select.select([0], [], [], float(env.get("HARNESS_READ_SECONDS", "10")))
    os.set_blocking(0, False)
    try:
        data = os.read(0, 4096) if ready else b"<timed out>"
    except BlockingIOError:
        data = b"<another reader took it>"
    mark(f"AFTER_RUN_READ {data!r}")
"""

AFTER_RUN_SCRIPT = _FAKE_SERVICE_SETUP + _AFTER_RUN_TAIL

# Child script for the real-Ghidra variant: the same entry point as the ghidra-mcp CLI.
CLI_SCRIPT = LOGGING_PRELUDE + "from ghidra_mcp.cli import main\nmain()\n"

# The CLI service, but sys.stdin hides its file descriptor, like a host application that
# embeds ghidra-mcp with a stdin stream of its own. MCP input still arrives on fd 0.
CLI_NO_STDIN_FD_SCRIPT = (
    LOGGING_PRELUDE
    + r"""
import io
import os


class _NoFilenoStdin(io.RawIOBase):
    def readable(self):
        return True

    def fileno(self):
        raise io.UnsupportedOperation("this stdin has no file descriptor")

    def readinto(self, buffer):
        data = os.read(0, len(buffer))
        buffer[: len(data)] = data
        return len(data)


sys.stdin = io.TextIOWrapper(io.BufferedReader(_NoFilenoStdin()), encoding="utf-8")
from ghidra_mcp.cli import main

main()
"""
)

# AFTER_RUN_SCRIPT with the real CLI settings (environment variables) and real PyGhidra.
CLI_AFTER_RUN_SCRIPT = (
    LOGGING_PRELUDE
    + r"""
import os
import time

from ghidra_mcp.config import load_settings
from ghidra_mcp.service import create_service

env = os.environ


def mark(message):
    print(message, file=sys.stderr, flush=True)


service = create_service(load_settings())
"""
    + _AFTER_RUN_TAIL
)

TEST_TOKEN = "shutdown-test-token-0123456789abcdef"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class ServerProcess:
    process: subprocess.Popen[bytes]
    stderr_lines: list[str] = field(default_factory=list)
    replies: dict[int, dict[str, Any]] = field(default_factory=dict)
    _reply_ready: threading.Condition = field(default_factory=threading.Condition)

    def __post_init__(self) -> None:
        threading.Thread(target=self._pump_stderr, daemon=True).start()
        if self.process.stdout is not None:
            threading.Thread(target=self._pump_stdout, daemon=True).start()

    def _pump_stderr(self) -> None:
        assert self.process.stderr is not None
        for raw in self.process.stderr:
            with self._reply_ready:
                self.stderr_lines.append(raw.decode("utf-8", "replace").rstrip())
                self._reply_ready.notify_all()

    def _pump_stdout(self) -> None:
        assert self.process.stdout is not None
        for raw in self.process.stdout:
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            if isinstance(message, dict) and isinstance(message.get("id"), int):
                with self._reply_ready:
                    self.replies[message["id"]] = message
                    self._reply_ready.notify_all()

    @property
    def stderr(self) -> str:
        with self._reply_ready:
            return "\n".join(self.stderr_lines)

    def send(self, message: dict[str, Any]) -> None:
        self.send_raw((json.dumps(message) + "\n").encode("utf-8"))

    def send_raw(self, data: bytes) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def wait_reply(self, request_id: int, timeout: float) -> dict[str, Any]:
        with self._reply_ready:
            if not self._reply_ready.wait_for(lambda: request_id in self.replies, timeout):
                raise AssertionError(f"no reply to request {request_id}:\n{self.stderr}")
            return self.replies[request_id]

    def line_index(self, needle: str) -> int:
        """Index of the first stderr line containing needle; fails with the full stderr."""

        with self._reply_ready:
            index = next((i for i, line in enumerate(self.stderr_lines) if needle in line), None)
        assert index is not None, f"{needle!r} never logged:\n{self.stderr}"
        return index

    def wait_stderr(self, needle: str, timeout: float) -> None:
        with self._reply_ready:
            if not self._reply_ready.wait_for(
                lambda: any(needle in line for line in self.stderr_lines), timeout
            ):
                raise AssertionError(f"{needle!r} never logged:\n{chr(10).join(self.stderr_lines)}")

    def stdio_initialize(self, timeout: float) -> None:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "shutdown-test", "version": "0"},
                },
            }
        )
        self.wait_reply(1, timeout)
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def stdio_call(self, request_id: int, name: str, arguments: dict[str, Any]) -> None:
        self.send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    def close_stdin(self) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()

    def terminate(self) -> float:
        self.process.send_signal(signal.SIGTERM)
        return time.monotonic()

    def wait_exit(self, timeout: float) -> int | None:
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def start_server(
    script: str,
    *,
    env: dict[str, str],
    cwd: Path,
    stdio: bool,
) -> ServerProcess:
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE if stdio else subprocess.DEVNULL,
        stdout=subprocess.PIPE if stdio else subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={**os.environ, **env},
        cwd=cwd,
    )
    return ServerProcess(process)


def wait_http_ready(port: int, timeout: float) -> None:
    import httpx

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/health", timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise AssertionError("HTTP server never became ready")
