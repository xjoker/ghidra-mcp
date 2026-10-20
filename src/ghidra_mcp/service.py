"""完整 MCP 服务对象的装配与退出清理。"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import partial
import io
import logging
import os
import queue
import select
import signal
import sys
import threading
from typing import Any, Iterator

from mcp.server.fastmcp import FastMCP

from .catalog import build_default_registry
from .concurrency import program_resource_key
from .config import (
    ConfigurationError,
    Settings,
    normalize_http_public_url,
    validate_http_auth_token,
)
from .runtime import SIGTERM_NOT_HANDLED, GhidraRuntime, ProgramWorkspace
from .server import GhidraToolExecutor, create_mcp_app


_LOGGER = logging.getLogger(__name__)

# Exit status after a SIGTERM-triggered shutdown: the conventional 128 + signal number,
# the same status `docker stop` reported before the drain existed.
_SIGTERM_EXIT_STATUS = 128 + signal.SIGTERM


class _InterruptibleStdin(io.RawIOBase):
    """Read-only stand-in for fd 0 whose EOF can be forced from any thread.

    The MCP stdio transport reads stdin on an AnyIO worker thread that cannot be cancelled
    while it is blocked in read(), so a SIGTERM could never end the transport while the
    client keeps stdin open. A daemon thread copies fd 0 into a bounded queue instead;
    ``stop()`` makes the reader see EOF at once, which takes the same graceful path as a
    real stdin EOF. The copying thread is a daemon, so a read that never returns cannot
    block interpreter exit. Where ``select.poll`` exists it waits for input in short polls
    before each read, so after ``release()`` it stops reading fd 0 instead of taking the
    next chunk meant for whoever reads stdin after ``MCPService.run`` returns.

    That is best effort: the copying thread checks for ``stop()``/``release()`` after its
    poll and then reads without holding a lock, so input that is already waiting in fd 0
    when either is called can still be read once more (one chunk of up to 64 KiB, which
    may include bytes that arrive just after the call) and is then dropped. Input that
    arrives while the thread is still in its last poll stays in fd 0.
    """

    _CHUNK_SIZE = 64 * 1024
    _POLL_SECONDS = 0.25

    def __init__(self, fd: int, *, max_chunks: int = 64) -> None:
        super().__init__()
        self._fd = fd
        self._chunks: queue.Queue[bytes] = queue.Queue(maxsize=max_chunks)
        self._pending = b""
        self._at_eof = False
        self._ended = threading.Event()
        self._stopped = False
        self._pump = threading.Thread(target=self._copy, name="ghidra-mcp-stdin", daemon=True)
        self._pump.start()

    def _copy(self) -> None:
        try:
            while not self._ended.is_set():
                if not self._wait_readable():
                    continue
                if self._ended.is_set():
                    # stop()/release() ran during the poll: leave the input for the next reader.
                    break
                chunk = os.read(self._fd, self._CHUNK_SIZE)
                if not chunk:
                    break
                while not self._ended.is_set():
                    try:
                        self._chunks.put(chunk, timeout=0.5)
                        break
                    except queue.Full:
                        continue
        except OSError:
            _LOGGER.warning("Reading stdin failed; treating it as EOF", exc_info=True)
        finally:
            self._end()

    def _wait_readable(self) -> bool:
        """Wait briefly for input (or EOF) on fd 0; True when a read will not block."""

        if not hasattr(select, "poll"):
            return True
        poller = select.poll()
        poller.register(self._fd, select.POLLIN)
        return bool(poller.poll(self._POLL_SECONDS * 1000))

    def stop(self) -> None:
        """Make readers see EOF now, dropping input not yet read. Safe from any thread."""

        self._stopped = True
        self._end()

    def release(self) -> None:
        """Stop, then wait for the copying thread to end so it no longer reads fd 0.

        Without ``select.poll`` the thread may stay blocked in read(); it is not waited for.
        """

        self.stop()
        if hasattr(select, "poll"):
            self._pump.join(4 * self._POLL_SECONDS)

    def _end(self) -> None:
        self._ended.set()
        try:
            self._chunks.put_nowait(b"")
        except queue.Full:
            # The queue is full, so readers are not blocked; they check _ended before reading.
            pass

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self._stopped:
            return 0
        if not self._pending:
            if self._at_eof:
                return 0
            if self._ended.is_set() and self._chunks.empty():
                self._at_eof = True
                return 0
            chunk = self._chunks.get()
            if not chunk or self._stopped:
                self._at_eof = True
                return 0
            self._pending = chunk
        view = memoryview(buffer).cast("B")
        size = min(len(view), len(self._pending))
        view[:size] = self._pending[:size]
        self._pending = self._pending[size:]
        return size


def _stdin_fileno() -> int | None:
    """Return the file descriptor behind sys.stdin, or None when there is none to wrap."""

    try:
        return sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        # io.UnsupportedOperation is an OSError/ValueError subclass (for example under pytest).
        return None


@dataclass(slots=True)
class MCPService:
    settings: Settings
    app: FastMCP
    workspace: ProgramWorkspace
    tool_executor: GhidraToolExecutor
    _terminate_requested: threading.Event = field(
        default_factory=threading.Event, init=False, repr=False
    )
    _draining: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _stdin: _InterruptibleStdin | None = field(default=None, init=False, repr=False)

    def run(self) -> None:
        """Serve until the transport ends, then drain running calls and close all programs.

        The transport ends on stdin EOF (stdio), on a normal transport return, or on
        SIGTERM. On SIGTERM the stdio transport stops reading as if stdin had closed, and
        the HTTP transport lets uvicorn shut down gracefully first. In every case running
        calls finish before ``close_all``. After a SIGTERM-triggered shutdown this raises
        ``SystemExit(143)``. SIGTERM handling is installed only when called on the main
        thread, because Python accepts signal handlers only there.
        """

        with self._sigterm_handling():
            try:
                self.app.run(transport=self.settings.transport)  # type: ignore[arg-type]
            finally:
                self._draining.set()
                _LOGGER.info("shutdown: transport stopped; draining running tool calls")
                # 先排空仍在 worker 上运行的调用，再关闭程序，避免程序在读写途中被保存或释放。
                self.tool_executor.close(self.workspace.close_all)
        if self._terminate_requested.is_set():
            raise SystemExit(_SIGTERM_EXIT_STATUS)

    def _on_sigterm(self, signum: int, _frame: Any) -> Any:
        """SIGTERM handler; also called on a JVM signal thread once the JVM owns SIGTERM.

        Returns ``SIGTERM_NOT_HANDLED`` when called off the main thread with no transport it
        can stop, so the JVM forwarder falls back to the JVM's own SIGTERM handler.
        """

        if self._draining.is_set() or self._terminate_requested.is_set():
            _LOGGER.warning("SIGTERM received again; shutdown is already in progress")
            return None
        if self._stdin is None and threading.current_thread() is not threading.main_thread():
            # A JVM signal thread, and nothing this thread can stop: stdio whose sys.stdin
            # has no file descriptor (embedded use), or a forwarded SIGTERM outside uvicorn's
            # serve window. This thread cannot end the transport, and
            # _thread.interrupt_main() does not wake a loop idle in select(), so recording
            # the request here would swallow the signal. The JVM's handler takes it instead:
            # Java shutdown hooks run and the process exits 143, without drain or close_all.
            _LOGGER.warning(
                "SIGTERM received on a JVM thread with no transport to stop; "
                "leaving it to the JVM (no drain, no close_all)"
            )
            return SIGTERM_NOT_HANDLED
        self._terminate_requested.set()
        _LOGGER.warning("SIGTERM received; stopping the transport, then draining running calls")
        if self._stdin is not None:
            self._stdin.stop()
            return None
        # Main thread. streamable-http: uvicorn handles SIGTERM itself while serving and
        # re-raises it afterwards; this handler sees it then, or before uvicorn has started
        # serving. Also stdio when stdin has no file descriptor to wrap, before the JVM has
        # started (afterwards SIGTERM arrives on a JVM thread, above). SystemExit ends the
        # event loop and the finally block in run() still drains and runs close_all. For
        # stdio without a file descriptor that is not immediate: the transport's stdin read
        # cannot be cancelled, so the process exits (143) only at the next stdin message,
        # which gets no reply, or at stdin EOF.
        raise SystemExit(_SIGTERM_EXIT_STATUS)

    @contextmanager
    def _sigterm_handling(self) -> Iterator[None]:
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        previous_handler = signal.signal(signal.SIGTERM, self._on_sigterm)
        previous_stdin = sys.stdin
        stdin_fd = _stdin_fileno() if self.settings.transport == "stdio" else None
        if stdin_fd is not None:
            self._stdin = _InterruptibleStdin(stdin_fd)
            sys.stdin = io.TextIOWrapper(
                io.BufferedReader(self._stdin), encoding="utf-8", errors="replace"
            )
        try:
            yield
        finally:
            sys.stdin = previous_stdin
            if self._stdin is not None:
                # After an error in run() the copying thread would otherwise keep reading fd 0.
                self._stdin.release()
            self._stdin = None
            # None means the previous handler was installed outside Python and cannot be
            # restored. Leaving ours would ignore every later SIGTERM (_draining stays set),
            # so fall back to the default disposition.
            signal.signal(
                signal.SIGTERM,
                signal.SIG_DFL if previous_handler is None else previous_handler,
            )


def create_service(settings: Settings, *, pyghidra_module: Any | None = None) -> MCPService:
    if settings.install_dir is None:
        raise ConfigurationError("必须通过 GHIDRA_INSTALL_DIR 或 TOML 配置 Ghidra 安装目录")
    public_url = None
    if settings.transport == "streamable-http":
        validate_http_auth_token(settings.auth_token)
        public_url = normalize_http_public_url(settings.public_url)
    if settings.transport == "streamable-http" and settings.input_root is None:
        raise ConfigurationError("streamable-http 必须设置 GHIDRA_MCP_INPUT_ROOT")
    runtime = GhidraRuntime(
        settings.install_dir,
        pyghidra_module=pyghidra_module,
        analysis_timeout_seconds=settings.analysis_timeout_seconds,
    )
    workspace = ProgramWorkspace(
        runtime,
        project_location=settings.storage_root,
        input_root=settings.input_root,
    )
    resource_namer = partial(program_resource_key, resolve_program=workspace.resource_key)
    registry = build_default_registry(workspace)
    tool_executor = GhidraToolExecutor(max_workers=settings.max_workers)
    app = create_mcp_app(
        registry,
        host=settings.host,
        port=settings.port,
        auth_token=settings.auth_token if settings.transport == "streamable-http" else None,
        public_url=public_url,
        tool_executor=tool_executor,
        resource_namer=resource_namer,
        # Configured roots as given and as resolved: foreign errors naming any of them are
        # hidden from clients even when the text does not look like an absolute path.
        host_paths=(
            settings.install_dir,
            runtime.install_dir,
            settings.storage_root,
            workspace.project_location,
            settings.input_root,
            workspace.input_root,
        ),
    )
    return MCPService(
        settings=settings,
        app=app,
        workspace=workspace,
        tool_executor=tool_executor,
    )
