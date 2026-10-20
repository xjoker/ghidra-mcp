"""Real-JVM shutdown regression tests (SAF-19).

Before the fix, a ``ghidra-mcp`` stdio process that had started the JVM stayed alive after
stdin EOF (DestroyJavaVM waited forever for the worker thread that created the JVM), and
SIGTERM was handled by the JVM itself (exit 143 without the drain or ``close_all``).
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from shutdown_harness import (  # noqa: E402
    CLI_SCRIPT,
    TEST_TOKEN,
    free_port,
    start_server,
    wait_http_ready,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "generated" / "libsymbolic.so"
OPEN_DEADLINE = 300.0
# The process must be gone within this many seconds of stdin EOF / SIGTERM.
EXIT_BUDGET = 20.0


def _require_ghidra() -> str:
    install_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_value:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not FIXTURE.is_file():
        pytest.skip("先运行 scripts/build_fixtures.py")
    return install_value


def _stdio_server_with_open_program(tmp_path: Path) -> object:
    install_dir = _require_ghidra()
    server = start_server(
        CLI_SCRIPT,
        env={
            "GHIDRA_INSTALL_DIR": install_dir,
            "GHIDRA_MCP_TRANSPORT": "stdio",
            "GHIDRA_MCP_STORAGE_ROOT": str(tmp_path / "projects"),
        },
        cwd=tmp_path,
        stdio=True,
    )
    try:
        server.stdio_initialize(OPEN_DEADLINE)
        server.stdio_call(2, "program_open", {"binary_path": str(FIXTURE), "analyze": True})
        reply = server.wait_reply(2, OPEN_DEADLINE)
        assert not reply["result"].get("isError"), reply
    except BaseException:
        server.kill()
        raise
    return server


@pytest.mark.integration
def test_real_jvm_stdio_process_exits_after_stdin_eof(tmp_path: Path) -> None:
    server = _stdio_server_with_open_program(tmp_path)
    try:
        started = time.monotonic()
        server.close_stdin()
        status = server.wait_exit(EXIT_BUDGET)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert status == 0, f"still alive {EXIT_BUDGET}s after stdin EOF:\n{server.stderr}"
    assert elapsed < EXIT_BUDGET
    assert "close_all: finished, 1 closed, 0 failed" in server.stderr


@pytest.mark.integration
def test_real_jvm_stdio_sigterm_runs_close_all_after_the_jvm_started(tmp_path: Path) -> None:
    server = _stdio_server_with_open_program(tmp_path)
    try:
        started = server.terminate()
        status = server.wait_exit(EXIT_BUDGET)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert status == 128 + signal.SIGTERM, server.stderr
    assert elapsed < EXIT_BUDGET
    assert "SIGTERM received; stopping the transport" in server.stderr
    assert "close_all: finished, 1 closed, 0 failed" in server.stderr


@pytest.mark.integration
def test_real_jvm_streamable_http_sigterm_runs_close_all(tmp_path: Path) -> None:
    import asyncio

    import httpx
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    install_dir = _require_ghidra()
    port = free_port()
    server = start_server(
        CLI_SCRIPT,
        env={
            "GHIDRA_INSTALL_DIR": install_dir,
            "GHIDRA_MCP_TRANSPORT": "streamable-http",
            "GHIDRA_MCP_HOST": "127.0.0.1",
            "GHIDRA_MCP_PORT": str(port),
            "GHIDRA_MCP_PUBLIC_URL": f"http://127.0.0.1:{port}",
            "GHIDRA_MCP_AUTH_TOKEN": TEST_TOKEN,
            "GHIDRA_MCP_INPUT_ROOT": str(FIXTURE.parent),
            "GHIDRA_MCP_STORAGE_ROOT": str(tmp_path / "projects"),
        },
        cwd=tmp_path,
        stdio=False,
    )

    async def open_then_sigterm() -> float:
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        started = 0.0
        try:
            async with httpx.AsyncClient(headers=headers, timeout=OPEN_DEADLINE) as http:
                async with streamable_http_client(
                    f"http://127.0.0.1:{port}/mcp", http_client=http
                ) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        opened = await session.call_tool(
                            "program_open", {"binary_path": str(FIXTURE), "analyze": True}
                        )
                        assert not opened.isError, opened
                        started = server.terminate()
                        await asyncio.to_thread(server.wait_exit, EXIT_BUDGET)
        except Exception:
            # The client raises when the server leaves under a live session.
            pass
        return started

    try:
        wait_http_ready(port, 120)
        started = asyncio.run(open_then_sigterm())
        status = server.wait_exit(EXIT_BUDGET)
        elapsed = time.monotonic() - started
    finally:
        server.kill()
    assert started > 0, server.stderr
    assert status == 128 + signal.SIGTERM, server.stderr
    assert elapsed < EXIT_BUDGET
    assert "close_all: finished, 1 closed, 0 failed" in server.stderr
