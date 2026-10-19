"""Library create_mcp_app worker-pool wiring (Elliot #7 L3 / L4)."""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import pytest

from ghidra_mcp.registry import ToolDefinition, ToolRegistry


DESCRIPTION = """create_mcp_app worker 契约测试工具。

输入输出与副作用：输入程序会话或二进制路径；返回标识；只读。

何时使用：仅用于验证库入口在 max_workers>1 时的接线；真实分析请使用任务工具。
"""


def _registry_with(handler, *, name: str = "probe", mutates: bool = False) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolDefinition(name, DESCRIPTION, handler, mutates=mutates))
    return registry


def test_create_mcp_app_rejects_max_workers_above_one_without_resource_namer() -> None:
    """L3: 库用户开 w>1 却不传会话→二进制映射时必须失败，不能静默用裸 program_resource_key。"""

    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    registry = _registry_with(lambda program_id: program_id)
    match = "max_workers 大于 1 时必须提供 resource_namer"

    with pytest.raises(ValueError, match=match):
        create_mcp_app(registry, host="127.0.0.1", port=8765, max_workers=2)

    with pytest.raises(ValueError, match=match):
        create_mcp_app(
            registry,
            host="127.0.0.1",
            port=8765,
            tool_executor=GhidraToolExecutor(max_workers=2),
        )


def test_create_mcp_app_allows_default_single_worker_without_resource_namer() -> None:
    """默认 CLI / 库路径 worker=1 时不要求 resource_namer（行为与改前一致）。"""

    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    registry = _registry_with(lambda program_id: program_id)
    app = create_mcp_app(registry, host="127.0.0.1", port=8765)
    assert app is not None

    executor = GhidraToolExecutor(max_workers=1)
    try:
        app = create_mcp_app(
            registry,
            host="127.0.0.1",
            port=8765,
            tool_executor=executor,
            max_workers=1,
        )
        assert "probe" in app._tool_manager._tools
    finally:
        executor.shutdown()


def test_create_mcp_app_accepts_max_workers_above_one_with_resource_namer() -> None:
    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    registry = _registry_with(lambda program_id: program_id)
    executor = GhidraToolExecutor(max_workers=2)
    try:
        app = create_mcp_app(
            registry,
            host="127.0.0.1",
            port=8765,
            tool_executor=executor,
            resource_namer=lambda arguments: str(arguments.get("program_id", "")),
        )
        result = asyncio.run(app.call_tool("probe", {"program_id": "p"}))
        assert result is not None
    finally:
        executor.shutdown()


def test_resource_namer_runs_off_the_event_loop_when_workers_exceed_one() -> None:
    """L4: w>1 时推导资源键（含 Path.resolve）不得占用事件循环线程。"""

    from ghidra_mcp.server import GhidraToolExecutor, create_mcp_app

    loop_thread: list[int] = []
    namer_threads: list[int] = []
    resolve_ran = threading.Event()

    def namer(arguments: dict) -> str | None:
        namer_threads.append(threading.get_ident())
        # 真实生产路径会对 binary_path 做 resolve；在此复现并确认不在 loop 线程。
        if "binary_path" in arguments:
            key = str(Path(str(arguments["binary_path"])).resolve())
        else:
            key = str(arguments.get("program_id", ""))
        # 稍作停顿：若误跑在 loop 上，会拖住传输层。
        time.sleep(0.02)
        resolve_ran.set()
        return key

    def probe(binary_path: str) -> str:
        return binary_path

    registry = _registry_with(probe, name="openish")
    executor = GhidraToolExecutor(max_workers=2)
    app = create_mcp_app(
        registry,
        host="127.0.0.1",
        port=8765,
        tool_executor=executor,
        resource_namer=namer,
    )
    tool = app._tool_manager._tools["openish"]

    async def exercise() -> str:
        loop_thread.append(threading.get_ident())
        # 与 namer 并发探测：loop 仍能推进
        tick = asyncio.create_task(asyncio.sleep(0))
        result = await tool.run({"binary_path": "data/sample.bin"})
        await tick
        return result

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert resolve_ran.is_set()
    assert loop_thread and namer_threads
    assert namer_threads[0] != loop_thread[0], (
        f"resource_namer ran on the event-loop thread ({namer_threads[0]})"
    )
