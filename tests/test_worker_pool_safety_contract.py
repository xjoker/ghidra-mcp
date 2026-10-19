"""worker 池并发安全的回归测试：关机竞争、队头阻塞、写者饥饿。

时序全部由 threading.Event 控制。唯一带超时的等待是“断言某事件没有发生”，
修复后的实现在任何调度下都不会触发该事件，因此通过方向是确定的；
超时只决定原有缺陷暴露得多快。
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest

from ghidra_mcp.config import Settings
from ghidra_mcp.server import GhidraToolExecutor
from ghidra_mcp.service import MCPService


# 断言“没有发生”时的观察窗口；正确实现与窗口长短无关。
QUIET_WINDOW = 0.5
# 等待“应该发生”的事件的上限，只在出错时才会真正等满。
DEADLINE = 10.0


class Recorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: list[str] = []

    def add(self, event: str) -> None:
        with self._lock:
            self.events.append(event)


def _blocking(recorder: Recorder, tag: str, started: threading.Event, release: threading.Event):
    def call() -> str:
        recorder.add(f"{tag}-start")
        started.set()
        assert release.wait(DEADLINE), f"{tag} 未在期限内被放行"
        recorder.add(f"{tag}-end")
        return tag

    return call


def _instant(recorder: Recorder, tag: str, started: threading.Event | None = None):
    def call() -> str:
        recorder.add(tag)
        if started is not None:
            started.set()
        return tag

    return call


async def _wait_thread_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, DEADLINE), "期望的事件没有发生"


# ---------------------------------------------------------------- 1. 关机竞争


class _FakeApp:
    """模拟传输层：run() 返回即代表事件循环已经退出。"""

    def __init__(self, on_run: Any) -> None:
        self._on_run = on_run

    def run(self, transport: str) -> None:
        self._on_run()


class _FakeWorkspace:
    def __init__(self, recorder: Recorder, entered: threading.Event) -> None:
        self._recorder = recorder
        self._entered = entered

    def close_all(self) -> None:
        self._recorder.add("close_all")
        self._entered.set()


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_shutdown_waits_for_in_flight_tool_calls_before_closing_programs(workers: int) -> None:
    executor = GhidraToolExecutor(max_workers=workers)
    recorder = Recorder()
    read_started = threading.Event()
    release_read = threading.Event()
    close_entered = threading.Event()
    in_flight: dict[str, Any] = {}

    def transport() -> None:
        # 在独立事件循环里发起一个仍在 worker 上运行的读调用，然后让传输层“退出”，
        # 就像客户端断开时还有工具调用没跑完。
        loop = asyncio.new_event_loop()
        try:
            task = loop.create_task(
                executor.run(
                    _blocking(recorder, "read", read_started, release_read),
                    (),
                    {},
                    resource="program-a",
                    exclusive=False,
                )
            )
            loop.run_until_complete(_wait_thread_event(read_started))
            task.cancel()
            loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
        finally:
            loop.close()
        in_flight["cancelled"] = True

    service = MCPService(
        settings=Settings(),
        app=_FakeApp(transport),  # type: ignore[arg-type]
        workspace=_FakeWorkspace(recorder, close_entered),  # type: ignore[arg-type]
        tool_executor=executor,
    )
    runner = threading.Thread(target=service.run)
    runner.start()
    try:
        assert read_started.wait(DEADLINE)
        # 读调用仍在 worker 上：关闭程序不能在此时开始。
        assert close_entered.wait(QUIET_WINDOW) is False, recorder.events
    finally:
        release_read.set()
        runner.join(DEADLINE)
    assert not runner.is_alive()
    assert in_flight.get("cancelled") is True
    assert recorder.events == ["read-start", "read-end", "close_all"]


def test_shutdown_runs_close_all_on_the_single_worker_thread_by_default() -> None:
    executor = GhidraToolExecutor()
    threads: list[int] = []

    class Workspace:
        def close_all(self) -> None:
            threads.append(threading.get_ident())

    def transport() -> None:
        asyncio.run(executor.run(lambda: threads.append(threading.get_ident()), (), {}))

    MCPService(
        settings=Settings(),
        app=_FakeApp(transport),  # type: ignore[arg-type]
        workspace=Workspace(),  # type: ignore[arg-type]
        tool_executor=executor,
    ).run()

    assert len(threads) == 2
    assert threads[0] == threads[1]
    assert threads[0] != threading.get_ident()


# ---------------------------------------------------------------- 2. 队头阻塞


def test_writes_queued_on_one_program_do_not_occupy_workers_needed_by_another() -> None:
    executor = GhidraToolExecutor(max_workers=2)
    recorder = Recorder()
    first_write_started = threading.Event()
    second_write_started = threading.Event()
    release_writes = threading.Event()

    async def exercise() -> None:
        writes = [
            asyncio.create_task(
                executor.run(
                    _blocking(recorder, "write-a1", first_write_started, release_writes),
                    (),
                    {},
                    resource="program-a",
                    exclusive=True,
                )
            ),
            asyncio.create_task(
                executor.run(
                    _blocking(recorder, "write-a2", second_write_started, release_writes),
                    (),
                    {},
                    resource="program-a",
                    exclusive=True,
                )
            ),
        ]
        try:
            await _wait_thread_event(first_write_started)
            # 程序 A 的第二个写还在排队；程序 B 的读必须拿到空闲 worker 立即完成。
            try:
                result = await asyncio.wait_for(
                    executor.run(
                        _instant(recorder, "read-b"),
                        (),
                        {},
                        resource="program-b",
                        exclusive=False,
                    ),
                    timeout=DEADLINE / 2,
                )
            except TimeoutError:
                pytest.fail(f"程序 B 的读被程序 A 的写队列阻塞：{recorder.events}")
            assert result == "read-b"
            assert second_write_started.is_set() is False
        finally:
            release_writes.set()
            await asyncio.gather(*writes)

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert recorder.events.index("read-b") < recorder.events.index("write-a1-end")
    assert recorder.events.index("write-a1-end") < recorder.events.index("write-a2-start")


# ---------------------------------------------------------------- 3. 写者饥饿


def test_waiting_writer_blocks_newly_arriving_readers() -> None:
    executor = GhidraToolExecutor(max_workers=4)
    recorder = Recorder()
    first_read_started = threading.Event()
    release_first_read = threading.Event()
    late_read_started = threading.Event()
    write_started = threading.Event()

    async def exercise() -> None:
        first = asyncio.create_task(
            executor.run(
                _blocking(recorder, "read-1", first_read_started, release_first_read),
                (),
                {},
                resource="program-a",
                exclusive=False,
            )
        )
        await _wait_thread_event(first_read_started)
        write = asyncio.create_task(
            executor.run(
                _instant(recorder, "write", write_started),
                (),
                {},
                resource="program-a",
                exclusive=True,
            )
        )
        # 让写者先登记为等待者，再放进新的读者。
        for _ in range(5):
            await asyncio.sleep(0)
        late = asyncio.create_task(
            executor.run(
                _instant(recorder, "read-late", late_read_started),
                (),
                {},
                resource="program-a",
                exclusive=False,
            )
        )
        try:
            # 有写者在等：新读者不能插队进入。
            entered = await asyncio.to_thread(late_read_started.wait, QUIET_WINDOW)
            assert entered is False, recorder.events
            assert write_started.is_set() is False
        finally:
            release_first_read.set()
            await asyncio.gather(first, write, late)

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert recorder.events == ["read-1-start", "read-1-end", "write", "read-late"]


def test_writer_is_admitted_while_readers_keep_overlapping() -> None:
    """模拟持续重叠的读：每个读者都在下一个读者进入后才退出。"""

    executor = GhidraToolExecutor(max_workers=4)
    recorder = Recorder()
    write_done = threading.Event()
    readers_after_write: list[int] = []

    def make_reader(index: int, started: threading.Event, release: threading.Event):
        def call() -> int:
            started.set()
            assert release.wait(DEADLINE)
            if write_done.is_set():
                readers_after_write.append(index)
            return index

        return call

    async def exercise() -> None:
        starts = [threading.Event() for _ in range(6)]
        releases = [threading.Event() for _ in range(6)]
        tasks = [
            asyncio.create_task(
                executor.run(
                    make_reader(0, starts[0], releases[0]),
                    (),
                    {},
                    resource="program-a",
                    exclusive=False,
                )
            )
        ]
        await _wait_thread_event(starts[0])

        def write() -> str:
            recorder.add("write")
            write_done.set()
            return "write"

        writer = asyncio.create_task(
            executor.run(write, (), {}, resource="program-a", exclusive=True)
        )
        for _ in range(5):
            await asyncio.sleep(0)
        for index in range(1, 6):
            tasks.append(
                asyncio.create_task(
                    executor.run(
                        make_reader(index, starts[index], releases[index]),
                        (),
                        {},
                        resource="program-a",
                        exclusive=False,
                    )
                )
            )
            # 读者优先实现下，新读者在前一个读者释放前就会进入，写者永远等不到。
            await asyncio.to_thread(starts[index].wait, QUIET_WINDOW / 5)
            releases[index - 1].set()
        for release in releases:
            release.set()
        await asyncio.wait_for(writer, DEADLINE)
        await asyncio.gather(*tasks)

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert recorder.events == ["write"]
    # 写者之后到达的读者必须在写完成后才执行。
    assert sorted(readers_after_write) == [1, 2, 3, 4, 5]


# ---------------------------------------------------------------- 闸门细节


def test_cancelled_call_keeps_the_gate_until_its_worker_finishes() -> None:
    """asyncio 取消不能停止 worker 上的调用，所以闸门必须等调用真正结束才释放。"""

    executor = GhidraToolExecutor(max_workers=2)
    recorder = Recorder()
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()

    async def exercise() -> None:
        first = asyncio.create_task(
            executor.run(
                _blocking(recorder, "write-1", first_started, release_first),
                (),
                {},
                resource="program-a",
                exclusive=True,
            )
        )
        await _wait_thread_event(first_started)
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        second = asyncio.create_task(
            executor.run(
                _instant(recorder, "write-2", second_started),
                (),
                {},
                resource="program-a",
                exclusive=True,
            )
        )
        entered = await asyncio.to_thread(second_started.wait, QUIET_WINDOW)
        assert entered is False, recorder.events
        release_first.set()
        assert await second == "write-2"

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert recorder.events == ["write-1-start", "write-1-end", "write-2"]


def test_cancelled_waiter_leaves_the_queue_and_unblocks_readers_behind_it() -> None:
    from ghidra_mcp.concurrency import ProgramGates

    gates = ProgramGates()

    async def exercise() -> None:
        await gates.acquire("p", exclusive=False)
        writer = asyncio.create_task(gates.acquire("p", exclusive=True))
        await asyncio.sleep(0)
        reader = asyncio.create_task(gates.acquire("p", exclusive=False))
        await asyncio.sleep(0)
        assert not reader.done()
        writer.cancel()
        await asyncio.gather(writer, return_exceptions=True)
        await asyncio.wait_for(reader, DEADLINE)
        gates.release("p", exclusive=False)
        gates.release("p", exclusive=False)

    asyncio.run(exercise())
    assert gates.active_keys() == []


@pytest.mark.parametrize("resumed_before_cancel", [False, True])
@pytest.mark.parametrize("exclusive", [True, False])
def test_waiter_cancelled_after_being_granted_hands_the_gate_back(
    exclusive: bool, resumed_before_cancel: bool
) -> None:
    """闸门已经交给等待者、它还没恢复执行就被取消：必须原样交还，否则该程序永久卡住。

    resumed_before_cancel=False：取消发生在唤醒回调 _resolve 运行之前；
    resumed_before_cancel=True：_resolve 已运行（future 已完成），但任务还没恢复执行。
    """

    from ghidra_mcp.concurrency import ProgramGates

    gates = ProgramGates()

    async def exercise() -> None:
        await gates.acquire("p", exclusive=True)
        granted = asyncio.create_task(gates.acquire("p", exclusive=exclusive))
        await asyncio.sleep(0)
        behind = asyncio.create_task(gates.acquire("p", exclusive=True))
        await asyncio.sleep(0)
        # 释放时闸门直接交给排在队首的等待者；排在它后面的写者仍在队列里。
        gates.release("p", exclusive=True)
        assert len(gates._gates["p"].waiters) == 1
        if resumed_before_cancel:
            await asyncio.sleep(0)
        assert not granted.done()
        granted.cancel()
        with pytest.raises(asyncio.CancelledError):
            await granted
        # 被取消的等待者交还了闸门，后面的写者因此进入。
        await asyncio.wait_for(behind, DEADLINE)
        gates.release("p", exclusive=True)

    asyncio.run(exercise())
    assert gates.active_keys() == []


def test_readers_queued_behind_a_writer_enter_together_after_it() -> None:
    from ghidra_mcp.concurrency import ProgramGates

    gates = ProgramGates()

    async def exercise() -> None:
        await gates.acquire("p", exclusive=True)
        readers = [asyncio.create_task(gates.acquire("p", exclusive=False)) for _ in range(3)]
        writer = asyncio.create_task(gates.acquire("p", exclusive=True))
        await asyncio.sleep(0)
        gates.release("p", exclusive=True)
        await asyncio.wait_for(asyncio.gather(*readers), DEADLINE)
        assert not writer.done()
        for _ in readers:
            gates.release("p", exclusive=False)
        await asyncio.wait_for(writer, DEADLINE)
        gates.release("p", exclusive=True)

    asyncio.run(exercise())
    assert gates.active_keys() == []


def test_gate_entries_are_dropped_once_idle() -> None:
    executor = GhidraToolExecutor(max_workers=4)

    async def exercise() -> None:
        await asyncio.gather(
            *(
                executor.run(
                    lambda: None, (), {}, resource=f"program-{index}", exclusive=index % 2 == 0
                )
                for index in range(200)
            )
        )

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()
    assert executor._gates.active_keys() == []


def test_closed_executor_rejects_new_calls_and_releases_their_gate() -> None:
    from ghidra_mcp.server import ExecutorClosedError

    executor = GhidraToolExecutor(max_workers=2)
    executor.shutdown()

    async def exercise() -> None:
        with pytest.raises(ExecutorClosedError):
            await executor.run(lambda: None, (), {}, resource="program-a", exclusive=True)

    asyncio.run(exercise())
    assert executor._gates.active_keys() == []


def test_one_worker_keeps_the_single_thread_submission_order_across_programs() -> None:
    """默认单 worker 时调用严格按提交顺序执行，与原单线程执行器一致。"""

    executor = GhidraToolExecutor()
    recorder = Recorder()
    first_started = threading.Event()
    release_first = threading.Event()

    async def exercise() -> None:
        tasks = [
            asyncio.create_task(
                executor.run(
                    _blocking(recorder, "write-a1", first_started, release_first),
                    (),
                    {},
                    resource="program-a",
                    exclusive=True,
                )
            )
        ]
        await _wait_thread_event(first_started)
        for tag, resource, exclusive in (
            ("write-a2", "program-a", True),
            ("read-b", "program-b", False),
            ("read-a", "program-a", False),
            ("write-b", "program-b", True),
        ):
            tasks.append(
                asyncio.create_task(
                    executor.run(
                        _instant(recorder, tag), (), {}, resource=resource, exclusive=exclusive
                    )
                )
            )
            await asyncio.sleep(0)
        release_first.set()
        await asyncio.gather(*tasks)

    try:
        asyncio.run(exercise())
    finally:
        executor.shutdown()

    assert recorder.events == [
        "write-a1-start",
        "write-a1-end",
        "write-a2",
        "read-b",
        "read-a",
        "write-b",
    ]


@pytest.mark.parametrize("workers", [2, 4])
@pytest.mark.parametrize("cancel_queued", [True, False])
def test_shutdown_lets_a_running_write_finish_and_drops_calls_queued_behind_it(
    workers: int, cancel_queued: bool
) -> None:
    """退出时仍在写程序的调用（例如分析）必须先结束，之后才关闭程序；排在它后面的调用不再执行。"""

    executor = GhidraToolExecutor(max_workers=workers)
    recorder = Recorder()
    write_started = threading.Event()
    release_write = threading.Event()
    close_entered = threading.Event()

    def transport() -> None:
        loop = asyncio.new_event_loop()
        try:
            running = loop.create_task(
                executor.run(
                    _blocking(recorder, "analysis", write_started, release_write),
                    (),
                    {},
                    resource="program-a",
                    exclusive=True,
                )
            )
            loop.run_until_complete(_wait_thread_event(write_started))
            queued = [
                loop.create_task(
                    executor.run(
                        _instant(recorder, tag), (), {}, resource="program-a", exclusive=exclusive
                    )
                )
                for tag, exclusive in (("queued-read", False), ("queued-write", True))
            ]
            # 让排队的调用真正进入闸门队列。
            loop.run_until_complete(asyncio.sleep(0.05))
            assert not any(task.done() for task in queued)
            running.cancel()
            loop.run_until_complete(asyncio.gather(running, return_exceptions=True))
            if cancel_queued:
                for task in queued:
                    task.cancel()
                loop.run_until_complete(asyncio.gather(*queued, return_exceptions=True))
            # cancel_queued=False 时排队的调用随事件循环一起被丢弃，从未被取消。
        finally:
            loop.close()

    service = MCPService(
        settings=Settings(),
        app=_FakeApp(transport),  # type: ignore[arg-type]
        workspace=_FakeWorkspace(recorder, close_entered),  # type: ignore[arg-type]
        tool_executor=executor,
    )
    runner = threading.Thread(target=service.run)
    runner.start()
    try:
        assert write_started.wait(DEADLINE)
        # 写调用仍在 worker 上：关闭程序不能在此时开始。
        assert close_entered.wait(QUIET_WINDOW) is False, recorder.events
    finally:
        release_write.set()
        runner.join(DEADLINE)
    assert not runner.is_alive()
    assert recorder.events == ["analysis-start", "analysis-end", "close_all"]
    assert executor._gates.active_keys() == []


def test_one_worker_does_not_derive_resource_keys() -> None:
    """单 worker 不用闸门，资源键推导不应运行，调用路径与单线程执行器一致。"""

    from ghidra_mcp.registry import ToolDefinition, ToolRegistry
    from ghidra_mcp.server import create_mcp_app

    description = (
        "资源键测试工具。\n\n输入输出与副作用：输入程序会话；返回程序会话；写入。\n\n"
        "何时使用：仅用于验证单 worker 路径。\n"
    )
    namer_calls: list[dict[str, Any]] = []

    def namer(arguments: dict[str, Any]) -> str | None:
        namer_calls.append(arguments)
        raise AssertionError("单 worker 不应推导资源键")

    def probe(program_id: str) -> str:
        return program_id

    def build(workers: int):
        registry = ToolRegistry()
        registry.register(ToolDefinition("probe", description, probe, mutates=True))
        executor = GhidraToolExecutor(max_workers=workers)
        app = create_mcp_app(
            registry,
            host="127.0.0.1",
            port=8765,
            tool_executor=executor,
            resource_namer=namer,
        )
        return app, executor

    app, executor = build(1)
    try:
        asyncio.run(app.call_tool("probe", {"program_id": "p"}))
    finally:
        executor.shutdown()
    assert namer_calls == []

    app, executor = build(2)
    try:
        with pytest.raises(Exception, match="单 worker 不应推导资源键"):
            asyncio.run(app.call_tool("probe", {"program_id": "p"}))
    finally:
        executor.shutdown()
    assert namer_calls == [{"program_id": "p"}]


def test_waiter_abandoned_with_its_event_loop_does_not_release_the_gate_twice() -> None:
    """等待者的事件循环关闭后，闸门由唤醒方代为交还；协程被销毁时不得再释放一次。"""

    import gc
    import sys

    from ghidra_mcp.concurrency import ProgramGates

    gates = ProgramGates()
    unraisable: list[BaseException | None] = []
    previous_hook = sys.unraisablehook
    sys.unraisablehook = lambda record: unraisable.append(record.exc_value)
    try:
        abandoned_loop = asyncio.new_event_loop()
        abandoned_loop.set_exception_handler(lambda _loop, _context: None)
        try:
            abandoned_loop.run_until_complete(gates.acquire("p", exclusive=False))
            waiter = abandoned_loop.create_task(gates.acquire("p", exclusive=True))
            abandoned_loop.run_until_complete(asyncio.sleep(0))
            assert not waiter.done()
        finally:
            abandoned_loop.close()

        # 读者结束：闸门交给已经无法运行的写等待者，再由唤醒方交还，键随之回收。
        gates.release("p", exclusive=False)
        assert gates.active_keys() == []

        async def exercise() -> None:
            await gates.acquire("p", exclusive=True)
            # 销毁被遗弃的等待者协程：它不能释放当前持有者的独占闸门。
            nonlocal waiter
            del waiter
            gc.collect()
            second = asyncio.create_task(gates.acquire("p", exclusive=True))
            for _ in range(5):
                await asyncio.sleep(0)
            assert not second.done(), "被遗弃的等待者重复释放了闸门，第二个写者被放行"
            gates.release("p", exclusive=True)
            await second
            gates.release("p", exclusive=True)

        asyncio.run(exercise())
        gc.collect()
    finally:
        sys.unraisablehook = previous_hook
    assert unraisable == []
    assert gates.active_keys() == []
