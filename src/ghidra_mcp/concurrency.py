"""跨 MCP 调用的程序级共享读 / 独占写闸门。

Ghidra 的 ProgramDB 允许并发读取，但任何事务写入都必须在没有其它读写者时进行。
每个程序资源对应一个闸门：多个只读调用共享进入，写调用独占进入。

闸门是“准入式”的：调用先在事件循环上排队拿到闸门，之后才占用 worker 线程，
因此排队中的调用不会占满线程池、挡住其它程序的调用。闸门按到达顺序排队，
有写者在等时新来的读者排在它后面；写者完成后，队首连续的读者一起进入，
读写双方都不会饿死。释放由 worker 上的调用真正结束时触发，与 asyncio 取消无关。
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Callable


def program_resource_key(
    arguments: dict[str, Any],
    resolve_program: Callable[[str], str] | None = None,
) -> str | None:
    """推导工具调用的程序资源键；非程序工具返回 None。

    binary_path 键为解析后的绝对路径；program_id 键由 resolve_program 映射为
    底层二进制的绝对路径（未提供或会话不存在时为 program_id 本身），
    这样同一二进制的打开、关闭与各会话调用共用一个闸门。
    """

    if "program_id" in arguments:
        program_id = str(arguments["program_id"])
        return resolve_program(program_id) if resolve_program is not None else program_id
    if "binary_path" in arguments:
        return str(Path(str(arguments["binary_path"])).resolve())
    return None


@dataclass(eq=False, slots=True)
class _Waiter:
    exclusive: bool
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[None]
    granted: bool = False
    # 事件循环已关闭、闸门已由 _notify 代为交还；等待者自身不得再释放一次。
    abandoned: bool = False


@dataclass(slots=True)
class _Gate:
    readers: int = 0
    writer: bool = False
    waiters: deque[_Waiter] = field(default_factory=deque)

    def admits(self, exclusive: bool) -> bool:
        if exclusive:
            return not self.writer and self.readers == 0
        return not self.writer

    def take(self, exclusive: bool) -> None:
        if exclusive:
            self.writer = True
        else:
            self.readers += 1

    def drop(self, exclusive: bool) -> None:
        if exclusive:
            if not self.writer:
                raise RuntimeError("释放了未持有的独占闸门")
            self.writer = False
        else:
            if self.readers <= 0:
                raise RuntimeError("释放了未持有的共享闸门")
            self.readers -= 1

    @property
    def idle(self) -> bool:
        return not self.writer and self.readers == 0 and not self.waiters


def _resolve(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


class ProgramGates:
    """按资源键维护共享读、独占写闸门；空闲的键会被回收。"""

    def __init__(self) -> None:
        self._guard = Lock()
        self._gates: dict[str, _Gate] = {}

    async def acquire(self, key: str, *, exclusive: bool) -> None:
        """在事件循环上等待闸门；返回时调用方持有闸门，必须调用 release。"""

        with self._guard:
            gate = self._gates.get(key)
            if gate is None:
                gate = self._gates[key] = _Gate()
            if not gate.waiters and gate.admits(exclusive):
                gate.take(exclusive)
                return
            loop = asyncio.get_running_loop()
            waiter = _Waiter(exclusive, loop, loop.create_future())
            gate.waiters.append(waiter)
        try:
            await waiter.future
        except BaseException:
            with self._guard:
                if waiter.abandoned:
                    raise
                granted = waiter.granted
                # 谁把 granted 置回 False，谁负责交还闸门（与 _notify 的失败分支互斥）。
                waiter.granted = False
                woken: list[_Waiter] = []
                if not granted:
                    gate.waiters.remove(waiter)
                    woken = self._admit_waiters(gate)
                    self._discard_if_idle(key, gate)
            if granted:
                # 闸门已经交给了这个等待者，但它被取消了：原样交还。
                self.release(key, exclusive=exclusive)
            else:
                self._notify(key, woken)
            raise

    def release(self, key: str, *, exclusive: bool) -> None:
        """释放闸门并唤醒可以进入的等待者；可在任意线程调用。"""

        with self._guard:
            gate = self._gates[key]
            gate.drop(exclusive)
            woken = self._admit_waiters(gate)
            self._discard_if_idle(key, gate)
        self._notify(key, woken)

    def active_keys(self) -> list[str]:
        with self._guard:
            return list(self._gates)

    @staticmethod
    def _admit_waiters(gate: _Gate) -> list[_Waiter]:
        woken: list[_Waiter] = []
        while gate.waiters:
            head = gate.waiters[0]
            if not gate.admits(head.exclusive):
                break
            gate.waiters.popleft()
            gate.take(head.exclusive)
            head.granted = True
            woken.append(head)
            if head.exclusive:
                break
        return woken

    def _discard_if_idle(self, key: str, gate: _Gate) -> None:
        if gate.idle and self._gates.get(key) is gate:
            del self._gates[key]

    def _notify(self, key: str, woken: list[_Waiter]) -> None:
        for waiter in woken:
            try:
                waiter.loop.call_soon_threadsafe(_resolve, waiter.future)
            except RuntimeError:
                # 事件循环已经关闭，等待者永远不会运行：把闸门交还给后面的人，
                # 并标记等待者，使它的协程被销毁时不会重复释放。
                with self._guard:
                    owned = waiter.granted
                    waiter.granted = False
                    waiter.abandoned = True
                if owned:
                    self.release(key, exclusive=waiter.exclusive)
