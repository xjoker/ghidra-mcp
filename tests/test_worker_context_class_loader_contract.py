"""Tool workers get the system class loader as their Java context class loader (SAF-19 follow-up).

The JVM is created on a detached helper thread, so JPype attaches every tool worker with a
null context class loader. These tests use a fake jpype; the real-JVM check is in
tests/integration/test_real_ghidra_worker_context_class_loader.py.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import sys
import threading
import types
from typing import Any

import pytest

from ghidra_mcp import runtime as runtime_module
from ghidra_mcp import server as server_module
from ghidra_mcp.server import GhidraToolExecutor


class _FakeJava:
    """Just enough of jpype, java.lang.Thread and java.lang.ClassLoader: per-thread TCCLs."""

    def __init__(self) -> None:
        self.started = True
        self.system_loader = object()
        self.loaders: dict[str, Any] = {}
        self.set_calls: list[str] = []
        api = self

        class _JavaThread:
            def __init__(self, name: str) -> None:
                self.name = name

            def getContextClassLoader(self) -> Any:  # noqa: N802 - Java API
                return api.loaders.get(self.name)

            def setContextClassLoader(self, loader: Any) -> None:  # noqa: N802 - Java API
                api.set_calls.append(self.name)
                api.loaders[self.name] = loader

        class Thread:
            @staticmethod
            def currentThread() -> _JavaThread:  # noqa: N802 - Java API
                return _JavaThread(threading.current_thread().name)

        class ClassLoader:
            @staticmethod
            def getSystemClassLoader() -> Any:  # noqa: N802 - Java API
                return api.system_loader

        self.module = types.SimpleNamespace(
            isJVMStarted=lambda: api.started,
            JClass=lambda name: {"java.lang.Thread": Thread, "java.lang.ClassLoader": ClassLoader}[
                name
            ],
        )

    def current_loader(self) -> Any:
        return self.loaders.get(threading.current_thread().name)


@pytest.fixture
def fake_java(monkeypatch: pytest.MonkeyPatch) -> _FakeJava:
    java = _FakeJava()
    monkeypatch.setitem(sys.modules, "jpype", java.module)
    return java


def test_sets_the_system_class_loader_only_when_the_thread_has_none(fake_java: _FakeJava) -> None:
    runtime_module.ensure_context_class_loader()
    assert fake_java.current_loader() is fake_java.system_loader

    custom = object()
    fake_java.loaders[threading.current_thread().name] = custom
    runtime_module.ensure_context_class_loader()
    assert fake_java.current_loader() is custom
    assert fake_java.set_calls == [threading.current_thread().name]


def test_is_a_no_op_without_a_running_jvm(
    fake_java: _FakeJava, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_java.started = False
    runtime_module.ensure_context_class_loader()
    monkeypatch.delitem(sys.modules, "jpype")
    runtime_module.ensure_context_class_loader()
    assert fake_java.set_calls == []


@pytest.mark.parametrize("workers", [1, 2])
def test_every_executor_path_sets_the_loader_on_the_worker_before_the_call(
    fake_java: _FakeJava, workers: int
) -> None:
    executor = GhidraToolExecutor(max_workers=workers)
    seen: list[tuple[str, Any]] = []

    def probe() -> str:
        seen.append((threading.current_thread().name, fake_java.current_loader()))
        return threading.current_thread().name

    assert executor.run_sync(probe).startswith("ghidra-mcp")

    async def run_async() -> None:
        await executor.run(probe, (), {})
        await executor.run(probe, (), {}, resource="program", exclusive=False)

    asyncio.run(run_async())

    barrier = threading.Barrier(workers)

    def on_every_worker() -> str:
        barrier.wait(10)
        return probe()

    futures = [executor._submit(on_every_worker) for _ in range(workers)]
    worker_names = {future.result(10) for future in futures}
    assert len(worker_names) == workers

    executor.close(probe)

    assert len(seen) == 4 + workers
    assert all(loader is fake_java.system_loader for _, loader in seen), seen
    assert set(fake_java.set_calls) == worker_names
    assert "MainThread" not in fake_java.loaders


def test_a_failing_loader_update_is_logged_and_the_call_still_runs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom() -> None:
        raise RuntimeError("no loader")

    monkeypatch.setattr(server_module, "ensure_context_class_loader", boom)
    executor = GhidraToolExecutor(max_workers=1)
    with caplog.at_level(logging.WARNING, logger=server_module.__name__):
        assert executor.run_sync(lambda: 42) == 42
        assert executor.close(lambda: "closed") == "closed"
    assert caplog.text.count("Could not set the worker's context class loader") == 2


def _write_ghidra_install(root: Path) -> Path:
    properties = root / "ghidra" / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.1.4\n", encoding="utf-8")
    return root / "ghidra"


def test_the_thread_that_starts_the_jvm_gets_the_loader_after_the_helper_detached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple[str, str]] = []
    monkeypatch.setattr(runtime_module, "_forward_jvm_sigterm_to_python", lambda: None)
    monkeypatch.setattr(
        runtime_module,
        "_detach_current_thread_from_jvm",
        lambda: events.append(("detach", threading.current_thread().name)),
    )
    monkeypatch.setattr(
        runtime_module,
        "ensure_context_class_loader",
        lambda: events.append(("loader", threading.current_thread().name)),
    )

    class FakePyGhidra:
        def start(self, *, install_dir: Path) -> object:
            return "launcher"

    runtime = runtime_module.GhidraRuntime(
        _write_ghidra_install(tmp_path), pyghidra_module=FakePyGhidra()
    )
    caller = threading.current_thread().name
    assert runtime.ensure_started() == "launcher"
    assert events == [("detach", "ghidra-mcp-jvm-start"), ("loader", caller)]


def test_a_failing_loader_update_does_not_fail_jvm_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> None:
        raise RuntimeError("no loader")

    monkeypatch.setattr(runtime_module, "_forward_jvm_sigterm_to_python", lambda: None)
    monkeypatch.setattr(runtime_module, "_detach_current_thread_from_jvm", lambda: None)
    monkeypatch.setattr(runtime_module, "ensure_context_class_loader", boom)

    class FakePyGhidra:
        def start(self, *, install_dir: Path) -> object:
            return "launcher"

    runtime = runtime_module.GhidraRuntime(
        _write_ghidra_install(tmp_path), pyghidra_module=FakePyGhidra()
    )
    assert runtime.ensure_started() == "launcher"
    assert runtime.ensure_started() == "launcher"
