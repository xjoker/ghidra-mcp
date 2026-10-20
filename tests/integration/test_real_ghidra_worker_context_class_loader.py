"""Real-JVM check of the tool worker threads' context class loader (SAF-19 follow-up).

Since SAF-19 the JVM is created on a short-lived helper thread that detaches, so every tool
worker is attached to the JVM by JPype and starts with a null context class loader. Before
SAF-19 the single default worker created the JVM itself and had ``ghidra.GhidraClassLoader``.
``GhidraToolExecutor`` restores the system class loader (``GhidraClassLoader`` under
PyGhidra) on its workers. Each case runs in a fresh process so the first tool call is the
one that starts the JVM, as in the server.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

FIXTURE = Path(__file__).parents[1] / "fixtures" / "generated" / "libsymbolic.so"
DEADLINE = 300.0

_PROBE = r"""
import json
import sys
import threading
from pathlib import Path

from ghidra_mcp.catalog import build_default_registry
from ghidra_mcp.runtime import GhidraRuntime, ProgramWorkspace
from ghidra_mcp.server import GhidraToolExecutor

install_dir, fixture, projects, workers = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])


def context_class_loader(where):
    from java.lang import ClassLoader, Thread

    loader = Thread.currentThread().getContextClassLoader()
    return {
        "where": where,
        "thread": threading.current_thread().name,
        "loader": None if loader is None else str(loader.getClass().getName()),
        "is_system": loader is not None and bool(loader.equals(ClassLoader.getSystemClassLoader())),
    }


workspace = ProgramWorkspace(GhidraRuntime(Path(install_dir)), project_location=Path(projects))
tools = {tool.name: tool.handler for tool in build_default_registry(workspace).enabled_tools()}
executor = GhidraToolExecutor(max_workers=workers)
report = {"workers": workers, "probes": []}


def open_program():
    # The first tool call starts the JVM on this worker; probe the rest of the same call.
    opened = tools["program_open"](fixture, analyze=True)
    return opened["program_id"], context_class_loader("first call, after JVM start")


program_id, probe = executor.run_sync(open_program)
report["probes"].append(probe)

barrier = threading.Barrier(workers)


def on_every_worker():
    barrier.wait(60)
    return context_class_loader("later call")


futures = [executor._submit(on_every_worker) for _ in range(workers)]
report["probes"].extend(future.result(300) for future in futures)


def decompile():
    functions = tools["functions_list"](program_id, offset=0, limit=1000)
    entry = next(f["entry_point"] for f in functions if f["name"] == "fixture_symbolic")
    return tools["decompile_function"](program_id, entry, 60)["c"]


report["decompiled"] = "fixture_symbolic" in executor.run_sync(decompile)


def finalize():
    report["probes"].append(context_class_loader("close finalizer"))
    workspace.close_all()


executor.close(finalize)
from java.lang import ClassLoader

report["system_loader"] = str(ClassLoader.getSystemClassLoader().getClass().getName())
print("PROBE " + json.dumps(report), flush=True)
"""


@pytest.mark.integration
@pytest.mark.parametrize("workers", [1, 2])
def test_real_jvm_tool_workers_use_the_system_context_class_loader(
    tmp_path: Path, workers: int
) -> None:
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        pytest.skip("GHIDRA_INSTALL_DIR 未配置")
    if not FIXTURE.is_file():
        pytest.skip("先运行 scripts/build_fixtures.py")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _PROBE,
            install_dir,
            str(FIXTURE),
            str(tmp_path / "projects"),
            str(workers),
        ],
        capture_output=True,
        text=True,
        timeout=DEADLINE,
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    line = next((line for line in completed.stdout.splitlines() if line.startswith("PROBE ")), None)
    assert line is not None, completed.stdout + completed.stderr
    report = json.loads(line.removeprefix("PROBE "))

    assert report["system_loader"] == "ghidra.GhidraClassLoader"
    probes = report["probes"]
    later = [probe for probe in probes if probe["where"] == "later call"]
    assert len({probe["thread"] for probe in later}) == workers, probes
    for probe in probes:
        assert probe["loader"] == "ghidra.GhidraClassLoader", json.dumps(probes, indent=1)
        assert probe["is_system"], json.dumps(probes, indent=1)
    assert report["decompiled"]
