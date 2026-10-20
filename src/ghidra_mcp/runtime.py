"""PyGhidra JVM 与已打开程序的生命周期所有权。"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import logging
from pathlib import Path
import re
import signal
import sys
import threading
from threading import RLock
from time import monotonic
from types import ModuleType
from typing import Any, Iterator
from uuid import uuid4


_LOGGER = logging.getLogger(__name__)


class WorkspaceError(RuntimeError):
    """程序工作区操作失败。"""


# 最低支持版本。12.1.3 修复了导入 XML `*.bytes` 文件时的路径穿越漏洞（GP-7064），
# 以及 12.1.2 引入的 ELF 导入回归（处理动态 GNU 哈希表和符号表时可能失败，GP-7061）。
# 本服务会导入不可信二进制，因此在启动 JVM 之前拒绝更低的版本。
_MINIMUM_GHIDRA_VERSION = (12, 1, 3)
_MINIMUM_GHIDRA_VERSION_REASON = (
    "12.1.3 修复了导入 XML *.bytes 文件时的路径穿越漏洞（GP-7064），"
    "以及 12.1.2 引入的 ELF 导入回归（处理动态 GNU 哈希表和符号表时可能失败，GP-7061）"
)


def _format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def _read_ghidra_version(install_dir: Path) -> tuple[int, int, int]:
    properties = install_dir / "Ghidra" / "application.properties"
    try:
        lines = properties.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        # Host paths go to the server log only; the client-facing text stays path-free.
        _LOGGER.error("无法确认 Ghidra 版本：未能读取 %s：%s", properties, error)
        raise WorkspaceError(
            "无法确认 Ghidra 版本：未能读取安装目录中的 application.properties"
        ) from error
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == "application.version":
            match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[-._].*)?", value.strip())
            if match is not None:
                major, minor, patch = match.groups()
                return int(major), int(minor), int(patch or 0)
            break
    _LOGGER.error("无法确认 Ghidra 版本：%s 缺少有效的 application.version", properties)
    raise WorkspaceError(
        "无法确认 Ghidra 版本：安装目录中的 application.properties 缺少有效的 application.version"
    )


def _detach_current_thread_from_jvm() -> None:
    """Detach the calling thread from the JVM; a no-op when no real JVM is running."""

    import jpype

    if jpype.isJVMStarted():
        jpype.JClass("java.lang.Thread").detach()


def ensure_context_class_loader() -> None:
    """Give the calling thread the system class loader as its Java context class loader.

    Only the thread that creates the JVM gets ``ghidra.GhidraClassLoader`` as its context
    class loader; threads that JPype attaches later get null. Since the JVM is created on
    a detached helper thread (see ``GhidraRuntime._start_jvm``), every tool worker is such
    an attached thread, and Java code that calls ``getContextClassLoader()`` without a null
    check (ServiceLoader lookups, ``getResource``) would fail on it. Under PyGhidra the
    system class loader is ``GhidraClassLoader``. Leaves a non-null loader untouched, and is
    a no-op until a real JVM runs: jpype is only looked up in ``sys.modules`` so this costs
    nothing before PyGhidra is imported.
    """

    jpype = sys.modules.get("jpype")
    if jpype is None or not jpype.isJVMStarted():
        return
    thread = jpype.JClass("java.lang.Thread").currentThread()
    if thread.getContextClassLoader() is None:
        thread.setContextClassLoader(jpype.JClass("java.lang.ClassLoader").getSystemClassLoader())


# Keeps the Java-side SIGTERM handler proxy (and the handler it replaced) alive.
_JVM_SIGTERM_FORWARDER: list[Any] = []


def _forward_jvm_sigterm_to_python() -> None:
    """Hand SIGTERM back to Python once the JVM has started.

    On start-up the JVM installs its own SIGTERM handler, which runs Java shutdown hooks
    and exits with status 143 without returning to Python, so the drain and ``close_all``
    in ``MCPService.run`` never ran. This replaces the Java handler with one that calls the
    Python-level SIGTERM handler that is current at signal time (ghidra-mcp's own handler,
    or uvicorn's while it serves HTTP). Python's SIG_IGN is honoured. When Python has the
    default disposition, or the Python handler fails, it falls back to the JVM's previous
    handler, so library users that never install a handler keep the old behaviour. The
    handler runs on a JVM signal thread, so Python handlers reached this way must be
    thread-safe; ghidra-mcp's handler and uvicorn's only set flags. A no-op without a
    real JVM.
    """

    import jpype

    if not jpype.isJVMStarted() or _JVM_SIGTERM_FORWARDER:
        return
    previous: list[Any] = []

    @jpype.JImplements("sun.misc.SignalHandler")
    class _SigtermForwarder:
        @jpype.JOverride
        def handle(self, sig: Any) -> None:
            handler = signal.getsignal(signal.SIGTERM)
            if handler == signal.SIG_IGN:
                return
            if callable(handler):
                try:
                    handler(signal.SIGTERM, None)
                    return
                except BaseException:
                    _LOGGER.exception("Python SIGTERM handler failed; using the JVM default")
            previous[0].handle(sig)

    signal_class = jpype.JClass("sun.misc.Signal")
    forwarder = _SigtermForwarder()
    try:
        previous.append(signal_class.handle(signal_class("TERM"), forwarder))
    except Exception:
        # For example -Xrs, or SIGTERM ignored when the JVM started: the JVM then does not
        # own SIGTERM and Python's handler already receives it directly.
        _LOGGER.info("JVM does not own SIGTERM; leaving it to Python", exc_info=True)
        return
    _JVM_SIGTERM_FORWARDER.extend((forwarder, previous))


@dataclass(slots=True)
class _ProgramRecord:
    path: Path
    context: Any
    api: Any


class GhidraRuntime:
    def __init__(
        self,
        install_dir: Path,
        *,
        pyghidra_module: ModuleType | Any | None = None,
        analysis_timeout_seconds: int = 300,
    ) -> None:
        self.install_dir = install_dir.resolve()
        if pyghidra_module is None:
            import pyghidra

            pyghidra_module = pyghidra
        self.pyghidra = pyghidra_module
        self.analysis_timeout_seconds = analysis_timeout_seconds
        self._launcher: object | None = None
        self._lock = RLock()

    def ensure_started(self) -> object:
        with self._lock:
            if self._launcher is None:
                if not self.install_dir.is_dir():
                    _LOGGER.error("Ghidra 安装目录不存在：%s", self.install_dir)
                    raise WorkspaceError(
                        "Ghidra 安装目录不存在：请将 GHIDRA_INSTALL_DIR 指向有效的 Ghidra 安装目录"
                    )
                version = _read_ghidra_version(self.install_dir)
                if version < _MINIMUM_GHIDRA_VERSION:
                    detected = _format_version(version)
                    minimum = _format_version(_MINIMUM_GHIDRA_VERSION)
                    # 绝对安装路径只写服务端日志；返回给 MCP 客户端的错误只含版本与升级说明，
                    # 避免通过 Streamable HTTP 向远程客户端暴露宿主机路径。
                    _LOGGER.error(
                        "拒绝启动 JVM：%s 中的 Ghidra %s 低于最低支持版本 %s",
                        self.install_dir,
                        detected,
                        minimum,
                    )
                    raise WorkspaceError(
                        f"Ghidra {detected} 低于最低支持版本 {minimum}："
                        f"{_MINIMUM_GHIDRA_VERSION_REASON}。"
                        f"请安装 Ghidra {minimum} 或更高版本，"
                        "并将 GHIDRA_INSTALL_DIR 指向新的安装目录"
                    )
                self._launcher = self._start_jvm()
            return self._launcher

    def _start_jvm(self) -> object:
        """Start PyGhidra on a short-lived helper thread that detaches from the JVM before it ends.

        JNI turns the thread that creates the JVM into the non-daemon Java thread "main".
        If that thread ends without detaching (it used to be a tool worker thread), the JVM
        keeps counting it as alive, and the DestroyJavaVM call that JPype makes at
        interpreter exit waits for it forever: the process never exits after stdin EOF.
        The helper detaches right after start-up, so later Java calls from worker threads
        are attached by JPype as daemon threads and nothing blocks JVM shutdown.
        """

        outcome: dict[str, Any] = {}

        def start() -> None:
            try:
                outcome["launcher"] = self.pyghidra.start(install_dir=self.install_dir)
            except BaseException as error:
                outcome["error"] = error
            else:
                try:
                    _forward_jvm_sigterm_to_python()
                except Exception:
                    _LOGGER.warning("Could not route JVM SIGTERM to Python", exc_info=True)
            finally:
                try:
                    _detach_current_thread_from_jvm()
                except Exception:
                    _LOGGER.warning("Could not detach the JVM start-up thread", exc_info=True)

        helper = threading.Thread(target=start, name="ghidra-mcp-jvm-start", daemon=True)
        helper.start()
        helper.join()
        if "error" in outcome:
            raise outcome["error"]
        # The rest of the call that started the JVM runs on this thread with a null
        # context class loader; restore it before returning (see ensure_context_class_loader).
        try:
            ensure_context_class_loader()
        except Exception:
            _LOGGER.warning("Could not set the context class loader", exc_info=True)
        return outcome["launcher"]

    def analyze(self, program: Any) -> None:
        self.ensure_started()
        deadline = monotonic() + self.analysis_timeout_seconds
        monitor = self.pyghidra.task_monitor(self.analysis_timeout_seconds)
        self.pyghidra.analyze(program, monitor=monitor)
        if monitor.isCancelled() and monotonic() >= deadline:
            raise TimeoutError(f"Ghidra 自动分析超过 {self.analysis_timeout_seconds} 秒")

    def program_context(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        analyze: bool,
    ) -> Any:
        test_factory = getattr(self.pyghidra, "_program_context_factory", None)
        if test_factory is not None:
            return test_factory(
                binary,
                project_location=project_location,
                project_name=project_name,
                analyze=analyze,
            )
        return self._modern_program_context(
            binary,
            project_location=project_location,
            project_name=project_name,
            analyze=analyze,
        )

    @contextmanager
    def _modern_program_context(
        self,
        binary: Path,
        *,
        project_location: Path | None,
        project_name: str | None,
        analyze: bool,
    ) -> Iterator[Any]:
        location = project_location or binary.parent
        name = project_name or f"{binary.name}_ghidra"
        project = self.pyghidra.open_project(location, name, create=True)
        project_path = f"/{binary.name}"
        try:
            existing_context = self.pyghidra.program_context(project, project_path)
            try:
                program = existing_context.__enter__()
            except FileNotFoundError:
                pass
            else:
                try:
                    if analyze:
                        self.analyze(program)
                    yield self._flat_api(program)
                except BaseException:
                    if not existing_context.__exit__(*sys.exc_info()):
                        raise
                else:
                    existing_context.__exit__(None, None, None)
                return

            results = (
                self.pyghidra.program_loader()
                .source(str(binary))
                .project(project)
                .name(binary.name)
                .load()
            )
            consumer = self._new_consumer()
            program = results.getPrimaryDomainObject(consumer)
            try:
                if analyze:
                    self.analyze(program)
                results.save(self.pyghidra.task_monitor())
                yield self._flat_api(program)
            finally:
                program.release(consumer)
                results.close()
        finally:
            project.close()

    def _flat_api(self, program: Any) -> Any:
        from ghidra.program.flatapi import FlatProgramAPI

        return FlatProgramAPI(program)

    def _new_consumer(self) -> Any:
        from java.lang import Object

        return Object()

    def save(self, api: Any) -> None:
        """在工具返回成功前持久化当前程序数据库。"""

        api.getCurrentProgram().save("ghidra-mcp", self.pyghidra.task_monitor())


def _persistent_project_name(binary: Path) -> str:
    digest = sha256()
    digest.update(str(binary).encode("utf-8"))
    digest.update(b"\0")
    with binary.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return f"{binary.name}-{digest.hexdigest()[:20]}"


class ProgramWorkspace:
    def __init__(
        self,
        runtime: GhidraRuntime,
        *,
        project_location: Path | None = None,
        input_root: Path | None = None,
    ) -> None:
        self.runtime = runtime
        self.project_location = project_location.resolve() if project_location is not None else None
        self.input_root = input_root.resolve() if input_root is not None else None
        if self.project_location is not None:
            self.project_location.mkdir(parents=True, exist_ok=True)
        self._programs: dict[str, _ProgramRecord] = {}
        self._lock = RLock()

    def open(
        self,
        binary_path: Path,
        *,
        project_location: Path | None = None,
        analyze: bool = True,
    ) -> str:
        binary = binary_path.resolve()
        # The resolved path and the input root are host paths: log them, and echo back only
        # the path exactly as the client supplied it.
        if self.input_root is not None and not binary.is_relative_to(self.input_root):
            _LOGGER.warning("输入路径 %s 超出允许的输入根目录 %s", binary, self.input_root)
            raise WorkspaceError("输入路径超出允许的输入根目录（GHIDRA_MCP_INPUT_ROOT）")
        if not binary.is_file():
            _LOGGER.warning("输入二进制不存在：%s", binary)
            raise WorkspaceError(f"输入二进制不存在：{binary_path}")
        project_name = _persistent_project_name(binary)
        self.runtime.ensure_started()
        effective_location = (
            project_location.resolve() if project_location is not None else self.project_location
        )
        context = self.runtime.program_context(
            binary,
            project_location=effective_location,
            project_name=project_name,
            analyze=analyze,
        )
        api = context.__enter__()
        try:
            if analyze:
                self.runtime.save(api)
        except BaseException:
            context.__exit__(*sys.exc_info())
            raise
        program_id = uuid4().hex
        with self._lock:
            self._programs[program_id] = _ProgramRecord(binary, context, api)
        return program_id

    def get(self, program_id: str) -> Any:
        with self._lock:
            try:
                return self._programs[program_id].api
            except KeyError as error:
                raise WorkspaceError(f"程序会话不存在：{program_id}") from error

    def resource_key(self, program_id: str) -> str:
        """Return a stable resource key for the session's program so that writes from
        different sessions of the same program are mutually exclusive.

        This may be called from the event loop thread or from a pool thread (the server
        resolves resource keys through ``asyncio.to_thread``). It still does not take
        ``self._lock``: ``close()`` saves while holding that lock, so waiting on it here
        would stall the caller. Lock-free reading is safe because a single ``dict.get`` is
        atomic under the CPython GIL, and ``record.path`` never changes while the record
        is alive.
        """

        record = self._programs.get(program_id)
        return str(record.path) if record is not None else program_id

    def list_open(self) -> list[dict[str, str]]:
        with self._lock:
            return [
                {"program_id": program_id, "path": str(record.path)}
                for program_id, record in self._programs.items()
            ]

    def describe(self, program_id: str) -> dict[str, str]:
        program = self.get(program_id).getCurrentProgram()
        return {
            "program_id": program_id,
            "name": str(program.getName()),
            "language": str(program.getLanguageID()),
            "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": str(program.getImageBase()),
            "format": str(program.getExecutableFormat()),
            "min_address": str(program.getMinAddress()),
            "max_address": str(program.getMaxAddress()),
        }

    def close(self, program_id: str) -> None:
        with self._lock:
            try:
                record = self._programs[program_id]
            except KeyError as error:
                raise WorkspaceError(f"程序会话不存在：{program_id}") from error
            self.runtime.save(record.api)
            del self._programs[program_id]
            record.context.__exit__(None, None, None)

    def save(self, program_id: str) -> None:
        self.runtime.save(self.get(program_id))

    def analyze(self, program_id: str) -> None:
        self.runtime.analyze(self.get(program_id).getCurrentProgram())

    def close_all(self) -> None:
        with self._lock:
            program_ids = tuple(self._programs)
        _LOGGER.info("close_all: closing %d open program(s)", len(program_ids))
        failures: list[BaseException] = []
        for program_id in program_ids:
            try:
                self.close(program_id)
            except BaseException as error:
                failures.append(error)
        _LOGGER.info(
            "close_all: finished, %d closed, %d failed",
            len(program_ids) - len(failures),
            len(failures),
        )
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("关闭多个程序会话失败", failures)
