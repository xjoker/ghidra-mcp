"""PyGhidra JVM 与已打开程序的生命周期所有权。"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import sys
from threading import RLock
from time import monotonic
from types import ModuleType
from typing import Any, Iterator
from uuid import uuid4


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
        raise WorkspaceError(f"无法确认 Ghidra 版本：未能读取 {properties}") from error
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and key.strip() == "application.version":
            match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[-._].*)?", value.strip())
            if match is not None:
                major, minor, patch = match.groups()
                return int(major), int(minor), int(patch or 0)
            break
    raise WorkspaceError(f"无法确认 Ghidra 版本：{properties} 缺少有效的 application.version")


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
                    raise WorkspaceError(f"Ghidra 安装目录不存在：{self.install_dir}")
                version = _read_ghidra_version(self.install_dir)
                if version < _MINIMUM_GHIDRA_VERSION:
                    minimum = _format_version(_MINIMUM_GHIDRA_VERSION)
                    raise WorkspaceError(
                        f"Ghidra {_format_version(version)}（{self.install_dir}）"
                        f"低于最低支持版本 {minimum}：{_MINIMUM_GHIDRA_VERSION_REASON}。"
                        f"请安装 Ghidra {minimum} 或更高版本，"
                        "并将 GHIDRA_INSTALL_DIR 指向新的安装目录"
                    )
                self._launcher = self.pyghidra.start(install_dir=self.install_dir)
            return self._launcher

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
        if self.input_root is not None and not binary.is_relative_to(self.input_root):
            raise WorkspaceError(f"输入路径超出允许的输入根目录：{self.input_root}")
        if not binary.is_file():
            raise WorkspaceError(f"输入二进制不存在：{binary}")
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
        """返回会话底层程序的稳定资源键，使同一程序的不同会话写入互斥。

        在事件循环线程上调用，因此不取 self._lock：close() 持锁期间会存盘，
        取锁会让传输层卡住。单次 dict 读取在 GIL 下是原子的。
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
        failures: list[BaseException] = []
        for program_id in program_ids:
            try:
                self.close(program_id)
            except BaseException as error:
                failures.append(error)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("关闭多个程序会话失败", failures)
