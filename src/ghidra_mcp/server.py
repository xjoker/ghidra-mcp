"""把本地工具注册表绑定到 FastMCP。"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial, wraps
from hashlib import sha256
import hmac
from importlib.metadata import PackageNotFoundError, version as package_version
import inspect
import json
import logging
import os
from pathlib import Path
import re
import subprocess
from threading import Condition
from typing import Any, Callable, Iterable

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .concurrency import ProgramGates, program_resource_key
from .registry import ToolDefinition, ToolRegistry
from .runtime import WorkspaceError, ensure_context_class_loader
from .tools.navigation import ToolInputError


_LOGGER = logging.getLogger(__name__)

# Error types whose text ghidra-mcp writes itself. Each of their messages is audited to be
# free of host paths and may deliberately echo a value the client supplied (for example a
# binary path or a Ghidra data type path), so their text reaches the client unchanged.
# tests/test_client_error_paths_contract.py checks every place that builds one of them.
_CLIENT_SAFE_ERRORS = (WorkspaceError, ToolInputError)

# Something that looks like an absolute host path:
# - a POSIX "/x" that does not continue an ASCII word or a relative "./" / "../" segment
#   (this also covers "file:///x" URLs);
# - a well-known root directory followed by a separator ("/home/", "/srv/", "\Users\", ...)
#   wherever it appears, including right after an ASCII letter, digit, "_" or "."
#   ("projectdir/srv/x"); a root name that only ends a word ("x86/data") is not a path;
# - a Windows drive "C:\" or "C:/", a UNC "\\server" prefix, or a root-relative
#   "\Users\x" with no drive letter, but not a lone escape sequence such as "\n", "\d",
#   "\x41" or "\u00e9" (one that is followed by a further path character still matches);
# - a home directory "~/x" or "~user/x".
# It is deliberately conservative: http(s) URLs and Ghidra category paths such as
# "/Demangler/foo" match too, so foreign errors that contain them are hidden as well.
_WELL_KNOWN_ROOTS = (
    "home|Users|tmp|var|opt|srv|data|workspace|root|mnt|private|etc|usr|Volumes|media"
)
# A backslash escape (a letter, up to three octal digits, \xHH, \uHHHH, \UHHHHHHHH or one
# punctuation character) that no further path character follows.
_LONE_ESCAPE = (
    r"(?:[A-Za-z]|[0-7]{1,3}|x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}"
    r"|[^\sA-Za-z0-9_.~$\\/-])(?![A-Za-z0-9_.~$\\/-])"
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.])/(?=[^\s/])"
    rf"|[/\\](?:{_WELL_KNOWN_ROOTS})(?=[/\\])"
    r"|(?<![A-Za-z0-9])[A-Za-z]:[\\/]"
    r"|\\\\"
    rf"|(?<![A-Za-z0-9_\\])\\(?=[^\s\\])(?!{_LONE_ESCAPE})"
    r"|(?<![A-Za-z0-9_.])~[A-Za-z0-9_.-]*[/\\]"
)


def _host_path_forms(paths: Iterable[Path | str | None]) -> tuple[str, ...]:
    """Return the absolute spellings of the server's configured roots to look for in error text.

    Each root is taken as configured (when absolute), made absolute without resolving
    symlinks, and fully resolved, since Ghidra and the OS may report any of them. Relative
    spellings and the filesystem root itself are skipped: they would match ordinary text.
    """

    forms: set[str] = set()
    for path in paths:
        if path is None:
            continue
        configured = Path(path)
        candidates = [os.path.abspath(configured)]
        if configured.is_absolute():
            candidates.append(str(configured))
        try:
            candidates.append(str(configured.resolve()))
        except (OSError, RuntimeError):
            pass
        for candidate in candidates:
            candidate = candidate.rstrip("/\\")
            if candidate and Path(candidate) != Path(Path(candidate).anchor):
                forms.add(candidate)
    # Longest first, so the log names the most specific match.
    return tuple(sorted(forms, key=len, reverse=True))


def _shows_host_path(text: str, host_paths: tuple[str, ...]) -> bool:
    return _ABSOLUTE_PATH.search(text) is not None or any(path in text for path in host_paths)


class _ClientSafeToolError(RuntimeError):
    """Replaces an error whose text would show host paths to the MCP client."""


def _client_safe_error(
    tool_name: str, error: Exception, host_paths: tuple[str, ...] = ()
) -> Exception | None:
    """Return a path-free stand-in for ``error``, or None when its text may reach the client.

    FastMCP returns ``str(error)`` of any exception a tool raises to the client, over stdio
    and Streamable HTTP alike. Errors that ghidra-mcp does not word itself (Java exceptions
    from Ghidra, ``OSError``, PyGhidra start-up failures, ``Path.resolve`` symlink loops, ...)
    can carry install, project or input paths. Such text is logged server-side in full and
    the client only gets the error type plus, for ``OSError``, its path-free reason.
    ``host_paths`` are the server's configured roots (see ``_host_path_forms``); text that
    contains one is hidden even when the pattern above does not match it.
    """

    if isinstance(error, _CLIENT_SAFE_ERRORS):
        return None
    text = str(error)
    if not _shows_host_path(text, host_paths):
        return None
    _LOGGER.error(
        "工具 %s 失败，错误信息含服务端路径，已对客户端隐去：%s",
        tool_name,
        text,
        exc_info=error,
    )
    reason = ""
    if isinstance(error, OSError) and error.strerror:
        strerror = str(error.strerror)
        if not _shows_host_path(strerror, host_paths):
            reason = f"{strerror}；"
    return _ClientSafeToolError(
        f"{type(error).__name__}：{reason}错误详情包含服务端路径，已对客户端隐去，完整信息见服务端日志"
    )


def _on_worker(call: Callable[[], Any]) -> Callable[[], Any]:
    """Wrap a call so it runs with the system class loader as the worker's context class loader.

    Worker threads are attached to the JVM by JPype with a null context class loader (the
    JVM is created on a detached helper thread). Checking before every call is cheap and
    also covers workers that start after the JVM. A failure here is logged and does not
    fail the tool call.
    """

    def run() -> Any:
        try:
            ensure_context_class_loader()
        except Exception:
            _LOGGER.warning("Could not set the worker's context class loader", exc_info=True)
        return call()

    return run


class ExecutorClosedError(RuntimeError):
    """执行器正在关闭或已经关闭，不再接受新的工具调用。"""


class GhidraToolExecutor:
    """在固定 worker 池上运行 JVM 工具，并按程序串行写、并行读。

    调用先在事件循环上拿到程序闸门，再占用 worker 线程；闸门在 worker 上的调用
    真正结束时才释放。max_workers=1 时唯一的 worker 本身已经串行化所有调用，
    闸门不会增加安全性，因此直接按提交顺序排队，与单线程执行器的顺序完全一致。
    """

    def __init__(self, max_workers: int = 1, *, gates: ProgramGates | None = None) -> None:
        if max_workers < 1:
            raise ValueError("max_workers 必须大于等于 1")
        self.max_workers = max_workers
        self._gates = gates if gates is not None else ProgramGates()
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="ghidra-mcp"
        )
        self._state = Condition()
        self._in_flight = 0
        self._closing = False

    async def run(
        self,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        resource: str | None = None,
        exclusive: bool = False,
    ) -> Any:
        call = partial(function, *args, **kwargs)
        if resource is None or self.max_workers == 1:
            return await asyncio.wrap_future(self._submit(call))
        await self._gates.acquire(resource, exclusive=exclusive)
        try:
            future = self._submit(call)
        except BaseException:
            self._gates.release(resource, exclusive=exclusive)
            raise
        # 闸门跟随 worker 上的调用释放：asyncio 侧被取消时，仍在运行的调用继续持有闸门。
        future.add_done_callback(lambda _: self._gates.release(resource, exclusive=exclusive))
        return await asyncio.wrap_future(future)

    def run_sync(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        return self._submit(partial(function, *args, **kwargs)).result()

    def close(self, finalizer: Callable[[], Any] | None = None) -> Any:
        """停止接收新调用，等待已提交的调用全部结束，再在 worker 上执行 finalizer。

        用于退出清理：finalizer（例如关闭全部程序）不会与仍在运行的工具调用并发。
        """

        with self._state:
            self._closing = True
            self._state.wait_for(lambda: self._in_flight == 0)
        try:
            if finalizer is not None:
                return self._executor.submit(_on_worker(finalizer)).result()
            return None
        finally:
            self._executor.shutdown(wait=True)

    def shutdown(self) -> None:
        self.close()

    def _submit(self, call: Callable[[], Any]) -> Future[Any]:
        with self._state:
            if self._closing:
                raise ExecutorClosedError("服务正在关闭，不再接受新的工具调用")
            self._in_flight += 1
        try:
            future = self._executor.submit(_on_worker(call))
        except BaseException:
            self._finish(None)
            raise
        future.add_done_callback(self._finish)
        return future

    def _finish(self, _future: Future[Any] | None) -> None:
        with self._state:
            self._in_flight -= 1
            if self._in_flight == 0:
                self._state.notify_all()


def _async_handler(
    tool: ToolDefinition,
    executor: GhidraToolExecutor,
    resource_namer: Any,
    host_paths: tuple[str, ...] = (),
) -> Any:
    @wraps(tool.handler)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            # 单 worker 不使用闸门，因此不推导资源键，保持与单线程执行器相同的调用路径。
            # 多 worker 时资源键（含 Path.resolve）放到线程池，避免在事件循环线程上做 realpath/lstat。
            if executor.max_workers > 1:
                resource = await asyncio.to_thread(resource_namer, kwargs)
            else:
                resource = None
            return await executor.run(
                tool.handler,
                args,
                kwargs,
                resource=resource,
                exclusive=tool.mutates,
            )
        except Exception as error:
            replacement = _client_safe_error(tool.name, error, host_paths)
            if replacement is None:
                raise
            raise replacement from error

    return wrapped


class StaticTokenVerifier(TokenVerifier):
    """验证部署者通过环境变量提供的单一 Bearer token。"""

    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token.encode("utf-8")

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token.encode("utf-8"), self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="ghidra-mcp",
            scopes=["mcp"],
            subject="configured-client",
        )


def _schema_version(registry: ToolRegistry) -> str:
    contracts = [
        {
            "name": tool.name,
            "description": tool.description,
            "signature": str(inspect.signature(tool.handler)),
            "contract_version": tool.contract_version,
            "annotations": (
                tool.annotations.model_dump(exclude_none=True)
                if tool.annotations is not None
                else None
            ),
        }
        for tool in registry.enabled_tools()
    ]
    encoded = json.dumps(contracts, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return sha256(encoded).hexdigest()[:16]


def _runtime_version() -> str:
    try:
        return package_version("ghidra-mcp")
    except PackageNotFoundError:
        return "unknown"


def _git_commit() -> str:
    configured = os.environ.get("GHIDRA_MCP_GIT_COMMIT", "").strip()
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def create_mcp_app(
    registry: ToolRegistry,
    *,
    host: str,
    port: int,
    auth_token: str | None = None,
    public_url: str | None = None,
    version: str | None = None,
    git_commit: str | None = None,
    tool_executor: GhidraToolExecutor | None = None,
    max_workers: int = 1,
    resource_namer: Any = None,
    host_paths: Iterable[Path | str | None] = (),
) -> FastMCP:
    """绑定工具注册表到 FastMCP。

    max_workers（或传入的 tool_executor.max_workers）大于 1 时必须提供 resource_namer，
    把 program_id 映射到与 binary_path 相同的底层二进制键（例如
    ``partial(program_resource_key, resolve_program=workspace.resource_key)``）；
    否则同一二进制的各会话不会互斥。默认 CLI 路径走 ``create_service``，已传入该映射。

    host_paths are the server's configured roots (install, storage and input root). A
    foreign error whose text contains one of them is hidden from the client even when it
    does not look like an absolute path; ``create_service`` passes them.
    """

    auth = None
    verifier = None
    if auth_token is not None:
        if public_url is None:
            raise ValueError("启用 HTTP 鉴权时必须提供 public_url")
        base_url = public_url.rstrip("/")
        auth = AuthSettings(
            issuer_url=base_url,
            resource_server_url=f"{base_url}/mcp",
            required_scopes=["mcp"],
            # 静态 Bearer token 不携带 RFC 8707 resource/audience，由 StaticTokenVerifier 自行比对。
            validate_token_resource=False,
        )
        verifier = StaticTokenVerifier(auth_token)
    app = FastMCP(
        "ghidra-mcp",
        host=host,
        port=port,
        auth=auth,
        token_verifier=verifier,
    )
    executor = tool_executor or GhidraToolExecutor(max_workers=max_workers)
    if executor.max_workers > 1 and resource_namer is None:
        raise ValueError(
            "max_workers 大于 1 时必须提供 resource_namer，以便将同一二进制的各会话映射到同一闸门"
        )
    namer = resource_namer or program_resource_key
    known_paths = _host_path_forms(host_paths)
    for tool in registry.enabled_tools():
        app.tool(
            name=tool.name,
            description=tool.description,
            annotations=tool.annotations,
        )(_async_handler(tool, executor, namer, known_paths))

    health_payload = {
        "status": "ok",
        "version": version or _runtime_version(),
        "git_commit": git_commit or _git_commit(),
        "schema_version": _schema_version(registry),
    }

    @app.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_request: Request) -> Response:
        return JSONResponse(health_payload)

    return app
