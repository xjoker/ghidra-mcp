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
import os
from pathlib import Path
import subprocess
from threading import Condition
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .concurrency import ProgramGates, program_resource_key
from .registry import ToolDefinition, ToolRegistry


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
                return self._executor.submit(finalizer).result()
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
            future = self._executor.submit(call)
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


def _async_handler(tool: ToolDefinition, executor: GhidraToolExecutor, resource_namer: Any) -> Any:
    @wraps(tool.handler)
    async def wrapped(*args: Any, **kwargs: Any) -> Any:
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
) -> FastMCP:
    """绑定工具注册表到 FastMCP。

    max_workers（或传入的 tool_executor.max_workers）大于 1 时必须提供 resource_namer，
    把 program_id 映射到与 binary_path 相同的底层二进制键（例如
    ``partial(program_resource_key, resolve_program=workspace.resource_key)``）；
    否则同一二进制的各会话不会互斥。默认 CLI 路径走 ``create_service``，已传入该映射。
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
    for tool in registry.enabled_tools():
        app.tool(
            name=tool.name,
            description=tool.description,
            annotations=tool.annotations,
        )(_async_handler(tool, executor, namer))

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
