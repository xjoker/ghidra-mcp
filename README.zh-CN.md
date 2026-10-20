# Ghidra MCP

[English](README.md)

面向 headless 逆向分析的单进程 MCP 服务。Python 进程通过 PyGhidra 启动 JVM、管理持久化 Ghidra 项目，并向 AI 客户端暴露 35 个任务导向工具。

> 安全支持基线是 Ghidra 12.1.3+，更低版本会在启动 JVM 前被拒绝。容器镜像内置 Ghidra 12.1.4。Streamable HTTP 必须配置 Bearer token；跨主机部署还必须在可信反向代理终止 TLS。

## 项目状态

项目原创代码采用 Apache License 2.0。Ghidra、PyGhidra、MCP SDK 及其他第三方组件继续适用各自许可证。

本服务适合受控环境中的 headless 静态分析，不是多租户沙箱。Ghidra 会解析不受信任二进制，HTTP token 持有者可以调用分析和写入工具。部署时应使用隔离容器、只读输入挂载、独立持久卷和最小网络权限。

## 容器镜像

仓库包含 GitHub Actions 发布流程：推送与根目录 `VERSION` 文件一致的发版 tag `v<VERSION>` 时，以 `linux/amd64`、`--no-cache` 构建镜像，向 GHCR 推送版本标签和 `latest`，再按远端 digest 拉回，并核验 `/health` 中的版本与 Git commit。

首次发布并把 GHCR package 可见性设为 public 后，可匿名拉取：

```bash
docker pull ghcr.io/xjoker/ghidra-mcp:latest
```

GHCR 新建容器 package 默认可能是 private。Workflow 成功不等于已经能匿名下载，必须再用未登录环境执行 `docker pull` 验证。

启动服务：

```bash
docker volume create ghidra-mcp-projects
(
read -rsp 'Ghidra MCP token: ' GHIDRA_MCP_AUTH_TOKEN && echo
export GHIDRA_MCP_AUTH_TOKEN
docker run -d --name ghidra-mcp \
  --platform linux/amd64 \
  -p 127.0.0.1:8765:8765 \
  -e GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:8765 \
  -e GHIDRA_MCP_AUTH_TOKEN \
  -v ghidra-mcp-projects:/data/projects \
  -v /absolute/path/to/binaries:/data/input:ro \
  ghcr.io/xjoker/ghidra-mcp:latest
)
```

隐藏输入可避免 token 值进入 shell history。拥有 Docker daemon 权限的用户仍可查看容器环境变量，因此必须限制 daemon 访问。

客户端连接 `http://127.0.0.1:8765/mcp` 并发送 `Authorization: Bearer <token>`。公开健康检查位于 `http://127.0.0.1:8765/health`。

从源码构建时，把 `<VERSION>` 替换为根目录 `VERSION` 文件的值：

```bash
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  --load \
  --build-arg GIT_COMMIT=<完整 Git commit> \
  --build-arg VERSION=<VERSION> \
  -t ghidra-mcp:<VERSION> .
```

## 本地 stdio

前置条件：Python 3.11–3.13、Ghidra 12.1.3+、`uv` 和可写的项目目录。

```bash
uv sync --locked
cp .env.example .env
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
  GHIDRA_MCP_TRANSPORT=stdio \
  uv run ghidra-mcp
```

MCP 客户端应自行拉起 stdio 进程。等价通用配置如下：

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/ghidra-mcp", "run", "ghidra-mcp"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/absolute/path/to/ghidra",
        "GHIDRA_MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

不同客户端的字段名和配置位置可能不同。Streamable HTTP 客户端需要配置 `/mcp` URL 和 Bearer header。本项目不暴露 Ghidra GUI 自动化。

## 配置

优先级为环境变量 > `.env` > TOML > 默认值。默认 TOML 位于 `data/config/default.toml`。

| 环境变量 | 默认值 | 说明 |
|---|---:|---|
| `GHIDRA_INSTALL_DIR` | 无 | Ghidra 安装目录；必填 |
| `GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS` | `300` | 自动分析期限，范围 1–3600 秒 |
| `GHIDRA_MCP_MAX_WORKERS` | `1` | JVM worker 线程数，范围 1–64；同一程序的只读调用并行、写入仍逐程序串行 |
| `GHIDRA_MCP_TRANSPORT` | `stdio` | `stdio` 或 `streamable-http` |
| `GHIDRA_MCP_HOST` | `127.0.0.1` | HTTP 监听地址 |
| `GHIDRA_MCP_PORT` | `8765` | HTTP 端口，范围 1–65535 |
| `GHIDRA_MCP_PUBLIC_URL` | 无 | HTTP 模式必填，客户端实际访问的 HTTP(S) 根 URL |
| `GHIDRA_MCP_STORAGE_ROOT` | `data/projects` | Ghidra 项目持久化目录 |
| `GHIDRA_MCP_INPUT_ROOT` | 无 | HTTP 模式输入边界，符号链接不能越界 |
| `GHIDRA_MCP_AUTH_TOKEN` | 无 | HTTP 模式必填，至少 32 个 UTF-8 字节 |

公开 URL 不能包含 wildcard host、用户信息、查询参数或路径前缀。敏感值只从环境变量或未跟踪 `.env` 读取；不要把真实 token 写入 TOML、日志、命令历史或 Git。

当 `GHIDRA_MCP_MAX_WORKERS > 1` 时，互不相关的工具调用会在不同的 JVM worker 线程上运行。同一程序上的只读调用（例如 `decompile_function`）可以并发，写入调用则拿独占的按程序闸门，因此 Ghidra 事务与存盘不会重叠。生命周期调用（`program_open`、`program_close`）按底层二进制键控，同一二进制的并发会话仍会串行。调用先等待程序闸门再占用 worker，因此忙碌的程序不会拖住其它程序上的调用；已在等待的写入不会被晚到的读取插队；退出时，服务器会等正在运行的调用结束后再关闭程序（见[关闭](#关闭)）。

## 关闭

本节适用于任何 `GHIDRA_MCP_MAX_WORKERS` 设置，包括默认值 1。服务器在 stdin EOF、传输正常返回以及收到 SIGTERM（包括 `docker stop`）时关闭。stdio 模式下 SIGTERM 会像 stdin 关闭一样停止读取，HTTP 模式下先让 uvicorn 优雅关闭。随后服务器等正在运行的工具调用结束，再执行 `close_all`，尝试保存并关闭所有已打开的程序。stdin EOF 后进程以状态码 0 退出，SIGTERM 后以状态码 143 退出。仍在运行的调用的回复不会再送达（MCP 传输已经关闭），但这些调用会在 `close_all` 之前运行完毕。排空期间再次收到的 SIGTERM 只记日志，然后被忽略。

排空没有时间上限，请给 `docker stop -t`（或编排系统的宽限期）留出足够时间，覆盖预期最长的调用（例如自动分析）。宽限期过后的 SIGKILL 会打断排空，届时尚未存盘的工作会丢失。

关闭时的存盘是尽力而为，不是保证：

- 如果关闭时 `close_all` 抛出异常（例如某个程序无法存盘），服务器会记录 traceback，进程以状态码 1 退出，而不是 0 或 143。`close_all` 仍会尝试其余所有已打开的程序，但失败的程序不会存盘。
- JVM 启动后大约最初一到两秒内，SIGTERM 仍由 JVM 自己处理：进程立即以状态码 143 退出，不排空，也不执行 `close_all`。JVM 在第一次 `program_open` 时启动，因此这段时间内还没有已打开的程序。
- SIGINT 和 SIGHUP 不走这套关闭流程。JVM 启动后由 JVM 处理它们，进程以状态码 130（SIGINT）或 129（SIGHUP）退出，不执行 `close_all`。请用 SIGTERM 或关闭 stdin 来停止服务器。

## 文档

项目的详细文档以英文为主，统一维护在 [GitHub Wiki](https://github.com/xjoker/ghidra-mcp/wiki)：

- [快速开始](https://github.com/xjoker/ghidra-mcp/wiki/Getting-started)
- [工具目录](https://github.com/xjoker/ghidra-mcp/wiki/Tool-catalog)
- [运维指南](https://github.com/xjoker/ghidra-mcp/wiki/Operations)
- [贡献指南](CONTRIBUTING.md)
- [安全政策](SECURITY.md)

## 开发

当前只支持源码安装和本地构建，尚未声明 PyPI 发布渠道。

```bash
uv sync --locked --extra dev
uv run --locked pytest -m 'not integration' -q
uv run --locked ruff check src tests scripts
```

夹具生成与真实 Ghidra 集成测试见 [贡献指南](CONTRIBUTING.md)。

## 许可证

项目原创代码采用 [Apache License 2.0](LICENSE)，归属声明见 [NOTICE](NOTICE)。第三方组件适用各自许可证。
