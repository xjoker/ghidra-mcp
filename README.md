# Ghidra MCP

[简体中文](README.zh-CN.md)

A single-process MCP server for headless reverse engineering. One Python process starts the JVM through PyGhidra, manages persistent Ghidra projects, and exposes 35 task-oriented tools to AI clients.

> The security baseline is Ghidra 12.1.3 or later; older installations are rejected before the JVM starts. The container image bundles Ghidra 12.1.4. Streamable HTTP requires a Bearer token, and deployments beyond the local host must terminate TLS at a trusted reverse proxy.

## Project status

The project source is licensed under Apache License 2.0. Ghidra, PyGhidra, the MCP SDK, and other third-party components remain under their respective licenses.

This service is intended for controlled headless analysis, not as a multi-tenant sandbox. Ghidra parses untrusted binaries, and an HTTP token holder can invoke analysis and mutation tools. Use an isolated container, a read-only input mount, a dedicated persistent volume, and minimal network access.

## Container image

The repository contains a GitHub Actions workflow that builds `linux/amd64` with `--no-cache` when a release tag `v<VERSION>` (matching the root `VERSION` file) is pushed, publishes versioned and `latest` tags to GHCR, pulls the published digest, and verifies `/health` against the source version and commit.

Once the GHCR package has been published and its visibility is set to public, pull it without authentication:

```bash
docker pull ghcr.io/xjoker/ghidra-mcp:latest
```

GHCR creates new container packages as private by default. A successful workflow alone does not prove anonymous availability; verify it with an unauthenticated pull.

Run the image with persistent projects and a read-only input directory:

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

The hidden prompt keeps the token value out of shell history. Anyone with Docker daemon access can still inspect container environment variables; restrict daemon access accordingly.

Connect to `http://127.0.0.1:8765/mcp` with `Authorization: Bearer <token>`. The public health endpoint is `http://127.0.0.1:8765/health`.

To build from source, replace `<VERSION>` with the value in the root `VERSION` file:

```bash
docker buildx build \
  --platform linux/amd64 \
  --no-cache \
  --load \
  --build-arg GIT_COMMIT=<full Git commit> \
  --build-arg VERSION=<VERSION> \
  -t ghidra-mcp:<VERSION> .
```

## Local stdio

Requirements: Python 3.11–3.13, Ghidra 12.1.3+, `uv`, and a writable project directory.

```bash
uv sync --locked
cp .env.example .env
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra \
  GHIDRA_MCP_TRANSPORT=stdio \
  uv run ghidra-mcp
```

An MCP client should launch the stdio process itself. The equivalent generic configuration is:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/ghidra-mcp",
        "run",
        "ghidra-mcp"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/absolute/path/to/ghidra",
        "GHIDRA_MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

Field names and configuration locations vary by client. For Streamable HTTP, configure the `/mcp` URL and the Bearer authorization header. This project does not expose Ghidra GUI automation.

## Configuration

Precedence is environment variables > `.env` > TOML > defaults. The default TOML file is `data/config/default.toml`.

| Variable | Default | Purpose |
|---|---:|---|
| `GHIDRA_INSTALL_DIR` | none | Required Ghidra installation directory |
| `GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS` | `300` | Auto-analysis deadline, from 1 to 3600 seconds |
| `GHIDRA_MCP_MAX_WORKERS` | `1` | JVM worker threads, from 1 to 64; read-only calls on a program run in parallel while writes stay serialized per program |
| `GHIDRA_MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |
| `GHIDRA_MCP_HOST` | `127.0.0.1` | HTTP listen address |
| `GHIDRA_MCP_PORT` | `8765` | HTTP port, from 1 to 65535 |
| `GHIDRA_MCP_PUBLIC_URL` | none | Required HTTP(S) root URL seen by clients in HTTP mode |
| `GHIDRA_MCP_STORAGE_ROOT` | `data/projects` | Persistent Ghidra project directory |
| `GHIDRA_MCP_INPUT_ROOT` | none | Required HTTP input boundary; symlinks cannot escape it |
| `GHIDRA_MCP_AUTH_TOKEN` | none | Required HTTP token of at least 32 UTF-8 bytes |

The public URL cannot contain a wildcard host, user information, query string, or path prefix. Secrets are accepted only from environment variables or an untracked `.env`; do not put real tokens in TOML, logs, shell history, or Git.

With `GHIDRA_MCP_MAX_WORKERS > 1`, independent tool calls run on separate JVM worker threads. Read-only calls such as `decompile_function` on the same program run concurrently, while mutating calls take an exclusive per-program lock so Ghidra transactions and saves never overlap. Lifecycle calls (`program_open`, `program_close`) are keyed by the underlying binary, so concurrent sessions of one binary stay serialized. A call waits for its program lock before it takes a worker thread, so a busy program does not hold up calls on other programs; a waiting write is not overtaken by reads that arrive after it; and on exit the server lets running calls finish before it closes programs (see [Shutdown](#shutdown)).

## Shutdown

This applies to every `GHIDRA_MCP_MAX_WORKERS` setting, including the default of 1. The server shuts down on stdin EOF, on a normal transport return, and on SIGTERM (including `docker stop`). In stdio mode SIGTERM stops reading stdin as if it had closed; in HTTP mode uvicorn shuts down gracefully first. The server then lets running tool calls finish and runs `close_all`, which tries to save and close every open program. The process exits with status 0 after stdin EOF and with status 143 after SIGTERM. Replies to calls that were still running are not delivered, because the MCP transport is already closed, but those calls run to completion before `close_all`. A second SIGTERM during the drain is logged and ignored.

The drain has no time limit, so give `docker stop -t` (or your orchestrator's grace period) enough time for the longest call you expect, such as an auto-analysis. SIGKILL after the grace period interrupts the drain; work that was not saved by then is lost.

Saving on shutdown is best effort, not a guarantee:

- If `close_all` raises during shutdown, for example because a program cannot be saved, the server logs a traceback and the process exits with status 1 instead of 0 or 143. `close_all` still tries every other open program, but a program that failed is not saved.
- For roughly the first one to two seconds after the JVM starts, the JVM still handles SIGTERM itself: the process exits at once, with no drain and no `close_all`. The exit status is usually 143, but the JVM can also crash while it is still starting and abort with status 134 (SIGABRT), leaving an `hs_err_pid*.log` file in the working directory. The JVM starts during the first `program_open`, so no program is open yet in that window.
- SIGINT and SIGHUP do not run this shutdown. Once the JVM has started, the JVM handles them and the process exits with status 130 (SIGINT) or 129 (SIGHUP) without `close_all`. Before the JVM starts, SIGHUP kills the process at once without `close_all`. SIGINT before the JVM starts ends the process only after the transport stops: in HTTP mode uvicorn stops at once, while in stdio mode the process waits for the next stdin message or EOF; that message gets no reply. It then runs `close_all` (no program is open yet) and is killed by SIGINT. Stop the server with SIGTERM or by closing stdin.

## Documentation

The [GitHub Wiki](https://github.com/xjoker/ghidra-mcp/wiki) contains the detailed English getting-started guide, tool catalog, and operations runbook.

- [Getting started](https://github.com/xjoker/ghidra-mcp/wiki/Getting-started)
- [Tool catalog](https://github.com/xjoker/ghidra-mcp/wiki/Tool-catalog)
- [Operations](https://github.com/xjoker/ghidra-mcp/wiki/Operations)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Development

The project currently supports source installation and local builds; no PyPI distribution is declared.

```bash
uv sync --locked --extra dev
uv run --locked pytest -m 'not integration' -q
uv run --locked ruff check src tests scripts
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for fixture generation and real Ghidra integration tests.

## License

Project source is available under the [Apache License 2.0](LICENSE). Attribution is recorded in [NOTICE](NOTICE). Third-party components remain under their own licenses.
