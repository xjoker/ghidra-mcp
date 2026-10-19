"""服务配置加载与边界校验。"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from socket import inet_aton
from typing import Mapping
import os
import tomllib
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """配置文件或环境变量不符合公开契约。"""


def validate_http_auth_token(token: str | None) -> None:
    if token is None or not token.strip():
        raise ConfigurationError("streamable-http 必须设置 GHIDRA_MCP_AUTH_TOKEN")
    if token != token.strip():
        raise ConfigurationError("GHIDRA_MCP_AUTH_TOKEN 不允许包含首尾空白")
    if len(token.encode("utf-8")) < 32:
        raise ConfigurationError("GHIDRA_MCP_AUTH_TOKEN 至少需要 32 个 UTF-8 字节")


@dataclass(frozen=True, slots=True)
class Settings:
    install_dir: Path | None = None
    analysis_timeout_seconds: int = 300
    max_workers: int = 1
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8765
    storage_root: Path = Path("data/projects")
    input_root: Path | None = None
    public_url: str | None = None
    auth_token: str | None = field(default=None, repr=False)


_ALLOWED_KEYS = {
    "ghidra": {"install_dir", "analysis_timeout_seconds"},
    "server": {"transport", "host", "port", "public_url", "max_workers"},
    "storage": {"root", "input_root"},
}


def _read_toml(path: Path | None) -> dict[str, object]:
    if path is None or not path.exists():
        return {}
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    for section, values in document.items():
        if section not in _ALLOWED_KEYS:
            raise ConfigurationError(f"未知配置节 {section}，来源 {path.name}")
        if not isinstance(values, dict):
            raise ConfigurationError(f"配置节 {section} 必须是表，来源 {path.name}")
        for key in values:
            if key not in _ALLOWED_KEYS[section]:
                raise ConfigurationError(f"未知配置键 {section}.{key}，来源 {path.name}")
    return document


def _read_dotenv(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not key.strip():
            raise ConfigurationError(f"无效 .env 行 {line_number}，来源 {path.name}")
        key = key.strip()
        if (
            key == "GHIDRA_MCP_AUTH_TOKEN"
            and len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {'"', "'"}
        ):
            value = value[1:-1]
        elif key != "GHIDRA_MCP_AUTH_TOKEN":
            value = value.strip().strip('"').strip("'")
        values[key] = value
    return values


def _integer(value: object, *, key: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{key} 必须是整数，实际为 {value!r}") from error


def normalize_http_public_url(value: str | None) -> str:
    if value is None or not value.strip():
        raise ConfigurationError("streamable-http 必须设置 GHIDRA_MCP_PUBLIC_URL")
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("GHIDRA_MCP_PUBLIC_URL 必须是有效的 HTTP(S) 根 URL") from error
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or _is_unspecified_host(hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in parsed.netloc)
    ):
        raise ConfigurationError("GHIDRA_MCP_PUBLIC_URL 必须是有效的 HTTP(S) 根 URL")
    normalized = f"{parsed.scheme}://{parsed.hostname}"
    if ":" in parsed.hostname:
        normalized = f"{parsed.scheme}://[{parsed.hostname}]"
    if port is not None:
        normalized = f"{normalized}:{port}"
    return normalized


def _is_unspecified_host(hostname: str) -> bool:
    candidate = hostname.removesuffix(".")
    try:
        address = ip_address(candidate)
        mapped_address = getattr(address, "ipv4_mapped", None)
        return address.is_unspecified or (
            mapped_address is not None and mapped_address.is_unspecified
        )
    except ValueError:
        try:
            return inet_aton(candidate) == b"\0\0\0\0"
        except OSError:
            return False


def load_settings(
    *,
    config_path: Path | None = Path("data/config/default.toml"),
    dotenv_path: Path | None = Path(".env"),
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """按环境变量、.env、TOML、默认值的顺序合并配置。"""

    document = _read_toml(config_path)
    dotenv = _read_dotenv(dotenv_path)
    environment = os.environ if environ is None else environ

    server = document.get("server", {})
    ghidra = document.get("ghidra", {})
    storage = document.get("storage", {})
    assert isinstance(server, dict) and isinstance(ghidra, dict) and isinstance(storage, dict)

    def value(
        env_key: str, toml_values: dict[str, object], toml_key: str, default: object
    ) -> object:
        return environment.get(env_key, dotenv.get(env_key, toml_values.get(toml_key, default)))

    transport = str(value("GHIDRA_MCP_TRANSPORT", server, "transport", "stdio"))
    if transport not in {"stdio", "streamable-http"}:
        raise ConfigurationError("server.transport 必须是 stdio 或 streamable-http")
    auth_token = environment.get("GHIDRA_MCP_AUTH_TOKEN", dotenv.get("GHIDRA_MCP_AUTH_TOKEN", ""))
    auth_token = auth_token or None
    if transport == "streamable-http":
        validate_http_auth_token(auth_token)
    input_value = value("GHIDRA_MCP_INPUT_ROOT", storage, "input_root", "")
    input_root = Path(str(input_value)).resolve() if input_value else None
    if transport == "streamable-http" and input_root is None:
        raise ConfigurationError("streamable-http 必须设置 GHIDRA_MCP_INPUT_ROOT")
    install_value = value("GHIDRA_INSTALL_DIR", ghidra, "install_dir", "")
    install_dir = Path(str(install_value)).resolve() if install_value else None
    analysis_timeout_seconds = _integer(
        value(
            "GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS",
            ghidra,
            "analysis_timeout_seconds",
            300,
        ),
        key="ghidra.analysis_timeout_seconds",
    )
    if not 1 <= analysis_timeout_seconds <= 3600:
        raise ConfigurationError("ghidra.analysis_timeout_seconds 必须在 1 到 3600 之间")
    max_workers = _integer(
        value("GHIDRA_MCP_MAX_WORKERS", server, "max_workers", 1),
        key="server.max_workers",
    )
    if not 1 <= max_workers <= 64:
        raise ConfigurationError("server.max_workers 必须在 1 到 64 之间")
    port = _integer(value("GHIDRA_MCP_PORT", server, "port", 8765), key="server.port")
    if not 1 <= port <= 65535:
        raise ConfigurationError("server.port 必须在 1 到 65535 之间")
    public_url_value = str(value("GHIDRA_MCP_PUBLIC_URL", server, "public_url", "")).strip()
    public_url = (
        normalize_http_public_url(public_url_value) if transport == "streamable-http" else None
    )

    return Settings(
        install_dir=install_dir,
        analysis_timeout_seconds=analysis_timeout_seconds,
        max_workers=max_workers,
        transport=transport,
        host=str(value("GHIDRA_MCP_HOST", server, "host", "127.0.0.1")),
        port=port,
        storage_root=Path(str(value("GHIDRA_MCP_STORAGE_ROOT", storage, "root", "data/projects"))),
        input_root=input_root,
        public_url=public_url,
        auth_token=auth_token,
    )
