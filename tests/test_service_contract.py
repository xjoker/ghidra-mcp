import asyncio
from pathlib import Path

import pytest


class FakePyGhidra:
    def __init__(self) -> None:
        self.started = False

    def start(self, *, install_dir: Path) -> object:
        self.started = True
        return install_dir


def test_service_builds_default_catalog_without_starting_jvm(tmp_path: Path) -> None:
    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    fake = FakePyGhidra()
    storage_root = tmp_path / "projects"
    settings = Settings(install_dir=install_dir, storage_root=storage_root)

    service = create_service(settings, pyghidra_module=fake)
    tools = asyncio.run(service.app.list_tools())

    assert len(tools) == 35
    assert fake.started is False
    assert service.settings is settings
    assert service.workspace.project_location == storage_root.resolve()
    assert service.tool_executor.max_workers == settings.max_workers


def test_service_threads_configured_max_workers_into_the_executor(tmp_path: Path) -> None:
    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(install_dir=install_dir, max_workers=6)

    service = create_service(settings, pyghidra_module=FakePyGhidra())

    assert service.tool_executor.max_workers == 6


def test_http_service_requires_input_root_even_for_direct_settings(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(
        install_dir=install_dir,
        transport="streamable-http",
        public_url="https://mcp.example",
        auth_token="test-token-0123456789012345678901",
    )

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_INPUT_ROOT"):
        create_service(settings, pyghidra_module=FakePyGhidra())


def test_http_service_requires_token_even_for_direct_settings(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(
        install_dir=install_dir,
        transport="streamable-http",
        input_root=tmp_path,
        auth_token="   ",
    )

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_AUTH_TOKEN"):
        create_service(settings, pyghidra_module=FakePyGhidra())


def test_http_service_rejects_weak_token_even_for_direct_settings(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(
        install_dir=install_dir,
        transport="streamable-http",
        input_root=tmp_path,
        public_url="https://mcp.example",
        auth_token="short-token",
    )

    with pytest.raises(ConfigurationError, match="32"):
        create_service(settings, pyghidra_module=FakePyGhidra())


@pytest.mark.parametrize(
    "auth_token",
    [" " + "x" * 32, "x" * 32 + " ", "x" + " " * 31],
)
def test_http_service_rejects_token_with_edge_whitespace_even_for_direct_settings(
    tmp_path: Path, auth_token: str
) -> None:
    from ghidra_mcp.config import ConfigurationError, Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(
        install_dir=install_dir,
        transport="streamable-http",
        input_root=tmp_path,
        public_url="https://mcp.example",
        auth_token=auth_token,
    )

    with pytest.raises(ConfigurationError, match="首尾空白"):
        create_service(settings, pyghidra_module=FakePyGhidra())


def test_http_service_requires_public_url_even_for_direct_settings(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = Settings(
        install_dir=install_dir,
        transport="streamable-http",
        input_root=tmp_path,
        auth_token="test-token-0123456789012345678901",
    )

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_PUBLIC_URL"):
        create_service(settings, pyghidra_module=FakePyGhidra())


def test_too_old_ghidra_error_reaches_mcp_client_without_install_path(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from mcp.shared.memory import create_connected_server_and_client_session

    from ghidra_mcp.config import Settings
    from ghidra_mcp.service import create_service

    install_dir = tmp_path / "private-host-location" / "ghidra_12.1.2_PUBLIC"
    properties = install_dir / "Ghidra" / "application.properties"
    properties.parent.mkdir(parents=True)
    properties.write_text("application.version=12.1.2\n", encoding="utf-8")
    binary = tmp_path / "inputs" / "sample.so"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF")
    fake = FakePyGhidra()
    service = create_service(
        Settings(install_dir=install_dir, storage_root=tmp_path / "projects"),
        pyghidra_module=fake,
    )

    async def call_program_open() -> object:
        async with create_connected_server_and_client_session(service.app._mcp_server) as client:
            return await client.call_tool(
                "program_open", {"binary_path": str(binary), "analyze": False}
            )

    try:
        with caplog.at_level(logging.ERROR, logger="ghidra_mcp.runtime"):
            result = asyncio.run(call_program_open())
    finally:
        service.tool_executor.close(service.workspace.close_all)

    assert result.isError is True
    client_text = "\n".join(getattr(item, "text", "") for item in result.content)
    assert "Ghidra 12.1.2 低于最低支持版本 12.1.3" in client_text
    assert "GHIDRA_INSTALL_DIR" in client_text
    assert "private-host-location" not in client_text
    assert str(install_dir.resolve()) not in client_text
    assert fake.started is False
    assert any(
        str(install_dir.resolve()) in record.getMessage()
        for record in caplog.records
        if record.name == "ghidra_mcp.runtime"
    )
