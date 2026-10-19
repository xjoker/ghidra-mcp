from pathlib import Path
from types import SimpleNamespace

import pytest


def test_environment_overrides_dotenv_toml_and_defaults(tmp_path: Path) -> None:
    from ghidra_mcp.config import load_settings

    config = tmp_path / "settings.toml"
    config.write_text('[server]\ntransport = "stdio"\nport = 7000\n', encoding="utf-8")
    dotenv = tmp_path / ".env"
    dotenv.write_text("GHIDRA_MCP_PORT=7001\n", encoding="utf-8")

    settings = load_settings(
        config_path=config,
        dotenv_path=dotenv,
        environ={"GHIDRA_MCP_PORT": "7002"},
    )

    assert settings.port == 7002


def test_unknown_toml_key_reports_key_and_source(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    config = tmp_path / "settings.toml"
    config.write_text("[server]\nporrt = 7000\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"server\.porrt.*settings\.toml"):
        load_settings(config_path=config, dotenv_path=None, environ={})


def test_unimplemented_tool_groups_fail_instead_of_being_silently_ignored(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    config = tmp_path / "settings.toml"
    config.write_text('[tools]\ngroups = ["advanced"]\n', encoding="utf-8")

    with pytest.raises(ConfigurationError, match=r"未知配置节 tools.*settings\.toml"):
        load_settings(config_path=config, dotenv_path=None, environ={})


def test_runtime_path_and_transport_are_validated_at_configuration_boundary(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    install_dir = tmp_path / "ghidra"
    install_dir.mkdir()
    settings = load_settings(
        config_path=None,
        dotenv_path=None,
        environ={
            "GHIDRA_INSTALL_DIR": str(install_dir),
            "GHIDRA_MCP_TRANSPORT": "streamable-http",
            "GHIDRA_MCP_AUTH_TOKEN": "test-token-0123456789012345678901",
            "GHIDRA_MCP_INPUT_ROOT": str(tmp_path),
            "GHIDRA_MCP_PUBLIC_URL": "https://mcp.example",
        },
    )
    assert settings.install_dir == install_dir.resolve()
    assert settings.transport == "streamable-http"

    with pytest.raises(ConfigurationError, match="transport"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={"GHIDRA_MCP_TRANSPORT": "websocket"},
        )


def test_streamable_http_requires_auth_token_and_input_root(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_AUTH_TOKEN"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={"GHIDRA_MCP_TRANSPORT": "streamable-http"},
        )

    with pytest.raises(ConfigurationError, match="32"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={
                "GHIDRA_MCP_TRANSPORT": "streamable-http",
                "GHIDRA_MCP_AUTH_TOKEN": "short-token",
                "GHIDRA_MCP_INPUT_ROOT": str(tmp_path),
                "GHIDRA_MCP_PUBLIC_URL": "https://mcp.example",
            },
        )

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_INPUT_ROOT"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={
                "GHIDRA_MCP_TRANSPORT": "streamable-http",
                "GHIDRA_MCP_AUTH_TOKEN": "test-token-0123456789012345678901",
            },
        )


@pytest.mark.parametrize(
    "auth_token",
    [" " + "x" * 32, "x" * 32 + " "],
)
def test_streamable_http_rejects_environment_token_with_edge_whitespace(
    tmp_path: Path, auth_token: str
) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    with pytest.raises(ConfigurationError, match="首尾空白"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={
                "GHIDRA_MCP_TRANSPORT": "streamable-http",
                "GHIDRA_MCP_AUTH_TOKEN": auth_token,
                "GHIDRA_MCP_INPUT_ROOT": str(tmp_path),
                "GHIDRA_MCP_PUBLIC_URL": "https://mcp.example",
            },
        )


def test_streamable_http_requires_an_explicit_valid_public_url(tmp_path: Path) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    base = {
        "GHIDRA_MCP_TRANSPORT": "streamable-http",
        "GHIDRA_MCP_AUTH_TOKEN": "test-token-0123456789012345678901",
        "GHIDRA_MCP_INPUT_ROOT": str(tmp_path),
    }
    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_PUBLIC_URL"):
        load_settings(config_path=None, dotenv_path=None, environ=base)
    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_PUBLIC_URL"):
        load_settings(
            config_path=None,
            dotenv_path=None,
            environ={**base, "GHIDRA_MCP_PUBLIC_URL": "file:///tmp/mcp"},
        )

    settings = load_settings(
        config_path=None,
        dotenv_path=None,
        environ={**base, "GHIDRA_MCP_PUBLIC_URL": "https://mcp.example/"},
    )

    assert settings.public_url == "https://mcp.example"


@pytest.mark.parametrize(
    "public_url",
    [
        "http://[0:0:0:0:0:0:0:0]",
        "http://0",
        "http://0x0",
        "http://0000",
        "http://0.0.0.0.",
    ],
)
def test_public_url_rejects_semantically_unspecified_hosts(public_url: str) -> None:
    from ghidra_mcp.config import ConfigurationError, normalize_http_public_url

    with pytest.raises(ConfigurationError, match="GHIDRA_MCP_PUBLIC_URL"):
        normalize_http_public_url(public_url)


def test_unspecified_host_checks_mapped_ipv4_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ghidra_mcp.config as config

    mapped_zero = SimpleNamespace(is_unspecified=True)
    python_312_address = SimpleNamespace(
        is_unspecified=False,
        ipv4_mapped=mapped_zero,
    )
    monkeypatch.setattr(config, "ip_address", lambda _: python_312_address)

    assert config._is_unspecified_host("::ffff:0.0.0.0") is True


def test_public_url_rejects_mapped_ipv4_unspecified_across_python_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ghidra_mcp.config as config

    mapped_zero = SimpleNamespace(is_unspecified=True)
    python_312_address = SimpleNamespace(
        is_unspecified=False,
        ipv4_mapped=mapped_zero,
    )
    monkeypatch.setattr(config, "ip_address", lambda _: python_312_address)

    with pytest.raises(config.ConfigurationError, match="GHIDRA_MCP_PUBLIC_URL"):
        config.normalize_http_public_url("http://[::ffff:0.0.0.0]")


@pytest.mark.parametrize(
    ("public_url", "expected"),
    [
        ("http://127.0.0.1", "http://127.0.0.1"),
        ("https://mcp.example", "https://mcp.example"),
        ("http://[2001:db8::1]:8765", "http://[2001:db8::1]:8765"),
        ("http://[::ffff:127.0.0.1]", "http://[::ffff:127.0.0.1]"),
    ],
)
def test_public_url_accepts_specific_ip_and_domain_hosts(public_url: str, expected: str) -> None:
    from ghidra_mcp.config import normalize_http_public_url

    assert normalize_http_public_url(public_url) == expected


def test_auth_token_is_loaded_from_dotenv_but_never_exposed_by_repr(tmp_path: Path) -> None:
    from ghidra_mcp.config import load_settings

    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"GHIDRA_MCP_AUTH_TOKEN=private-test-token-0123456789012345\n"
        f"GHIDRA_MCP_INPUT_ROOT={tmp_path}\nGHIDRA_MCP_PUBLIC_URL=https://mcp.example\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=None,
        dotenv_path=dotenv,
        environ={"GHIDRA_MCP_TRANSPORT": "streamable-http"},
    )

    assert settings.auth_token == "private-test-token-0123456789012345"
    assert settings.input_root == tmp_path.resolve()
    assert "private-test-token-0123456789012345" not in repr(settings)


@pytest.mark.parametrize(
    "assignment",
    [
        "GHIDRA_MCP_AUTH_TOKEN= " + "x" * 32,
        "GHIDRA_MCP_AUTH_TOKEN=" + "x" * 32 + " ",
    ],
)
def test_streamable_http_rejects_unquoted_dotenv_token_with_edge_whitespace(
    tmp_path: Path, assignment: str
) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"{assignment}\nGHIDRA_MCP_INPUT_ROOT={tmp_path}\n"
        "GHIDRA_MCP_PUBLIC_URL=https://mcp.example\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="首尾空白"):
        load_settings(
            config_path=None,
            dotenv_path=dotenv,
            environ={"GHIDRA_MCP_TRANSPORT": "streamable-http"},
        )


@pytest.mark.parametrize("quote", ['"', "'"])
def test_streamable_http_accepts_dotenv_token_with_matching_outer_quotes(
    tmp_path: Path, quote: str
) -> None:
    from ghidra_mcp.config import load_settings

    token = "quoted-test-token-0123456789012345"
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"GHIDRA_MCP_AUTH_TOKEN={quote}{token}{quote}\n"
        f"GHIDRA_MCP_INPUT_ROOT={tmp_path}\n"
        "GHIDRA_MCP_PUBLIC_URL=https://mcp.example\n",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=None,
        dotenv_path=dotenv,
        environ={"GHIDRA_MCP_TRANSPORT": "streamable-http"},
    )

    assert settings.auth_token == token


@pytest.mark.parametrize(
    "quoted_token",
    ['" ' + "x" * 32 + '"', '"' + "x" * 32 + ' "'],
)
def test_streamable_http_rejects_dotenv_token_with_whitespace_inside_quotes(
    tmp_path: Path, quoted_token: str
) -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    dotenv = tmp_path / ".env"
    dotenv.write_text(
        f"GHIDRA_MCP_AUTH_TOKEN={quoted_token}\n"
        f"GHIDRA_MCP_INPUT_ROOT={tmp_path}\n"
        "GHIDRA_MCP_PUBLIC_URL=https://mcp.example\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="首尾空白"):
        load_settings(
            config_path=None,
            dotenv_path=dotenv,
            environ={"GHIDRA_MCP_TRANSPORT": "streamable-http"},
        )


def test_input_root_uses_environment_dotenv_toml_precedence(tmp_path: Path) -> None:
    from ghidra_mcp.config import load_settings

    toml_root = tmp_path / "toml"
    dotenv_root = tmp_path / "dotenv"
    environment_root = tmp_path / "environment"
    config = tmp_path / "settings.toml"
    config.write_text(f'[storage]\ninput_root = "{toml_root}"\n', encoding="utf-8")
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"GHIDRA_MCP_INPUT_ROOT={dotenv_root}\n", encoding="utf-8")

    settings = load_settings(
        config_path=config,
        dotenv_path=dotenv,
        environ={"GHIDRA_MCP_INPUT_ROOT": str(environment_root)},
    )

    assert settings.input_root == environment_root.resolve()


def test_max_workers_is_configurable_but_bounded() -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    default = load_settings(config_path=None, dotenv_path=None, environ={})
    configured = load_settings(
        config_path=None,
        dotenv_path=None,
        environ={"GHIDRA_MCP_MAX_WORKERS": "8"},
    )

    assert default.max_workers == 1
    assert configured.max_workers == 8
    for invalid in ("0", "65", "many"):
        with pytest.raises(ConfigurationError, match="max_workers"):
            load_settings(
                config_path=None,
                dotenv_path=None,
                environ={"GHIDRA_MCP_MAX_WORKERS": invalid},
            )


def test_analysis_timeout_is_configurable_but_bounded() -> None:
    from ghidra_mcp.config import ConfigurationError, load_settings

    default = load_settings(config_path=None, dotenv_path=None, environ={})
    configured = load_settings(
        config_path=None,
        dotenv_path=None,
        environ={"GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS": "17"},
    )

    assert default.analysis_timeout_seconds == 300
    assert configured.analysis_timeout_seconds == 17
    for invalid in ("0", "3601"):
        with pytest.raises(ConfigurationError, match="analysis_timeout_seconds"):
            load_settings(
                config_path=None,
                dotenv_path=None,
                environ={"GHIDRA_MCP_ANALYSIS_TIMEOUT_SECONDS": invalid},
            )
