# Changelog

## Unreleased

- The error returned to MCP clients when the configured Ghidra is older than the minimum supported version no longer includes the absolute Ghidra installation directory; it reports only the detected version, the minimum version, the reason, and upgrade guidance. The installation directory is written to the server log (logger `ghidra_mcp.runtime`) instead, so remote Streamable HTTP clients no longer learn host filesystem paths from this error.

## 20261019.2

- **Breaking change for self-hosted installations:** raised the minimum supported Ghidra version from 12.1.2 to 12.1.3. `ghidra-mcp` now refuses to start the JVM against Ghidra 12.1.2 or older and reports the detected version, the installation directory, the minimum version, and the reason. Ghidra 12.1.3 fixed a potential path-traversal vulnerability when importing XML `*.bytes` files (GP-7064) and an ELF importer regression introduced in 12.1.2 that could fail when processing the dynamic GNU hash table and symbol table (GP-7061). Upgrade Ghidra and point `GHIDRA_INSTALL_DIR` at the new installation before upgrading `ghidra-mcp`.
- Upgraded the Ghidra bundled in the container image from 12.1.2 to the official 12.1.4 release (`ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`). Ghidra 12.1.4 also fixes a potential `DomainObjectLockedException` (GP-7190), potential stack overflows in the OMF and PE loaders (GP-7173, GP-7205), and stops loading libraries whose location a binary specifies with a UNC path (GP-7176).

## 20261019.1

- Security: upgraded `mcp` 1.28.1 → 1.30.0 to fix GHSA-84m7-p3x7-pcfv / CVE-2026-59951 (stateful Streamable HTTP sessions were never reclaimed, allowing unbounded memory growth), and raised the minimum supported `mcp` to 1.30.
- Security: upgraded the transitive dependencies `pyjwt` 2.13.0 → 2.15.1 and `cryptography` 49.0.0 → 50.0.2 to clear published advisories.
- Explicitly set `AuthSettings.validate_token_resource=False` for the static Bearer token verifier; behavior is unchanged and the new `mcp` deprecation warning is silenced.
- Behavior change from the `mcp` 1.30 defaults in Streamable HTTP mode: request bodies larger than 4 MiB are rejected with HTTP 413, stateful sessions with no request in flight for 30 minutes are closed (an open GET stream keeps a session alive; requests to an expired session get HTTP 404 and the client must initialize again), and at most 10,000 sessions are kept at once (new sessions beyond that get HTTP 503). ghidra-mcp does not override these defaults.
- Capped `requires-python` at `<3.14` because `pyghidra` 3.1.0 pins `JPype1==1.5.2`, which publishes no CPython 3.14 wheels; supported versions are Python 3.11–3.13, and `.python-version` pins local development to 3.12.

## 20260722.6

- Moved detailed user documentation to the GitHub Wiki and made the remaining repository documentation English-first.
- Removed the clean-room charter and obsolete development-stage specification, source, and verification documents.
- Added a task-oriented Wiki with getting-started, tool catalog, and operations pages.

## 20260722.5

- Added a GHCR publication workflow pinned to exact action commits. Pushes to `main` build `linux/amd64` without cache, publish version and `latest` tags, and verify health metadata against the remote digest.
- Made the English README the primary entry point and added an independent Chinese README.
- Added Python package metadata for the README, project links, issue tracker, and container image.

## 20260722.4

- Licensed original project code under Apache License 2.0 and included the standard license and `xjoker` attribution in source archives, wheels, and container images.
- Added public contribution and security-reporting policies and MCP client configuration examples.
- Removed hard-coded release versions from documentation.

## 20260722.3

- Added standard MCP `ToolAnnotations` to tool contracts and included them in the schema digest.
- Marked `program_close` as a non-idempotent mutation that removes the active session while preserving save-first behavior and keeping the session open when saving fails.
- Upgraded the development test dependency to pytest 9.1.1 to resolve a medium-severity temporary-directory advisory.

## 20260722.2

- Made `instructions_list` report requested and effective start addresses and skipped byte counts, with optional strict start validation.
- Made `function_get` distinguish function-body membership from unassigned addresses and added `function_body_add` for confirmed detached continuation ranges.
- Added bounded pseudo-disassembly to `references_list` for direct references into undefined control-flow-flattening code islands, including coverage, source, and confidence metadata.
- Made `control_flow_graph` distinguish static default flow from analyzer-inferred computed flow.
- Added tool contract versions to the schema digest so clients can detect incompatible response changes.

## 20260722.1

- Implemented a single-process PyGhidra MCP server from an empty Git history.
- Added 34 program, navigation, analysis, inspection, and transactional mutation tools.
- Added local stdio and Bearer-authenticated Streamable HTTP transports.
- Added layered configuration, persistent projects, health metadata, and a non-root `linux/amd64` image.
- Added original symbolic, stripped, and control-flow-heavy ELF fixtures with real Ghidra tests.
- Set Ghidra 12.1.2 as the security baseline and reject unknown or older installations before JVM startup.
- Added native Ghidra undo on save failure, bounded decompilation output, cancellable analysis deadlines, and strict HTTP input/public-URL boundaries.
