"""Reopening finds the program an earlier import actually stored (issue #3).

These tests use fake Ghidra project objects (no JVM). ``_source_fsrl`` normally parses the
``FSRL`` value with Ghidra's ``FSRL`` class; here it is replaced with a small parser for the
same ``file:///...?MD5=...|zip:///...?MD5=...`` form. The real parser and the real
``ApkLoader`` naming are covered by tests/integration/test_real_ghidra_apk_reopen.py.
"""

from contextlib import contextmanager
from hashlib import md5
import logging
from pathlib import Path

import pytest

from ghidra_mcp.runtime import GhidraRuntime


def _parse_fsrl(value):
    if value is None:
        return None
    levels = str(value).split("|")
    if not all("://" in level for level in levels):
        return None

    def split(level):
        path, _, query = level.split("://", 1)[1].partition("?")
        return path, query.removeprefix("MD5=") or None

    return split(levels[0])[1], split(levels[-1])[0]


class DomainFile:
    def __init__(self, pathname, metadata, content_type="Program"):
        self.pathname = pathname
        self.metadata = metadata
        self.content_type = content_type

    def getPathname(self):
        return self.pathname

    def getName(self):
        return self.pathname.rsplit("/", 1)[-1]

    def getContentType(self):
        return self.content_type

    def getMetadata(self):
        return self.metadata


class ProjectData:
    def __init__(self, files):
        self.files = files
        self.iterated = False

    def getFile(self, path):
        return next((item for item in self.files if item.pathname == path), None)

    def __iter__(self):
        self.iterated = True
        return iter(self.files)


class Project:
    def __init__(self, files):
        self.data = ProjectData(files)
        self.closed = False

    def getProjectData(self):
        return self.data

    def close(self):
        self.closed = True


class FakePyGhidra:
    """Opens only the paths in the project; importing records the call and fails the test."""

    def __init__(self, project):
        self.project = project
        self.opened: list[str] = []
        self.loader_calls = 0

    def open_project(self, *_args, **_kwargs):
        return self.project

    @contextmanager
    def program_context(self, project, path):
        if project.getProjectData().getFile(path) is None:
            raise FileNotFoundError(path)
        self.opened.append(path)
        yield f"program at {path}"

    def program_loader(self):
        self.loader_calls += 1
        raise AssertionError("an earlier import exists, so nothing may be imported again")


@pytest.fixture
def apk(tmp_path: Path) -> tuple[Path, str]:
    binary = tmp_path / "sample.apk"
    binary.write_bytes(b"PK\x03\x04 not a real apk")
    return binary, md5(binary.read_bytes()).hexdigest()


def _dex(pathname, apk_md5, *, inner="classes.dex", functions="71", analyzed=True):
    metadata = {
        "FSRL": f"file:///in/sample.apk?MD5={apk_md5}|zip:///{inner}?MD5=0123",
        "# of Functions": functions,
    }
    if analyzed:
        metadata["Analyzed"] = "true"
    return DomainFile(pathname, metadata)


def _runtime(monkeypatch, tmp_path, files):
    fake = FakePyGhidra(Project(files))
    runtime = GhidraRuntime(tmp_path, pyghidra_module=fake)
    monkeypatch.setattr(runtime, "_source_fsrl", _parse_fsrl)
    monkeypatch.setattr(runtime, "_flat_api", lambda program: program)
    return runtime, fake


def _reopen(runtime, binary):
    with runtime._modern_program_context(
        binary, project_location=binary.parent, project_name="sample", analyze=False
    ) as api:
        return api


def test_program_stored_under_the_import_name_is_used_without_scanning(
    monkeypatch, tmp_path, apk
) -> None:
    binary, apk_md5 = apk
    files = [_dex("/classes.dex", apk_md5), DomainFile("/sample.apk", {})]
    runtime, fake = _runtime(monkeypatch, tmp_path, files)
    monkeypatch.setattr(
        "ghidra_mcp.runtime._file_md5", lambda _binary: pytest.fail("no MD5 on the fast path")
    )

    assert _reopen(runtime, binary) == "program at /sample.apk"
    assert fake.project.data.iterated is False
    assert fake.loader_calls == 0
    assert fake.project.closed is True


def test_apk_reopens_the_program_ghidra_stored_as_classes_dex(monkeypatch, tmp_path, apk) -> None:
    binary, apk_md5 = apk
    runtime, fake = _runtime(monkeypatch, tmp_path, [_dex("/classes.dex", apk_md5)])

    assert _reopen(runtime, binary) == "program at /classes.dex"
    assert fake.opened == ["/classes.dex"]
    assert fake.loader_calls == 0


def test_legacy_duplicates_reopen_the_analysed_original_and_log_the_copies(
    monkeypatch, tmp_path, apk, caplog
) -> None:
    binary, apk_md5 = apk
    files = [
        _dex("/classes.dex.1", apk_md5, functions="0", analyzed=False),
        _dex("/classes.dex.0", apk_md5, functions="0", analyzed=False),
        _dex("/classes.dex", apk_md5),
    ]
    runtime, fake = _runtime(monkeypatch, tmp_path, files)

    with caplog.at_level(logging.INFO, logger="ghidra_mcp.runtime"):
        assert _reopen(runtime, binary) == "program at /classes.dex"

    assert fake.loader_calls == 0
    assert "/classes.dex.0, /classes.dex.1" in caplog.text
    assert str(tmp_path) not in caplog.text


def test_an_analysed_copy_wins_over_an_unanalysed_original(monkeypatch, tmp_path, apk) -> None:
    binary, apk_md5 = apk
    files = [
        _dex("/classes.dex", apk_md5, functions="0", analyzed=False),
        _dex("/classes.dex.1", apk_md5, functions="70", analyzed=False),
        _dex("/classes.dex.0", apk_md5, functions="71"),
    ]
    runtime, _fake = _runtime(monkeypatch, tmp_path, files)

    assert _reopen(runtime, binary) == "program at /classes.dex.0"


def test_among_equally_analysed_copies_ghidra_import_order_wins(monkeypatch, tmp_path, apk) -> None:
    binary, apk_md5 = apk
    files = [
        _dex("/renamed by the user", apk_md5),
        _dex("/classes.dex.10", apk_md5),
        _dex("/classes.dex.2", apk_md5),
    ]
    runtime, _fake = _runtime(monkeypatch, tmp_path, files)

    assert _reopen(runtime, binary) == "program at /classes.dex.2"


def test_multidex_apk_reopens_the_primary_classes_dex(monkeypatch, tmp_path, apk) -> None:
    binary, apk_md5 = apk
    files = [
        _dex("/classes10.dex", apk_md5, inner="classes10.dex"),
        _dex("/classes2.dex", apk_md5, inner="classes2.dex"),
        _dex("/classes.dex", apk_md5, functions="0", analyzed=False),
        _dex("/classes2.dex.0", apk_md5, inner="classes2.dex"),
    ]
    runtime, _fake = _runtime(monkeypatch, tmp_path, files)

    assert _reopen(runtime, binary) == "program at /classes.dex"


@pytest.mark.parametrize(
    "unrelated",
    [
        pytest.param(
            DomainFile(
                "/classes.dex", {"FSRL": "file:///in/other.apk?MD5=ffff|zip:///classes.dex"}
            ),
            id="other-container-md5",
        ),
        pytest.param(
            DomainFile("/classes.dex", {"FSRL": "file:///in/sample.apk|zip:///classes.dex"}),
            id="no-md5",
        ),
        pytest.param(DomainFile("/classes.dex", {}), id="no-fsrl"),
        pytest.param(DomainFile("/classes.dex", {"FSRL": "not an fsrl"}), id="unparsable-fsrl"),
        pytest.param("data-type-archive", id="not-a-program"),
    ],
)
def test_programs_not_imported_from_this_binary_are_ignored_and_it_is_imported(
    monkeypatch, tmp_path, apk, unrelated
) -> None:
    binary, apk_md5 = apk
    if unrelated == "data-type-archive":
        unrelated = _dex("/classes.dex", apk_md5)
        unrelated.content_type = "Archive"
    runtime, fake = _runtime(monkeypatch, tmp_path, [unrelated])

    assert runtime._stored_program_path(fake.project, binary) == "/sample.apk"
    with pytest.raises(AssertionError, match="nothing may be imported again"):
        _reopen(runtime, binary)
    assert fake.loader_calls == 1
    assert fake.opened == []
    assert fake.project.closed is True


def test_lookup_failure_still_closes_the_project(monkeypatch, tmp_path, apk) -> None:
    binary, apk_md5 = apk
    runtime, fake = _runtime(monkeypatch, tmp_path, [_dex("/classes.dex", apk_md5)])

    def broken(_value):
        raise RuntimeError("metadata unavailable")

    monkeypatch.setattr(runtime, "_source_fsrl", broken)
    with pytest.raises(RuntimeError, match="metadata unavailable"):
        _reopen(runtime, binary)
    assert fake.project.closed is True


def test_source_fsrl_without_a_value_needs_no_jvm(tmp_path) -> None:
    runtime = GhidraRuntime(tmp_path, pyghidra_module=object())

    assert runtime._source_fsrl(None) is None
