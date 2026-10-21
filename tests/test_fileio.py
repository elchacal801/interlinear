"""Tests for fileio.atomic_write, the one writer for files Interlinear writes, and for the zipapp build that uses it."""

import os
import stat
import sys

import pytest

from interlinear_cti import cli, pyz
from interlinear_cti.fileio import OutputError, atomic_write

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows read-only files")


def current_umask():
    umask = os.umask(0o077)
    os.umask(umask)
    return umask


def leftovers(folder):
    """Temporary files a write left behind."""
    return sorted(p.name for p in folder.iterdir() if p.name.endswith(".tmp"))


def test_bytes_text_and_text_chunks_are_written_exactly(tmp_path):
    path = tmp_path / "new" / "out.json"  # a missing folder is created
    atomic_write(path, b"a\r\nb")
    assert path.read_bytes() == b"a\r\nb"
    atomic_write(path, "caf" + chr(0xE9) + "\nx")  # UTF-8, and no newline translation on Windows
    assert path.read_bytes() == ("caf" + chr(0xE9) + "\nx").encode("utf-8")
    atomic_write(path, iter(["a", "b\n", "c"]))  # chunks, so a large JSON file is never held whole
    assert path.read_bytes() == b"ab\nc"
    assert leftovers(path.parent) == []


@posix_only
def test_a_new_file_gets_the_mode_a_plain_create_would(tmp_path):
    path = tmp_path / "new.json"
    atomic_write(path, "x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o666 & ~current_umask()


@posix_only
def test_a_replaced_file_keeps_its_mode(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("old")
    os.chmod(path, 0o640)
    atomic_write(path, "new")
    assert (stat.S_IMODE(path.stat().st_mode), path.read_text()) == (0o640, "new")
    os.chmod(path, 0o444)
    atomic_write(path, "newer")  # replacing needs write access to the folder, not to the file
    assert (stat.S_IMODE(path.stat().st_mode), path.read_text()) == (0o444, "newer")


@posix_only
def test_an_executable_file_gets_the_owner_execute_bit(tmp_path):
    path = tmp_path / "tool.pyz"
    atomic_write(path, b"#!/usr/bin/env python3\n", executable=True)
    assert stat.S_IMODE(path.stat().st_mode) == (0o666 & ~current_umask()) | stat.S_IXUSR


def test_a_failed_write_keeps_the_old_file_and_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("old")

    def chunks():
        yield "new"
        raise RuntimeError("the writer failed")

    with pytest.raises(RuntimeError):
        atomic_write(path, chunks())
    assert path.read_text() == "old"
    assert leftovers(tmp_path) == []


@windows_only
def test_a_read_only_file_on_windows_is_refused_and_the_temporary_file_removed(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("old")
    os.chmod(path, stat.S_IREAD)
    try:
        with pytest.raises(PermissionError):
            atomic_write(path, "new")
        assert path.read_text() == "old"
        assert leftovers(tmp_path) == []  # given the read-only mode, it had to be made writable to be removed
    finally:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def test_the_zipapp_is_built_atomically(tmp_path, monkeypatch):
    out = tmp_path / "interlinear-parse.pyz"
    out.write_bytes(b"old")

    def full_disk(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(pyz.zipapp, "create_archive", full_disk)
    with pytest.raises(OutputError, match="OSError"):
        pyz.build(out)
    assert out.read_bytes() == b"old"
    assert leftovers(tmp_path) == []


def test_the_zipapp_holds_the_writer_and_the_shown_characters_module():
    assert {"fileio.py", "textshow.py"} <= set(pyz.PARSE_FILES)


def test_an_error_writing_the_zipapp_exits_3_without_a_traceback(tmp_path, capsys):
    a_file = tmp_path / "file"
    a_file.write_bytes(b"x")
    assert cli.main(["build-parse-pyz", "-o", str(a_file / "x.pyz")]) == 3
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err
