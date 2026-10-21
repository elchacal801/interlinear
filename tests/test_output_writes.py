"""Output files: cleanup on any failure, the mode a new or replaced file gets, and never writing over the transcript."""

import json
import os
import stat
from pathlib import Path

import pytest

from interlinear_cti import cli
from interlinear_cti.model import Gloss, Line, Source, Technique, Transcript, save


def demo(text: str = "id", meaning: str = "Does something.") -> Transcript:
    return Transcript(interlinear_version="0.1.0", case="demo",
                      sources=[Source(id=0, name="s.sh", sha256="0" * 64, size=1, kind="bash_history",
                                      parsed_at="2026-10-15T00:00:00Z")],
                      lines=[Line(n=1, source=0, line=1, actor="operator", text=text,
                                  gloss=Gloss(source="rule", rule_id="r", meaning=meaning,
                                              techniques=[Technique(id="T1105", status="active")]))])


def temp_files(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if p.name.endswith(".tmp"))


OUTPUT_NAME = {"render": "out.md", "export-scenario": "out.json"}
RENDERED = "# `old`: interlinear transcript\n\nSources: `s.sh`\n"  # an earlier render, which render may replace


@pytest.mark.parametrize("command, transcript", [
    ("render", demo(text="a" + chr(0xD800) + "b")),
    ("export-scenario", demo(meaning="M" + chr(0xDFFF))),
])
def test_a_lone_surrogate_exits_2_and_leaves_no_temporary_file(tmp_path, command, transcript):
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(transcript.model_dump()), encoding="ascii")  # as a hand-edited file holds it: \ud800
    out = tmp_path / OUTPUT_NAME[command]
    assert cli.main([command, str(path), "-o", str(out)]) == 2
    assert not out.exists()
    assert temp_files(tmp_path) == []


def test_write_text_removes_its_temporary_file_on_any_exception(tmp_path, monkeypatch):
    def interrupted(src, dst):
        raise KeyboardInterrupt

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        cli._write_text(tmp_path / "out.md", "text\n")
    assert list(tmp_path.iterdir()) == []


WRITERS = {
    "write_text": lambda path: cli._write_text(path, "text\n"),
    "save": lambda path: save(demo(), path),
}


@pytest.mark.parametrize("writer", WRITERS)
def test_every_writer_goes_through_the_one_atomic_writer(tmp_path, monkeypatch, writer):
    from interlinear_cti import fileio

    calls = []
    atomic_write = fileio.atomic_write

    def record(path, data, executable=False):
        calls.append(Path(path).name)
        return atomic_write(path, data, executable)

    monkeypatch.setattr(fileio, "atomic_write", record)
    WRITERS[writer](tmp_path / "out")
    assert calls == ["out"]


def test_the_model_keeps_no_writer_helpers_of_its_own():
    from interlinear_cti import model

    assert not hasattr(model, "file_mode") and not hasattr(model, "discard_temp")


@pytest.fixture
def modes(monkeypatch):
    """The modes the writers give their files, with the umask reading 0o027."""
    given = []
    chmod = os.chmod

    def record(path, mode, *args, **kwargs):
        given.append(mode)
        return chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", record)
    monkeypatch.setattr(os, "umask", lambda mask: 0o027)
    return given


@pytest.mark.parametrize("writer", WRITERS)
def test_a_new_output_gets_the_mode_a_plain_create_gives(tmp_path, modes, writer):
    WRITERS[writer](tmp_path / "out")
    assert modes == [0o640]  # 0o666 less the umask, not mkstemp's 0o600


@pytest.mark.parametrize("writer", WRITERS)
def test_a_replaced_output_keeps_its_mode(tmp_path, modes, writer):
    path = tmp_path / "out"
    path.write_text("old", encoding="utf-8")
    os.chmod(path, 0o604)  # Windows keeps only "writable": 0o666
    before = stat.S_IMODE(path.stat().st_mode)
    modes.clear()
    WRITERS[writer](path)
    assert modes == [before] and before != 0o640
    assert stat.S_IMODE(path.stat().st_mode) == before


@pytest.mark.skipif(os.name == "nt", reason="Windows file modes hold only a read-only flag")
@pytest.mark.parametrize("writer", WRITERS)
def test_output_modes_follow_the_umask_on_posix(tmp_path, writer):
    old = os.umask(0o022)
    try:
        WRITERS[writer](tmp_path / "new")
        assert stat.S_IMODE((tmp_path / "new").stat().st_mode) == 0o644
        existing = tmp_path / "existing"
        existing.write_text("old", encoding="utf-8")
        os.chmod(existing, 0o600)
        WRITERS[writer](existing)
        assert stat.S_IMODE(existing.stat().st_mode) == 0o600
    finally:
        os.umask(old)


@pytest.mark.parametrize("command", ["render", "export-scenario"])
def test_a_read_only_output(tmp_path, command):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / OUTPUT_NAME[command]
    out.write_text(RENDERED, encoding="utf-8")
    os.chmod(out, stat.S_IREAD)
    try:
        code = cli.main([command, str(path), "-o", str(out)])
        if os.name == "nt":  # Windows cannot replace a read-only file
            assert code == 3 and out.read_text(encoding="utf-8") == RENDERED
        else:  # on POSIX the folder's permission decides, and the new file keeps the old one's mode
            assert code == 0 and stat.S_IMODE(out.stat().st_mode) == stat.S_IREAD
        assert temp_files(tmp_path) == []
    finally:
        os.chmod(out, stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.parametrize("command", ["render", "export-scenario"])
def test_the_transcript_is_never_overwritten(tmp_path, capsys, command):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    before = path.read_bytes()
    (tmp_path / "sub").mkdir()
    outputs = [path, tmp_path / "sub" / ".." / "transcript.json"]
    if os.name == "nt":  # a case-insensitive file system
        outputs.append(Path(str(path).upper()))
    for output in outputs:
        assert cli.main([command, str(path), "-o", str(output)]) == 2
        assert "is the transcript" in capsys.readouterr().err
    assert path.read_bytes() == before
    assert temp_files(tmp_path) == []


def test_render_refuses_a_transcript_whose_default_output_is_itself(tmp_path):
    path = tmp_path / "case.md"
    save(demo(), path)
    before = path.read_bytes()
    assert cli.main(["render", str(path)]) == 2
    assert path.read_bytes() == before


# render writes only Markdown, and replaces only its own earlier output: a model that runs it cannot aim it at a
# CLAUDE.md, a shell startup file or another transcript.

@pytest.mark.parametrize("name", [
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", "AGENT.md", "CONVENTIONS.md", ".cursorrules",
    "Claude.MD", "agents.md", "gemini.Md", "claude.LOCAL.md", "agent.MD", "Conventions.md", ".CursorRules",  # any case
    ".claude/x.md", ".github/copilot-instructions.md", ".cursor/rules.md", ".windsurf/rules.md", ".amazonq/x.md",
    ".kiro/steering.md", ".clinerules/x.md", ".roo/rules.md", ".continue/x.md",
    "a/.Claude/b/x.md", "docs/.GITHUB/x.md", ".cursor/sub/notes.md",  # nested, any case
    ".Windsurf/x.md", "a/.AMAZONQ/x.md", ".Kiro/b/x.md", ".ClineRules/x.md", "x/.ROO/x.md", ".Continue/x.md",
])
def test_render_refuses_agent_instruction_files_even_new_ones(tmp_path, capsys, name):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / name
    assert cli.main(["render", str(path), "-o", str(out)]) == 2
    assert "agent instruction" in capsys.readouterr().err
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["transcript.json"]  # no folder made either


@pytest.mark.parametrize("kind", ["fifo", "link to a fifo"])
@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX feature")
def test_render_refuses_an_output_that_is_not_a_regular_file_promptly(tmp_path, kind):
    # Opening a FIFO to read its first line would block until a writer came, so render must not open it. A
    # subprocess with a timeout, so a regression fails the test rather than hanging the run.
    import subprocess
    import sys

    path = tmp_path / "transcript.json"
    save(demo(), path)
    fifo = tmp_path / ("view.md" if kind == "fifo" else "pipe")
    os.mkfifo(fifo)
    out = fifo if kind == "fifo" else tmp_path / "view.md"
    if kind != "fifo":
        out.symlink_to(fifo)
    run = subprocess.run([sys.executable, "-m", "interlinear_cti.cli", "render", str(path), "-o", str(out)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 2
    assert "not a regular file" in run.stderr
    assert stat.S_ISFIFO(os.stat(out).st_mode)


def test_render_refuses_an_agent_instruction_file_that_holds_a_view(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / "CLAUDE.md"
    out.write_text(RENDERED, encoding="utf-8")
    assert cli.main(["render", str(path), "-o", str(out)]) == 2
    assert out.read_text(encoding="utf-8") == RENDERED


def test_render_refuses_a_default_output_that_is_an_agent_instruction_file(tmp_path):
    path = tmp_path / "AGENTS.json"
    save(demo(), path)
    assert cli.main(["render", str(path)]) == 2
    assert not (tmp_path / "AGENTS.md").exists()


@pytest.mark.parametrize("name", ["notes.md", "claude-notes.md", "github/x.md", "my.claude.md/x.md"])
def test_render_still_writes_ordinary_markdown(tmp_path, name):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / name
    assert cli.main(["render", str(path), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# `demo`: interlinear transcript\n")

@pytest.mark.parametrize("name", ["CLAUDE", ".bashrc", "notes.txt", "x.md.sh", "transcript.json.bak", ".md"])
def test_render_refuses_an_output_that_is_not_markdown(tmp_path, capsys, name):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / name
    assert cli.main(["render", str(path), "-o", str(out)]) == 2
    assert "must end in .md" in capsys.readouterr().err
    assert not out.exists() and temp_files(tmp_path) == []


@pytest.mark.parametrize("content", [
    b"# Project rules\n\nAlways run the tests.\n",
    b"",
    b"Notes\n# `demo`: interlinear transcript\n",  # the header, but not on the first line
    b"# `demo`: interlinear transcript and more\n",
    b"\xff\xfe# not UTF-8\n",
])
def test_render_refuses_to_replace_a_file_it_did_not_write(tmp_path, capsys, content):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / "README.md"  # a project's own Markdown (CLAUDE.md is refused by name, before this check)
    out.write_bytes(content)
    assert cli.main(["render", str(path), "-o", str(out)]) == 2
    assert "not an Interlinear render" in capsys.readouterr().err
    assert out.read_bytes() == content and temp_files(tmp_path) == []


def test_render_refuses_to_replace_a_folder(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    (tmp_path / "view.md").mkdir()
    assert cli.main(["render", str(path), "-o", str(tmp_path / "view.md")]) == 2
    assert (tmp_path / "view.md").is_dir()


@pytest.mark.parametrize("content", [
    RENDERED.encode(),
    b"# Transcript: interlinear transcript\n",
    b"# `old`: interlinear transcript\r\n\r\nSources: x\r\n",  # line endings an editor changed
    b"\xef\xbb\xbf# `old`: interlinear transcript\n",  # a BOM an editor added
    b"# old: interlinear transcript\n",  # the header before values became code spans
])
def test_render_replaces_its_own_earlier_output(tmp_path, content):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / "view.md"
    out.write_bytes(content)
    assert cli.main(["render", str(path), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# `demo`: interlinear transcript\n")


def test_render_twice_to_the_default_path(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    assert cli.main(["render", str(path)]) == 0
    assert cli.main(["render", str(path)]) == 0
    assert (tmp_path / "transcript.md").read_text(encoding="utf-8").startswith("# `demo`: interlinear transcript\n")
