import json

import pytest

from interlinear_cti.model import Line, Source, Transcript, TranscriptError, load, save


def make_transcript() -> Transcript:
    return Transcript(
        interlinear_version="0.1.0",
        sources=[Source(id=0, name=".bash_history", sha256="0" * 64, size=3, kind="bash_history",
                        parsed_at="2026-10-15T00:00:00Z")],
        lines=[Line(n=1, source=0, line=1, actor="operator", text="id")],
    )


def test_new_lines_start_pending():
    assert make_transcript().lines[0].gloss.source == "pending"


def test_round_trip(tmp_path):
    path = tmp_path / "transcript.json"
    save(make_transcript(), path)
    assert load(path) == make_transcript()


def test_save_leaves_no_temporary_files(tmp_path):
    save(make_transcript(), tmp_path / "transcript.json")
    assert [p.name for p in tmp_path.iterdir()] == ["transcript.json"]


def test_rejects_other_major_versions(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"interlinear_version": "1.0.0", "sources": [], "lines": []}), encoding="utf-8")
    with pytest.raises(TranscriptError, match="not supported"):
        load(path)


def test_rejects_files_that_are_not_transcripts(tmp_path):
    path = tmp_path / "t.json"
    path.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(TranscriptError, match="not an Interlinear transcript"):
        load(path)


def test_rejects_unknown_fields(tmp_path):
    data = json.loads(make_transcript().model_dump_json())
    data["lines"][0]["surprise"] = True
    path = tmp_path / "t.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(TranscriptError, match="invalid transcript"):
        load(path)


def test_save_writes_lf_line_endings_on_every_platform(tmp_path):
    path = tmp_path / "transcript.json"
    save(make_transcript(), path)
    raw = path.read_bytes()
    assert b"\n" in raw
    assert b"\r\n" not in raw


def test_load_accepts_a_utf8_bom(tmp_path):
    path = tmp_path / "transcript.json"
    path.write_bytes(b"\xef\xbb\xbf" + make_transcript().model_dump_json(indent=2).encode("utf-8"))
    assert load(path) == make_transcript()
