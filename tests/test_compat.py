"""0.1.1 adds two optional fields to transcript.json: a gloss's partial and a line's decoded. They are written only
when set, so a transcript that uses neither stays readable by 0.1.0, whose model rejects unknown keys."""

import json

from interlinear_cti.model import Decoded, Gloss, Line, Source, Transcript, load, save


def transcript(**line_fields) -> Transcript:
    return Transcript(interlinear_version="0.1.1", sources=[Source(id=0, name="h", sha256="0" * 64, size=1,
                                                                   kind="bash_history", parsed_at="x")],
                      lines=[Line(n=1, source=0, line=1, text="id", **line_fields)])


def test_unset_new_fields_are_not_written(tmp_path):
    path = tmp_path / "t.json"
    save(transcript(gloss=Gloss(source="rule", rule_id="whoami-id"), history=[Gloss()]), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    line = data["lines"][0]
    assert "decoded" not in line
    assert "partial" not in line["gloss"] and all("partial" not in g for g in line["history"])
    assert load(path) == transcript(gloss=Gloss(source="rule", rule_id="whoami-id"), history=[Gloss()])


def test_set_new_fields_are_written_and_read_back(tmp_path):
    path = tmp_path / "t.json"
    original = transcript(gloss=Gloss(source="rule", rule_id="x", partial="why"),
                          decoded=Decoded(parent=1, depth=1, encoding="base64", sha256="a" * 64, length=8))
    save(original, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["lines"][0]["gloss"]["partial"] == "why" and data["lines"][0]["decoded"]["parent"] == 1
    assert load(path) == original
