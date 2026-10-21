import json
import re

import pytest

from interlinear_cti import __version__, cli
from interlinear_cti.export import export_scenario
from interlinear_cti.model import Gloss, Line, Source, Technique, Transcript, save
from interlinear_cti.normalize import defang

ORDER_NOTE = ("Steps are chained only within each source file, in its line order; the files are parallel lanes, since "
              "nothing in them orders one against another. Each step cites its transcript lines and gloss sources.")


def g(source, *ids, meaning="Does something.", revoked_to=None):
    techniques = [Technique(id=i, status="revoked" if revoked_to else "active",
                            replaced_by=[revoked_to] if revoked_to else []) for i in ids]
    return Gloss(source=source, meaning=meaning, techniques=techniques, by="x")


def demo() -> Transcript:
    return Transcript(
        interlinear_version="0.1.0", case="demo",
        sources=[Source(id=0, name=".bash_history", sha256="0" * 64, size=1, kind="bash_history",
                        parsed_at="2026-10-15T00:00:00Z")],
        lines=[
            Line(n=1, source=0, line=1, actor="operator", text="a",
                 gloss=g("rule", "T1105", "T1059.004", meaning="Downloads a script and runs it.")),
            Line(n=2, source=0, line=2, actor="operator", text="b", gloss=g("rule", "T1105", meaning="Downloads a file.")),
            Line(n=3, source=0, line=3, actor="operator", text="cd /tmp", gloss=Gloss(source="none", meaning="Context.")),
            Line(n=4, source=0, line=4, actor="operator", text="c",
                 gloss=g("model", "T1562.003", meaning="Hides the history.", revoked_to="T1690")),
            Line(n=5, source=0, line=5, actor="operator", text="d"),
            Line(n=6, source=0, line=6, actor="operator", text="e", gloss=g("rule", "T1053.003", meaning="Adds a cron job.")),
        ],
    )


def test_export_groups_consecutive_lines_and_follows_revocations():
    spec, warnings = export_scenario(demo())
    assert warnings == []
    assert spec == {
        "title": "demo",
        "description": f"Exported by Interlinear {__version__} from .bash_history. {ORDER_NOTE}",
        "authors": [],
        "steps": [
            {"id": "s1", "technique": "T1105", "description": "Lines 1-2 (rule; operator): Downloads a script and runs it."},
            {"id": "s2", "technique": "T1690", "after": ["s1"],
             "description": "Model-glossed: Line 4 (model; operator): Hides the history."},
            {"id": "s3", "technique": "T1053.003", "after": ["s2"], "description": "Line 6 (rule; operator): Adds a cron job."},
        ],
        "countermeasures": "auto",
        "max_countermeasures_per_step": 2,
    }


def test_export_with_nothing_glossed_warns():
    t = demo()
    for line in t.lines:
        line.gloss = Gloss()
    spec, warnings = export_scenario(t, title="empty")
    assert spec["steps"] == [] and spec["title"] == "empty"
    assert warnings == ["no glossed lines with techniques; the scenario has no steps"]


def test_export_warns_about_lines_a_model_marked_context():
    t = demo()
    for n in (3, 5):  # a rule context line and a pending line, both now marked context by a model
        t.lines[n - 1].gloss = Gloss(source="model", meaning="Context.", by="m", confidence="high")
    spec, warnings = export_scenario(t)
    assert [step["technique"] for step in spec["steps"]] == ["T1105", "T1690", "T1053.003"]
    assert warnings == ["2 lines were marked context by a model and are not in the scenario"]


def test_one_line_marked_context_reads_in_the_singular():
    t = demo()
    t.lines[2].gloss = Gloss(source="model", meaning="Context.", by="m", confidence="high")
    _, warnings = export_scenario(t)
    assert warnings == ["1 line was marked context by a model and is not in the scenario"]


def test_cli_export_scenario(tmp_path, capsys):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    out = tmp_path / "scenario.json"
    assert cli.main(["export-scenario", str(path), "-o", str(out)]) == 0
    assert len(json.loads(out.read_text(encoding="utf-8"))["steps"]) == 3
    assert capsys.readouterr().out.rstrip().endswith(": 3 steps")


def test_cli_export_counts_one_step_in_the_singular(tmp_path, capsys):
    path = tmp_path / "transcript.json"
    save(one_line("M."), path)
    assert cli.main(["export-scenario", str(path), "-o", str(tmp_path / "scenario.json")]) == 0
    assert capsys.readouterr().out.rstrip().endswith(": 1 step")


def atlas_and_revoked() -> Transcript:
    t = demo()  # line 4 holds T1562.003, revoked and replaced by T1690
    t.sources[0].kind = "agent_jsonl"
    t.lines += [
        Line(n=7, source=0, line=7, actor="agent_tool", text="f",
             gloss=Gloss(source="model", by="m", meaning="Crafts a prompt that overrides the agent's instructions.",
                         techniques=[Technique(id="AML.T0051", framework="atlas", status="active")])),
        Line(n=8, source=0, line=8, actor="operator", text="g",
             gloss=Gloss(source="analyst", by="Diego", meaning="Old technique.",
                         techniques=[Technique(id="T1454", status="revoked")])),
    ]
    return t


@pytest.mark.countermap
@pytest.mark.parametrize("transcript, techniques, export_warnings", [
    (demo, ["T1105", "T1690", "T1053.003"], []),
    (atlas_and_revoked, ["T1105", "T1690", "T1053.003", "AML.T0051", "T1454"],
     ["T1454 is revoked and has no replacement; kept as is in step s5"]),
], ids=["demo", "atlas_and_revoked"])
def test_export_renders_in_every_countermap_format(transcript, techniques, export_warnings):
    pytest.importorskip("countermap")
    from countermap.emit import render
    from countermap.emit.validate import validate_attack_flow, validate_cad
    from countermap.query import Countermap
    from countermap.sources import default_db_path

    if not default_db_path().exists():
        pytest.skip("no Countermap database; run `countermap build`")
    spec, warnings = export_scenario(transcript())
    # What Interlinear exports: one step per run of a technique, chained in the transcript's order.
    assert [step["technique"] for step in spec["steps"]] == techniques
    assert [step.get("after") for step in spec["steps"]] == [None] + [[f"s{k}"] for k in range(1, len(techniques))]
    assert warnings == export_warnings
    # Countermap takes it in every format. render validates the CAD and Attack Flow output and raises if either
    # fails; both are checked again here. Only what every Countermap release returns is read, so a later release
    # that adds keys (per-step mitigations, detection strategies) changes nothing here.
    formats = ["cad", "attack_flow", "mermaid", "navigator"]
    out = render(spec, Countermap(default_db_path()), formats)
    assert all(out[name] for name in formats)
    assert not validate_cad(out["cad"]) and not validate_attack_flow(out["attack_flow"])
    assert out["title"] == spec["title"]
    for step in spec["steps"]:  # every step is drawn, under its technique
        assert re.search(rf"\b{step['id']}\b", out["mermaid"]) and step["technique"] in out["mermaid"]
    layers = out["navigator"].values() if isinstance(out["navigator"], dict) else out["navigator"]
    on_layers = {entry["techniqueID"] for layer in layers for entry in layer["techniques"]}
    assert {t for t in techniques if not t.startswith("AML.")} <= on_layers
    # Countermap's only remark on the export: an ATLAS technique has no place on an ATT&CK Navigator layer. A database
    # built without D3FEND's published mappings adds one about itself (no countermeasures were added), in 0.2.0 and
    # 0.2.1 alike, which says nothing about the export.
    remarks = [warning for warning in out["warnings"] if "D3FEND" not in warning]
    assert all("AML.T0051" in warning for warning in remarks)
    assert bool(remarks) == ("AML.T0051" in techniques)


def test_cli_export_scenario_exits_3_when_the_output_cannot_be_written(tmp_path):
    path = tmp_path / "transcript.json"
    save(demo(), path)
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    assert cli.main(["export-scenario", str(path), "-o", str(blocker / "out.json")]) == 3


# The export never exposes a live host, even where a cut lands inside one.

HOST = "login.example-bank" + ".com" + ".evil-test.net"


def one_line(meaning, case="d", names=("s",)) -> Transcript:
    return Transcript(interlinear_version="0.1.0", case=case,
                      sources=[Source(id=k, name=name, sha256="0" * 64, size=1, kind="bash_history", parsed_at="x")
                               for k, name in enumerate(names)],
                      lines=[Line(n=1, source=0, line=1, actor="operator", text="x",
                                  gloss=Gloss(source="rule", meaning=meaning, techniques=[Technique(id="T1105")]))])


@pytest.mark.parametrize("shift", range(-20, 30))
def test_a_cut_step_description_leaves_no_live_host(shift):
    prefix = "Line 1 (rule; operator): "
    head = ("word " * 200)[: 500 - len(prefix) - len("Fetches from login.example-bank.com") + shift]
    meaning = defang(head + "Fetches from " + HOST + " daily.")  # as glossing stores it: only the last dot defanged
    assert "login.example-bank.com.evil-test[.]net" in meaning
    spec, _ = export_scenario(one_line(meaning))
    description = spec["steps"][0]["description"]
    assert len(description) <= 500 and description.endswith("...")
    assert description.startswith(prefix + "word word")
    assert defang(description) == description


@pytest.mark.parametrize("pad", range(150, 200))
def test_a_cut_title_leaves_no_live_host(pad):
    spec, _ = export_scenario(one_line("M."), title="t" * pad + " " + HOST)
    assert len(spec["title"]) <= 200  # Countermap's limit
    assert defang(spec["title"]) == spec["title"]


def test_the_title_and_source_names_are_defanged():
    t = one_line("M.", case="seen at login.example-bank" + ".com", names=("a.evil-test" + ".com", "b.sh"))
    spec, _ = export_scenario(t)
    assert spec["title"] == "seen at login.example-bank[.]com"
    assert spec["description"] == f"Exported by Interlinear {__version__} from a.evil-test[.]com, b.sh. {ORDER_NOTE}"
    spec, _ = export_scenario(t, title="www.evil-test" + ".com")
    assert spec["title"] == "www.evil-test[.]com"


# Export correctness

def test_a_revoked_technique_with_no_replacement_is_named_in_a_warning():
    t = demo()
    old = Gloss(source="analyst", by="Diego", meaning="Old technique.",
                techniques=[Technique(id="T1454", status="revoked")])
    t.lines[4].gloss = old
    t.lines.append(Line(n=7, source=0, line=7, actor="operator", text="f", gloss=old.model_copy(deep=True)))
    spec, warnings = export_scenario(t)
    assert [step["technique"] for step in spec["steps"]] == ["T1105", "T1690", "T1454", "T1053.003", "T1454"]
    assert warnings == ["T1454 is revoked and has no replacement; kept as is in steps s3, s5"]


def test_steps_never_merge_lines_from_two_sources():
    t = demo()
    t.sources.append(Source(id=1, name="b.sh", sha256="1" * 64, size=1, kind="script",
                            parsed_at="2026-10-15T00:00:00Z"))
    t.lines[1].source = 1  # line 2: the same technique and actor as line 1, from another file
    spec, _ = export_scenario(t)
    # Each file is a lane of its own: no step of one file comes after a step of another.
    assert [(step["id"], step["technique"], step.get("after")) for step in spec["steps"]] == [
        ("s1", "T1105", None), ("s2", "T1690", ["s1"]), ("s3", "T1053.003", ["s2"]), ("s4", "T1105", None)]
    assert spec["steps"][0]["description"] == ".bash_history: Line 1 (rule; operator): Downloads a script and runs it."
    assert spec["steps"][3]["description"] == "b.sh: Line 2 (rule; operator): Downloads a file."
    assert spec["description"].endswith(ORDER_NOTE)


def test_a_missing_meaning_is_left_out():
    t = demo()
    t.lines[5].gloss.meaning = None
    spec, _ = export_scenario(t)
    assert spec["steps"][-1]["description"] == "Line 6 (rule; operator)"


def test_cli_export_prints_warnings_escaped(tmp_path, capsys):
    t = demo()
    t.lines[5].gloss = Gloss(source="analyst", by="Diego", meaning="M.",
                             techniques=[Technique(id="T1454" + chr(0x1B) + "[2J", status="revoked")])
    path = tmp_path / "transcript.json"
    save(t, path)
    assert cli.main(["export-scenario", str(path), "-o", str(tmp_path / "scenario.json")]) == 1
    err = capsys.readouterr().err
    assert "warning: Line 6 has a technique ID that is not" in err and chr(0x1B) not in err


def test_cli_export_refuses_a_scenario_with_no_steps(tmp_path, capsys):
    t = demo()
    for line in t.lines:
        line.gloss = Gloss()
    path = tmp_path / "transcript.json"
    save(t, path)
    out = tmp_path / "scenario.json"
    assert cli.main(["export-scenario", str(path), "-o", str(out)]) == 2
    err = capsys.readouterr().err
    assert "no glossed lines with techniques" in err and "at least one step" in err
    assert not out.exists()


def test_the_description_names_at_most_ten_sources():
    names = tuple(f"s{k:02}.sh" for k in range(30))
    spec, _ = export_scenario(one_line("M.", names=names))
    assert spec["description"] == (f"Exported by Interlinear {__version__} from {', '.join(names[:10])} and 20 more. "
                                   f"{ORDER_NOTE}")


def test_the_description_caps_long_source_names():
    head = f"Exported by Interlinear {__version__} from "
    names = tuple("n" * 200 + str(k) for k in range(3))
    spec, _ = export_scenario(one_line("M.", names=names))
    assert spec["description"] == f"{head}{names[0]} and 2 more. {ORDER_NOTE}"
    spec, _ = export_scenario(one_line("M.", names=("n" * 5000,)))
    named = spec["description"][len(head):-len(". " + ORDER_NOTE)]
    assert len(named) == 300 and named == "n" * 297 + "..."


@pytest.mark.parametrize("bad", ["attack:T1105", "t1105", "T1105 ", "T1105" + chr(0x1B) + "[2J", "T11050", "",
                                 "TA0001", "AML.T0051.000.1"])
def test_only_canonical_technique_ids_are_exported(bad):
    t = demo()
    t.lines[1].gloss = g("rule", bad, meaning="Hand-edited.")  # line 2
    spec, warnings = export_scenario(t)
    assert [step["technique"] for step in spec["steps"]] == ["T1105", "T1690", "T1053.003"]
    assert spec["steps"][0]["description"] == "Line 1 (rule; operator): Downloads a script and runs it."
    assert warnings == ["Line 2 has a technique ID that is not an ATT&CK or ATLAS technique ID; left out of the "
                        "scenario"]


def test_a_non_canonical_replacement_is_left_out_too():
    t = demo()
    t.lines[3].gloss = g("model", "T1562.003", meaning="Hides the history.", revoked_to="T1690; x")  # line 4
    t.lines[5].gloss = g("rule", "AML.T0051", meaning="Injects a prompt.")  # line 6: an ATLAS ID is canonical
    t.lines.append(Line(n=7, source=0, line=7, actor="operator", text="f", gloss=g("rule", "<b>", meaning="M.")))
    spec, warnings = export_scenario(t)
    assert [step["technique"] for step in spec["steps"]] == ["T1105", "AML.T0051"]
    assert warnings == ["Lines 4, 7 have a technique ID that is not an ATT&CK or ATLAS technique ID; left out of the "
                        "scenario"]


def shown(code: int) -> str:
    return f"{chr(0x27E8)}U+{code:04X}{chr(0x27E9)}"


def test_export_shows_invisible_characters():
    rlo = chr(0x202E)
    t = one_line("Fetches" + chr(0x200B) + " a file.", names=("notes" + rlo + "txt.sh",))
    spec, _ = export_scenario(t, title="a" + rlo + "b" + chr(0x9B) + "31m" + chr(0x1B) + chr(0x7F))
    assert spec["title"] == f"a{shown(0x202E)}b{shown(0x9B)}31m{shown(0x1B)}{shown(0x7F)}"
    assert spec["steps"][0]["description"] == f"Line 1 (rule; operator): Fetches{shown(0x200B)} a file."
    assert f" from notes{shown(0x202E)}txt.sh. " in spec["description"]
    spec, _ = export_scenario(one_line("M.", case="x" + chr(0xFE0F) + chr(0x3164)))  # default-ignorable, outside Cf
    assert spec["title"] == f"x{shown(0xFE0F)}{shown(0x3164)}"
