"""The gloss skill's settings: it runs on Haiku by default (2026-10-21 model-tier trials), keeps its narrow
pre-approved commands, and hands the lines it could not gloss with confidence to an analyst."""

from pathlib import Path

import yaml

SKILL = Path(__file__).resolve().parent.parent / "plugin" / "skills" / "gloss" / "SKILL.md"


def parts():
    text = SKILL.read_text(encoding="utf-8").replace("\r\n", "\n")  # a Windows checkout may use CRLF
    assert text.startswith("---\n")
    front, body = text[4:].split("\n---\n", 1)
    return yaml.safe_load(front), body


def test_the_skill_runs_on_haiku():
    front, _ = parts()
    assert front["model"] == "haiku"


def test_the_pre_approved_commands_are_unchanged():
    front, _ = parts()
    assert front["allowed-tools"] == ("Bash(interlinear pending:*), Bash(interlinear apply-glosses:*), "
                                      "PowerShell(interlinear pending:*), PowerShell(interlinear apply-glosses:*)")


def test_the_report_lists_lines_for_analyst_review():
    _, body = parts()
    report = body.split("**Report:**", 1)[1]
    assert "low" in report and "pending" in report
    assert "analyst review" in report
    assert "interlinear annotate" in report
