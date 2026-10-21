import json
import re
from pathlib import Path

import pytest

from interlinear_cti.export import export_scenario
from interlinear_cti.glossing import apply_rules
from interlinear_cti.model import Transcript
from interlinear_cti.normalize import TLDS
from interlinear_cti.parse import parse_paths
from interlinear_cti.render import render_markdown
from interlinear_cti.rules import load_library

FIXTURES = Path(__file__).parent / "fixtures"
INPUTS = sorted(
    (p for p in (FIXTURES / "inputs").iterdir() if p.is_file() and not p.name.startswith(".")),
    key=lambda p: p.name,
)
APPROVED = FIXTURES / "approved"
NOW = "2026-10-15T00:00:00Z"
_H = r"[0-9A-Fa-f]{1,4}"
# An IPv6 literal needs "::" or all eight groups, so clock times such as 10:22:33 never match.
_V6 = rf"(?:{_H}(?::{_H}){{7}}|(?:{_H}(?::{_H}){{0,6}})?::(?:{_H}(?::{_H}){{0,6}})?)"
# Deliberately stricter than the defanger: no lookarounds on addresses, any live dotted name whose last
# label is a TLD the defanger handles, any scheme other than hxxp(s) followed by a live host (the defanger
# leaves "ftp://" but defangs the host after it), and live IPv6 literals, bare or in brackets.
UNDEFANGED = re.compile(
    r"https?://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[A-Za-z0-9-]\.(?:%s)(?![A-Za-z0-9])" % "|".join(sorted(TLDS, key=len, reverse=True))
    + r"|(?<![A-Za-z0-9+.-])(?!hxxps?://)[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*(?=[/:?#\s'\")]|$)"
    + rf"|(?<![\w:\[]){_V6}(?![\w:\]])"
    + rf"|\[{_V6}\]",
    re.IGNORECASE,
)


def glossed(path: Path, resolver) -> Transcript:
    transcript = Transcript.model_validate(parse_paths([path], case=path.name, now=NOW))
    apply_rules(transcript, load_library(resolver=resolver), at=NOW)
    transcript.datasets = resolver.versions()
    return transcript


def scenario_text(transcript: Transcript) -> str:
    spec, _ = export_scenario(transcript)
    return json.dumps(spec, indent=2, ensure_ascii=False) + "\n"


def approved(name: str) -> str:
    return (APPROVED / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("path", INPUTS, ids=lambda p: p.name)
def test_fixture_output_is_defanged(path, resolver):
    transcript = glossed(path, resolver)
    texts = [line.text for line in transcript.lines]
    texts += [ioc.value for line in transcript.lines for ioc in line.gloss.iocs]
    texts += [s.name for s in transcript.sources] + transcript.warnings
    texts += [render_markdown(transcript), scenario_text(transcript)]
    for text in texts:
        assert not UNDEFANGED.search(text), text


LIVE_FORMS = [
    "http://example.com/x",
    "https://203.0.113.5/x",
    "ftp://h/x",
    "sftp://files.example/x",
    "ftp://example.com",
    "203.0.113.5",
    "host.example.com",
    "2001:db8::5",
    "::1",
    "2001:db8:0:0:0:0:0:5",
    "[2001:db8::5]:80",
    "see [2001:db8::5]",
]
DEFANGED_FORMS = [
    "hxxp://example[.]com/x",
    "hxxps://203.0.113[.]5/x",
    "ftp://example[.]com/x",
    "sftp://203.0.113[.]5/x",
    "203.0.113[.]5",
    "host[.]example[.]com",
    "2001[:]db8[:][:]5",
    "at 10:22:33 UTC",
    "sha256 `76691a8c0bb5`",
    "rules `2026.10.1` ATT&CK `20.0`",
    "[rule: whoami-id] [context] [pending]",
]


@pytest.mark.parametrize("text", LIVE_FORMS)
def test_sweep_flags_live_forms(text):
    assert UNDEFANGED.search(text), text


@pytest.mark.parametrize("text", DEFANGED_FORMS)
def test_sweep_passes_defanged_forms(text):
    assert not UNDEFANGED.search(text), text


def test_approved_holds_exactly_two_files_per_input():
    expected = {f"{p.name}{suffix}" for p in INPUTS for suffix in (".md", ".scenario.json")}
    assert {p.name for p in APPROVED.iterdir()} == expected


@pytest.mark.parametrize("path", INPUTS, ids=lambda p: p.name)
def test_markdown_matches_the_approved_copy(path, resolver):
    assert render_markdown(glossed(path, resolver)) == approved(f"{path.name}.md")


@pytest.mark.parametrize("path", INPUTS, ids=lambda p: p.name)
def test_scenario_matches_the_approved_copy(path, resolver):
    assert scenario_text(glossed(path, resolver)) == approved(f"{path.name}.scenario.json")
