"""CONTEXT is an allowlist: the bypasses found by four review rounds, through the real path (parse_paths on a file,
then apply_rules), in each reader. None of the lines that run code may be labeled context, or be claimed by a
persistence-write rule that would describe a record hiding them. Attack-like text is built from fragments."""

import json

import pytest

from interlinear_cti.glossing import apply_rules
from interlinear_cti.model import Transcript
from interlinear_cti.parse import parse_paths
from interlinear_cti import rules
from interlinear_cti.rules import load_library

AT = "2026-10-19T00:00:00Z"
BS, NUL, CR, NBSP, LONG_S = "\\", chr(0), chr(13), chr(0xA0), chr(0x17F)
SHADOW = "cat /etc/" + "sha" + "dow"
ADD = "user" + "add -o -u 0 svc"
MARK = "echo MA" + "RK >&2"
SUB = "a" + BS + "[" + BS + "$" + BS + "(id" + BS + ")" + BS + "]"  # x=a\[\$\(id\)\] stores a[$(id)]
# agent-call.jsonl holds the whole text as one agent tool call, which parse splits into its commands (D10(a)).
READERS = (".bash_history", ".zsh_history", "x.sh", "agent.jsonl", "agent-call.jsonl")
PERSISTENCE_WRITES = {"cron-download", "cron", "ssh-authorized-keys-download", "ssh-authorized-keys", "sshd-config",
                      "shell-rc-download", "shell-rc", "rc-script-download", "rc-script", "systemd-service-download",
                      "systemd-service", "pm2-startup", "sudoers-write"}


@pytest.fixture(scope="module")
def library():
    return load_library()


def raw_for(kind: str, text: str) -> bytes:
    """text as kind: one agent tool call, or one history entry, per line, a script, or one agent tool call."""
    lines = text.split("\n")
    if kind == "agent-call.jsonl":
        out = json.dumps({"role": "tool_call", "tool": "terminal", "input": text}) + "\n"
    elif kind == "agent.jsonl":
        out = "".join(json.dumps({"role": "tool_call", "tool": "terminal", "input": t}) + "\n" for t in lines)
    elif kind == ".zsh_history":
        out = "".join(f": 17600000{k:02d}:0;{t}\n" for k, t in enumerate(lines))
    else:
        out = text + "\n"
    return out.encode("utf-8")


def glossed(tmp_path, library, name: str, data: bytes) -> Transcript:
    path = tmp_path / name
    path.write_bytes(data)
    transcript = Transcript.model_validate(parse_paths([path], now=AT))
    path.unlink()
    apply_rules(transcript, library, at=AT)
    return transcript


def assert_hidden(transcript: Transcript, runs: tuple[str, ...], model: bool = False) -> None:
    """No line that holds one of runs is context or a persistence write; with model, each is left to the model."""
    seen = 0
    for line in transcript.lines:
        if line.actor == "tool_output" or not any(marker in line.text for marker in runs):
            continue
        seen += 1
        assert line.gloss.source != "none", (line.text, line.gloss.rule_id)
        assert line.gloss.rule_id not in PERSISTENCE_WRITES, (line.text, line.gloss.rule_id)
        if model:
            assert line.gloss.source == "pending", (line.text, line.gloss.rule_id)
    assert seen, "no line holds the payload"


# Session state: a record that changes how later commands resolve, then a literal command that now runs code.
SESSION = [
    # confirm review: bash's hash table and alias list as arrays, and their declare, export, += and local forms
    ("BASH_CMDS=(ls /tmp/.x/p)\nls", ("ls",)),
    ("BASH_ALIASES=(ls '" + MARK + "')\nls -la", ("ls",)),
    ("declare -A BASH_CMDS=(ls /tmp/.x/p)\nls", ("ls",)),
    ("export BASH_ALIASES=(cd '" + MARK + "')\ncd /tmp", ("cd",)),
    ("BASH_CMDS+=(pwd /tmp/.x/p)\npwd", ("pwd",)),
    ("local -A BASH_ALIASES=(ls '" + MARK + "')\nls", ("ls",)),
    ("BASH_CMDS=(ls /bin/sh)\nls -c '" + SHADOW + " > /tmp/.x/s'", ("ls",)),
    ("BASH_ALIASES=(echo '" + ADD + ";')\necho hi", ("echo",)),
    # set -k puts NAME=value arguments into the environment of each later command
    ("set -k\nls LD_PRELOAD=/tmp/.x/l.so\ndocker logs web LD_PRELOAD=/tmp/.x/l.so\nclear LD_PRELOAD=/tmp/.x/l.so",
     ("LD_PRELOAD",)),
    ("set -o keyword\ncd BASH_ENV=/tmp/.x/e", ("BASH_ENV",)),
    # the classic forms, and the ones that hide the trigger word
    ("alias ls='" + MARK + "'\nls", ("ls",)),
    ("a''lias ls='" + MARK + "'\nls", ("ls",)),
    (BS + "alias ls='" + MARK + "'\nls", ("ls",)),
    ("a=alias\n$a ls='" + MARK + "'\nls", ("ls",)),
    ("{alias,ls='" + MARK + "'}\nls", ("ls",)),
    ("ls() { " + MARK + "; }\nls", ("ls",)),
    ("function cd { " + MARK + "; }\ncd /tmp", ("cd",)),
    ("hash -p /tmp/.x/p ls\nls", ("ls",)),
    ("enable -n echo\necho hi", ("echo",)),
    ("trap '" + MARK + "' DEBUG\ntrue", ("true",)),
    ("PATH=/tmp/.x:/usr/bin\nls", ("ls",)),
    ("export PROMPT_COMMAND=/tmp/.x/p\npwd", ("pwd",)),
    ("read -r PROMPT_COMMAND < /tmp/.x/v\npwd", ("pwd",)),
    ("printf -v PS4 x\ntrue", ("true",)),
    (". /tmp/.x/env\nls", ("ls",)),
    ("source /tmp/.x/env\nls", ("ls",)),
    ("eval \"$(cat /tmp/.x/e)\"\nls", ("ls",)),
    ("shopt -s expand_aliases\nls", ("ls",)),
    ("echo 'alias cd=/tmp/.x/p' >> ~/.bashrc\ncd /var", ("cd /var",)),
]

# zsh: names and forms that run code in zsh but read as bash context (confirm review C-2)
ZSH = [
    ("functions=(ls '" + ADD + "')\nls -la", ("ls",)),
    ("aliases=(cd '" + SHADOW + " >/tmp/.x/s;')\ncd /tmp", ("cd",)),
    ("PROMPT=" + BS + "$" + BS + "(id" + BS + ")\nRPROMPT='%~'\nRPS1=x\nSPROMPT=x", ("PROMPT", "RPS1")),
    ("x=" + SUB + "\na=(1 2)\necho $a[x]\nls $a[x]\n[ \"$a[x]\" ]\ncd /tmp/$a[x]", ("x", "a")),
    ("precmd_functions+=(x)\nls", ("ls",)),
    ("chpwd() { " + MARK + " }\ncd /tmp", ("cd",)),
    ("path=(/tmp/.x $path)\nls", ("ls",)),
    ("setopt prompt_subst\nls", ("ls",)),
    # zsh reads these numbers as arithmetic, so x's value a[$(id)] runs id (found when rerunning the probes)
    ("x=" + SUB + "\nexit x\nreturn x\nshift x\nbreak x\nprintf '%d' x\nread -t x y", ("x",)),
]

# Bytes that bash reads differently than the stored lines show (confirm review C-3, C-4; earlier C7).
BYTES = [
    ("x.sh", ("true\necho x" + BS + NUL + "\n#|" + SHADOW + "\n").encode(), ("true", "echo", "#|")),
    ("x.sh", (("#" * 70 + "\n") * 120 + "true\necho x" + BS + NUL + "\n#|" + SHADOW + "\n").encode(),
     ("true", "#|")),
    ("x.sh", ("true\necho x" + BS + NUL + NUL + "\n#|" + MARK + "\n").encode(), ("true", "#|")),
    ("x.sh", ("true\nls -la /tmp" + BS + NUL + "\n#| id\n").encode(), ("true", "#|")),
    ("x.sh", ("true\ncat >> ~/.bashrc <<'EOF'\nalias ll=ls\nEO" + NUL + "F\n" + ADD + "\n" + SHADOW
              + "\nEOF\nid\n").encode(), ("true", "user", "shadow", "id")),
    ("x.sh", ("true\ncat <" + NUL + "<EOF\nwhoami\nEOF\nid\n").encode(), ("true", "whoami", "id")),
    ("x.sh", ("true\necho $" + NUL + "(id)\n").encode(), ("true", "echo")),
    ("agent.jsonl", (json.dumps({"role": "tool_call", "tool": "terminal", "input": "echo x" + BS + NUL + "\n#|"
                                 + SHADOW}) + "\n").encode(), ("echo", "#|")),
    ("x.sh", (": " + BS + CR + "\n" + SHADOW + " #" + CR + "\n").encode(), (":", "shadow")),
    ("x.sh", (": " + BS + CR + "\n" + ADD + "\nls\n").encode(), (":", "user", "ls")),
    ("x.sh", ("echo " + BS + CR + "\n" + ADD + "\n").encode(), ("echo", "user")),
    (".bash_history", (": " + BS + CR + "\n" + ADD + CR + "\n").encode(), (":", "user")),
    ("x.sh", ("cd /tmp" + CR + "ls\n").encode(), ("cd",)),
]

# Lines bash reads as something else: env options that take a command line (I-1), docker's global options (I-3), a #
# glued to a word (M-2), a no-break space (M-3), and letters that (?i) folds to ASCII.
MODEL = ["env -S /tmp/.x/a whoami", "env -S'/tmp/.x/a' whoami", "env -S/tmp/.x/a id", "env --split-string=/tmp/.x/a id",
         "env -iS /tmp/.x/a uname -a", "timeout 5 env -S /tmp/.x/a whoami", "env -S /tmp/.x/a cat /etc/passwd",
         "env -a x /tmp/.x/a", "env -C /tmp/.x id", "env -P /tmp/.x id", "su#x", "su root#x -c id",
         "cat" + NBSP + "/etc/passwd", "whoami" + NBSP + "#", "l" + LONG_S, "l" + LONG_S + " -la", LONG_S + "udo bash",
         LONG_S + "et -e", "hi" + LONG_S + "tory"]
NOT_CONTEXT = ["docker --config info info", "docker -c version version", "docker --context logs logs web",
               "docker -H logs logs web", "docker --config compose compose logs", "docker -l info info",
               "docker --log-level logs logs x", "docker -D info"]

# Earlier rounds: values that run code when evaluated, test and printf forms, blanks that hide a comment.
EARLIER = [
    ("x=" + SUB + "\n[[ $x -eq 0 ]]", ("x",)),
    ("op=-v\n[ $op 'b[x]' ]", ("[",)),
    ("v=-v\n[ $v ]\nif [ $v ]", ("[",)),
    ("p='-v b[x]'\n[ -f $p ]\ntest -n $p", ("[", "test")),
    ("test $'-v' 'b[x]'\n[ $\"-v\" 'b[x]' ]", ("test", "[")),
    ("printf >/dev/null -vHISTFILE /dev/null\nprintf 2>&1 -vPROMPT_COMMAND /tmp/.x/run\nprintf >&2 -vPS4 x",
     ("printf",)),
    ("echo x" + NBSP + "#|" + SHADOW + "\nls" + NBSP + "#| " + ADD, ("echo", "ls")),
    ("x=" + BS + "$" + BS + "(id" + BS + ")\nRANDOM=" + SUB + "\nOPTIND=" + SUB, ("x", "RANDOM", "OPTIND")),
    ("read -u 3 x\nsudo -p ls bash\necho ${x@P}\necho ${!x}\necho ${y:x}", ("read", "sudo", "echo")),
    ("set +o history\nexport HISTFILE=/dev/null\nls", ("set", "HIST", "ls")),
]


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("text, runs", SESSION, ids=[text.split("\n")[0][:40] for text, _ in SESSION])
def test_session_changes_stop_context(tmp_path, library, kind, text, runs):
    assert_hidden(glossed(tmp_path, library, kind, raw_for(kind, text)), runs)


@pytest.mark.parametrize("text, runs", ZSH, ids=[text.split("\n")[0][:40] for text, _ in ZSH])
def test_zsh_special_names(tmp_path, library, text, runs):
    assert_hidden(glossed(tmp_path, library, ".zsh_history", raw_for(".zsh_history", text)), runs)


@pytest.mark.parametrize("name, data, runs", BYTES, ids=[f"bytes{k}" for k in range(len(BYTES))])
def test_control_bytes_stop_context(tmp_path, library, name, data, runs):
    transcript = glossed(tmp_path, library, name, data)
    assert_hidden(transcript, runs)
    assert transcript.sources[0].no_context


@pytest.mark.parametrize("kind", (".bash_history", "x.sh"))
@pytest.mark.parametrize("text", MODEL)
def test_misread_lines_go_to_the_model(tmp_path, library, kind, text):
    assert_hidden(glossed(tmp_path, library, kind, raw_for(kind, text)), (text,), model=True)


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("text", NOT_CONTEXT)
def test_docker_global_options(tmp_path, library, kind, text):
    assert_hidden(glossed(tmp_path, library, kind, raw_for(kind, text)), ("docker",))


@pytest.mark.parametrize("kind", (".bash_history", "x.sh", "agent.jsonl", "agent-call.jsonl"))
@pytest.mark.parametrize("text, runs", EARLIER, ids=[f"earlier{k}" for k in range(len(EARLIER))])
def test_earlier_rounds(tmp_path, library, kind, text, runs):
    assert_hidden(glossed(tmp_path, library, kind, raw_for(kind, text)), runs)


# The allowlist still labels plain work, and says where and why it stops.
PLAIN = "cd /tmp\nls -la\necho hello\nx=1\ntrue\n# a note\n[ -f /tmp/x ]\ntest -n x\napt-get update\ndocker logs web"


@pytest.mark.parametrize("kind", READERS)
def test_plain_lines_stay_context(tmp_path, library, kind):
    transcript = glossed(tmp_path, library, kind, raw_for(kind, PLAIN))
    context = [line.text for line in transcript.lines if line.gloss.source == "none"]
    expected = [t for t in PLAIN.split("\n") if not (kind == ".zsh_history" and t == "x=1")]
    assert sorted(context) == sorted(expected)
    assert not transcript.sources[0].no_context


def test_the_tainting_line_is_named(tmp_path, library):
    transcript = glossed(tmp_path, library, "x.sh", raw_for("x.sh", "cd /tmp\nls\nalias ll='ls -la'\nls\ncd /"))
    labels = [line.gloss.source for line in transcript.lines]
    assert labels[:2] == ["none", "none"] and "none" not in labels[2:]
    assert any("line 3: alias can change how later commands run" in w for w in transcript.warnings)


@pytest.mark.parametrize("name", ("x.sh", ".bash_history", ".zsh_history"))
def test_a_crlf_file_gets_no_context(tmp_path, library, name):
    # A CR is a bash concern (a backslash before it joins lines differently than the stored lines show), so a bash,
    # zsh or sh source keeps the strict rule even when its line endings are uniformly CRLF.
    data = raw_for(name, "cd /tmp\nls -la").replace(b"\n", b"\r\n")
    transcript = glossed(tmp_path, library, name, data)
    assert [line.gloss.source for line in transcript.lines] == ["pending", "pending"]
    assert transcript.sources[0].no_context.startswith("line 1: ")


POWERSHELL = ("x.ps1", "ConsoleHost_history.txt")
PS_TEXT = "cd C:" + BS + "Temp\nGet-ChildItem\nls\n# a note\nwhoami\necho hello"


def _labels(transcript: Transcript) -> list[tuple[int, str, str]]:
    return [(line.line, line.text, line.gloss.source) for line in transcript.lines]


@pytest.mark.parametrize("encoding", ("utf-8", "utf-16"))
@pytest.mark.parametrize("name", POWERSHELL)
def test_a_uniformly_crlf_powershell_file_is_read_as_if_it_were_lf(tmp_path, library, name, encoding):
    # Windows writes PowerShell scripts and the PSReadLine history with CRLF (and Windows PowerShell 5.1's > writes
    # UTF-16), and PowerShell reads CRLF as LF, so uniform CRLF is not a taint there.
    lf = glossed(tmp_path, library, name, (PS_TEXT + "\n").encode(encoding))
    crlf = glossed(tmp_path, library, name, (PS_TEXT.replace("\n", CR + "\n") + CR + "\n").encode(encoding))
    assert _labels(crlf) == _labels(lf)
    assert {text for _, text, label in _labels(crlf) if label == "none"} == {"ls", "# a note", "echo hello"}
    assert not crlf.sources[0].no_context
    assert not any(CR in line.text or chr(0x240D) in line.text for line in crlf.lines)


@pytest.mark.parametrize("name", POWERSHELL)
@pytest.mark.parametrize("data", [
    b"ls\r\n# a note\nls\r\n",  # mixed: one line ends LF
    b"ls\r\n# a note\rls\r\n",  # a lone CR
    b"ls\r\r\n# a note\r\n",  # a CR not followed by LF, before a CRLF
    b"ls\r\n# a note\r\nls\r",  # a lone CR at the end of the file
    b"ls\r\n# a " + NUL.encode() + b"note\r\n",  # a NUL in a CRLF file
    b"ls\r\n# a " + chr(0x0B).encode() + b"note\r\n",  # another control character in a CRLF file
    b"ls\r\n# a " + chr(0x85).encode() + b"note\r\n",  # a C1 control (NEL) in a CRLF file
], ids=["mixed", "lone-cr", "cr-cr-lf", "final-cr", "nul", "vt", "nel"])
def test_a_powershell_file_with_other_crs_or_controls_still_gets_no_context(tmp_path, library, name, data):
    transcript = glossed(tmp_path, library, name, data)
    assert transcript.sources[0].no_context
    assert "none" not in [line.gloss.source for line in transcript.lines]


@pytest.mark.parametrize("text, zsh, expected", [
    ("ls -la", False, True), ("cd ~/x", False, True), ('echo "a b"', False, True), ("# $(id) is a note", False, True),
    ("[ -f /tmp/x ]", False, True), ("x=1", False, True), ("x=1", True, False), ("X=1", False, False),
    ("path=x", False, False), ("_x=1", False, False), ("ls ~", False, False), ("cd ~-", False, False),
    ("echo 'a", False, False), ("echo $x", False, False), ("ls *", False, False), ("echo hi!", False, False),
    ("cd /tmp && ls", False, False), ("echo `id`", False, False), ("echo '$(id)'", False, False),
    ("[ -f x ] ]", False, False), ("[[ -f x ]]", False, False), ("ls\nid", False, False),
    ("echo " + chr(0xE9), False, False), ("ls" + chr(0x0B), False, False),
    ("exit 1", False, True), ("exit x", False, False), ("then exit x", False, False), ("shift x", False, False),
    ("printf '%d' 5", False, True), ("printf '%d' x", False, False), ("printf '%s' x", False, True),
    ("read -t 5 x", False, True), ("read -t x y", False, False), ("read -rn1 c", False, True),
])
def test_plainly_literal(text, zsh, expected):
    assert rules.plainly_literal(text, zsh) is expected


@pytest.mark.parametrize("text", ["ls -la", "cd /tmp", "echo hi", "x=1", "[ -f x ]", "if [ -f x ]; then", "cp a b",
                                  "ls *.log", "cat /etc/passwd", "echo $HOME"])
def test_ordinary_lines_change_nothing(text):
    assert rules.changes_later_commands(text) is None
