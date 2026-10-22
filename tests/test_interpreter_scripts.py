"""Impacket's examples are usually run through the interpreter (python3 secretsdump.py ...), by agents above all. The
command position steps over python and its plain flags when the next word is a .py script, so every rule that names a
script matches it the same way with or without the interpreter. Anything else after python (-c code, -m module, an
option that takes an argument) leaves python as the command."""

import pytest

from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import load_library, partial_reason


@pytest.fixture(scope="module")
def library():
    return load_library()


def rule_of(library, text):
    rule = library.match(normalize_text(text), context=False)
    return rule and rule.id


SD = "secrets" + "dump.py"  # assembled at runtime, as attack-like text in the other tests

SCRIPTS = [
    (f"{SD} -just-dc corp/admin@10.0.0.5", "dcsync"),
    (f"{SD} -ntds ntds.dit -system SYSTEM LOCAL", "ntds-dump"),
    (f"{SD} -sam SAM -system SYSTEM LOCAL", "sam-dump"),
    ("GetUserSPNs.py corp/jdoe -dc-ip 10.0.0.5 -request", "kerberoast"),
    ("GetNPUsers.py corp/ -usersfile u.txt -no-pass", "asreproast"),
    ("psexec.py corp/admin@10.0.0.5", "smb-exec"),
    ("wmiexec.py corp/admin@10.0.0.5", "wmi-exec"),
]


def test_the_listed_rule_ids_are_the_library_s(library):
    for text, rule_id in SCRIPTS:
        assert rule_of(library, text) == rule_id, text


@pytest.mark.parametrize("prefix", [
    "python3 ", "python ", "python3.11 ", "python3 -u ", "python3 -B -u ", "sudo python3 ", "python.exe ",
    "python3 /opt/impacket/examples/", "python3 ./", "python3 '", "env python3 ",
])
@pytest.mark.parametrize("text, rule_id", SCRIPTS)
def test_a_script_run_through_python_matches_its_rule(library, prefix, text, rule_id):
    line = prefix + text
    if prefix.endswith("'"):
        script, _, rest = text.partition(" ")
        line = prefix + script + "' " + rest
    assert rule_of(library, line) == rule_id, line
    rule = next(r for r in library.rules if r.id == rule_id)
    assert partial_reason(rule, normalize_text(line)) is None, line


@pytest.mark.parametrize("text", [
    f"python3 -c 'import os' {SD} -just-dc corp/admin@10.0.0.5",
    f"python3 -m {SD[:-3]} -just-dc corp/admin@10.0.0.5",
    f"python3 -W ignore {SD} -just-dc corp/admin@10.0.0.5",
    f"python3 tool.py {SD} -just-dc corp/admin@10.0.0.5",
    f"pythonx {SD} -just-dc corp/admin@10.0.0.5",
    f"python3 {SD}x -just-dc corp/admin@10.0.0.5",
])
def test_python_is_stepped_over_only_before_a_script(library, text):
    assert rule_of(library, text) != "dcsync", text
