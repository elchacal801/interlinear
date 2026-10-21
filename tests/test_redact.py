"""Credentials in attacker commands stay in transcript.json as evidence, but are redacted from the text `interlinear
pending` sends to a hosted model (by default) and from the Markdown view (on request)."""

import json

import pytest

from interlinear_cti import cli
from interlinear_cti.glossing import apply_glosses, pending_lines
from interlinear_cti.model import load
from interlinear_cti.normalize import normalize_text
from interlinear_cti.redact import redact

SECRETS = ("Passw0rd", "Summer2026!", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "8846f7eaee8fb117ad06bdd830b7586c",
           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlc2lnbmF0dXJl", "AKIAIOSFODNN7EXAMPLE",
           "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa")

LEAKY = [
    "net user hacker Passw0rd /add",
    "net user hacker 'Passw0rd' /add /domain",
    "evil-winrm -i 10.0.0.5 -u admin -p 'Summer2026!'",
    "crackmapexec smb 10.0.0.0/24 -u admin -p Summer2026!",
    "nxc smb 10.0.0.5 -u admin -p 'Summer2026!' --shares",
    "impacket-psexec CORP/admin:Summer2026!@10.0.0.5",
    "secretsdump.py 'corp.local/admin:Summer2026!@10.0.0.5'",
    "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "DB_PASSWORD=Passw0rd ./run.sh",
    "curl -u admin:Summer2026! http://203.0.113.5/api",
    "curl http://203.0.113.5/login?user=admin&password=Summer2026!",
    "mysql -u root -pSummer2026! shop",
    "sshpass -p Summer2026! ssh root@10.0.0.5",
    "$pw = ConvertTo-SecureString 'Summer2026!' -AsPlainText -Force",
    "$password = 'Summer2026!'",
    "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlc2lnbmF0dXJl' http://x",
    "smbclient //10.0.0.5/c$ -U 'admin%Summer2026!'",
    "xfreerdp /u:admin /p:Summer2026! /v:10.0.0.5",
    "echo 'Summer2026!' | sudo -S id",
    "evil-winrm -i 10.0.0.5 -u admin -H 8846f7eaee8fb117ad06bdd830b7586c",
    "wmiexec.py -hashes :8846f7eaee8fb117ad06bdd830b7586c corp/admin@10.0.0.5",
    "hydra -l admin -p Summer2026! ssh://10.0.0.5",
    "ldapsearch -x -H ldap://10.0.0.5 -D admin -w Summer2026!",
    "mysql --password=Summer2026! -u root",
    "Invoke-Thing -Password Summer2026!",
    "aws configure set aws_secret_access_key wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    "echo AKIAIOSFODNN7EXAMPLE",
    "git clone https://ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@github.com/x/y",
    "export ANTHROPIC_API_KEY=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa",
    "echo 'admin:Summer2026!' | chpasswd",
    "useradd -m -p Passw0rd bob",
]

CLEAN = [
    "nmap -p 80,443 10.0.0.5",
    "mkdir -p /tmp/x",
    "ssh -p 2222 root@10.0.0.5",
    "docker run -p 8080:80 nginx",
    "net user bob /domain",
    "hydra -l admin -P rockyou.txt ssh://10.0.0.5",
    "git clone git@github.com:x/y.git",
    "cat /etc/passwd | grep root",
    "ls -la ~/.ssh",
    "Set-ExecutionPolicy Bypass -Scope Process",
    "docker login --password-stdin",
    "curl http://203.0.113.5:8080/x",
]


@pytest.mark.parametrize("text", LEAKY)
def test_credentials_are_redacted(text):
    stored = normalize_text(text)  # rules and redaction see the defanged text that transcript.json holds
    out = redact(stored)
    assert "<redacted" in out and not any(secret in out for secret in SECRETS), out


@pytest.mark.parametrize("text", CLEAN)
def test_ordinary_options_are_left_alone(text):
    stored = normalize_text(text)
    assert redact(stored) == stored


def test_redaction_is_idempotent():
    once = redact(normalize_text(LEAKY[2]))
    assert redact(once) == once


def test_pending_redacts_by_default_and_the_transcript_keeps_the_evidence(tmp_path, capsys):
    history = tmp_path / ".bash_history"
    history.write_bytes(b"net user hacker Passw0rd /add\nfrobnicate -p Summer2026!\n")
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(history), "-o", str(path)]) == 0
    capsys.readouterr()
    assert cli.main(["pending", str(path)]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert "Passw0rd" not in rows[0]["text"] and "<redacted" in rows[0]["text"]
    assert "Passw0rd" in load(path).lines[0].text  # the evidence stays in transcript.json
    assert cli.main(["pending", str(path), "--no-redact-secrets"]) == 0
    assert "Passw0rd" in json.loads(capsys.readouterr().out)[0]["text"]


def test_pending_lines_redacts_only_when_asked(parse_text):
    transcript = parse_text(".bash_history", "net user hacker Passw0rd /add\n")
    assert "Passw0rd" in pending_lines(transcript)[0]["text"]
    assert "Passw0rd" not in pending_lines(transcript, redact_secrets=True)[0]["text"]


def test_render_redacts_line_text_and_gloss_text_on_request(tmp_path, monkeypatch, resolver, capsys):
    monkeypatch.setattr("interlinear_cti.verify.CountermapResolver", lambda db=None: resolver)
    history = tmp_path / ".bash_history"
    history.write_bytes(b"frobnicate --password Summer2026!\n")
    path = tmp_path / "transcript.json"
    assert cli.main(["parse", str(history), "-o", str(path)]) == 0
    transcript = load(path)
    entry = {"n": 1, "meaning": "Logs in with --password Summer2026! to the tool.", "techniques": ["T1059.004"],
             "confidence": "low"}
    apply_glosses(transcript, [entry], source="model", by="m", resolver=resolver, at="2026-10-22T00:00:00Z")
    from interlinear_cti.model import save

    save(transcript, path)
    assert cli.main(["render", str(path)]) == 0
    assert "Summer2026!" in path.with_suffix(".md").read_text(encoding="utf-8")
    assert cli.main(["render", str(path), "--redact-secrets"]) == 0
    view = path.with_suffix(".md").read_text(encoding="utf-8")
    assert "Summer2026!" not in view and view.count("<redacted") == 2


def test_redaction_scales_linearly():
    import time

    def best(text):
        out = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            redact(text)
            out = min(out, time.perf_counter() - start)
        return out

    for unit in ("a:", "/a:b", "-p ", "a=", "password=", "--password ", "x@", "net user a ", "'", "echo a | ",
                 "-----BEGIN RSA PRIVATE KEY-----", "Authorization: ", "pass:", "/p:", "$a = '", "eyJa.", "a%"):
        head = "nxc mysql sqlcmd 7z zip ldapsearch useradd "
        small, large = (head + unit * (n // len(unit)) for n in (4096, 16384))
        small_time, large_time = best(small), best(large)
        assert large_time < 0.25, (unit, large_time)
        assert large_time < 0.003 or large_time < 8 * small_time, (unit, small_time, large_time)
