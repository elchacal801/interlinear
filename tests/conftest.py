import re

import pytest

from interlinear_cti.model import Technique, Transcript
from interlinear_cti.parse import parse_paths

# Technique statuses as Countermap reports them for ATT&CK 20.0 / ATLAS 2026.09 (checked 2026-10-15).
KNOWN = {
    "T1105": ("Ingress Tool Transfer", "active", []),
    "T1059.004": ("Unix Shell", "active", []),
    "T1059.001": ("PowerShell", "active", []),
    "T1222.002": ("Linux and Mac Permissions", "active", []),
    "T1140": ("Deobfuscate/Decode Files or Information", "active", []),
    "T1552.004": ("Private Keys", "active", []),
    "T1003.008": ("/etc/passwd and /etc/shadow", "active", []),
    "T1033": ("System Owner/User Discovery", "active", []),
    "T1082": ("System Information Discovery", "active", []),
    "T1057": ("Process Discovery", "active", []),
    "T1049": ("System Network Connections Discovery", "active", []),
    "T1016": ("System Network Configuration Discovery", "active", []),
    "T1087.001": ("Local Account", "active", []),
    "T1083": ("File and Directory Discovery", "active", []),
    "T1053.003": ("Cron", "active", []),
    "T1136.001": ("Local Account", "active", []),
    "T1098.004": ("SSH Authorized Keys", "active", []),
    "T1690": ("Prevent Command History Logging", "active", []),
    "T1070.003": ("Clear Command History", "active", []),
    "T1070.004": ("File Deletion", "active", []),
    "T1090": ("Proxy", "active", []),
    "T1021.004": ("SSH", "active", []),
    "T1046": ("Network Service Discovery", "active", []),
    "T1110": ("Brute Force", "active", []),
    "T1496.001": ("Compute Hijacking", "active", []),
    # Added with the rule library hardening (checked 2026-10-18).
    "T1572": ("Protocol Tunneling", "active", []),
    "T1110.001": ("Password Guessing", "active", []),
    "T1110.002": ("Password Cracking", "active", []),
    "T1110.004": ("Credential Stuffing", "active", []),  # 2026-10-20 precision fixes
    "T1685": ("Disable or Modify Tools", "active", []),
    "T1685.005": ("Clear Windows Event Logs", "active", []),
    "T1685.006": ("Clear Linux or Mac System Logs", "active", []),
    "T1548.001": ("Setuid and Setgid", "active", []),
    "T1548.003": ("Sudo and Sudo Caching", "active", []),
    "T1095": ("Non-Application Layer Protocol", "active", []),
    "T1197": ("BITS Jobs", "active", []),
    "T1027.010": ("Command Obfuscation", "active", []),
    "T1053.005": ("Scheduled Task", "active", []),
    "T1547.001": ("Registry Run Keys / Startup Folder", "active", []),
    "T1087.002": ("Domain Account", "active", []),
    "T1069.001": ("Local Groups", "active", []),
    "T1069.002": ("Domain Groups", "active", []),
    "T1482": ("Domain Trust Discovery", "active", []),
    "T1018": ("Remote System Discovery", "active", []),
    "T1543.002": ("Systemd Service", "active", []),
    "T1546.004": ("Unix Shell Configuration Modification", "active", []),
    "T1037.004": ("RC Scripts", "active", []),
    "T1668": ("Exclusive Control", "active", []),
    "T1059.006": ("Python", "active", []),
    "T1059": ("Command and Scripting Interpreter", "active", []),
    "T1059.003": ("Windows Command Shell", "active", []),
    # Added with the first real-data coverage pass (checked against Countermap 20.0, 2026-10-19).
    "T1610": ("Deploy Container", "active", []),
    "T1609": ("Container Administration Command", "active", []),
    "T1612": ("Build Image on Host", "active", []),
    "T1613": ("Container and Resource Discovery", "active", []),
    "T1611": ("Escape to Host", "active", []),
    "T1552.007": ("Container API", "active", []),
    "T1489": ("Service Stop", "active", []),
    "T1518": ("Software Discovery", "active", []),
    "T1569.003": ("Systemctl", "active", []),
    "T1685.004": ("Disable or Modify Linux Audit System Log", "active", []),
    "T1686": ("Disable or Modify System Firewall", "active", []),
    "T1560.001": ("Archive via Utility", "active", []),
    "T1654": ("Log Enumeration", "active", []),
    "T1555.003": ("Credentials from Web Browsers", "active", []),
    "T1539": ("Steal Web Session Cookie", "active", []),
    "T1217": ("Browser Information Discovery", "active", []),
    "T1078.003": ("Local Accounts", "active", []),
    # The Windows, AD and cloud rule pack (checked against Countermap's ATT&CK 20.0, 2026-10-22).
    "T1003.001": ("LSASS Memory", "active", []),
    "T1003.002": ("Security Account Manager", "active", []),
    "T1003.003": ("NTDS", "active", []),
    "T1003.006": ("DCSync", "active", []),
    "T1490": ("Inhibit System Recovery", "active", []),
    "T1558.003": ("Kerberoasting", "active", []),
    "T1558.004": ("AS-REP Roasting", "active", []),
    "T1550.002": ("Pass the Hash", "active", []),
    "T1021.006": ("Windows Remote Management", "active", []),
    "T1110.003": ("Password Spraying", "active", []),
    "T1021.002": ("SMB/Windows Admin Shares", "active", []),
    "T1569.002": ("Service Execution", "active", []),
    "T1047": ("Windows Management Instrumentation", "active", []),
    "T1552.001": ("Credentials In Files", "active", []),
    "T1552.005": ("Cloud Instance Metadata API", "active", []),
    "T1048": ("Exfiltration Over Alternative Protocol", "active", []),
    "T1562.003": (None, "revoked", ["T1690"]),
    "T1053.004": ("Launchd", "deprecated", []),
    "AML.T0051": ("LLM Prompt Injection", "active", []),
}


# The real resolver's gate: only an ATT&CK or ATLAS technique ID is looked up. Anything else is unknown.
_CANONICAL = re.compile(r"(?:AML\.)?T[0-9]{4}(?:\.[0-9]{3})?")


class FakeResolver:
    """Stands in for CountermapResolver so tests need neither Countermap nor its database.

    Like the real resolver, it strips and upper-cases the ID and checks only canonical technique IDs, and a
    non-string is unknown.
    """

    def check(self, technique_id: str) -> Technique:
        if not isinstance(technique_id, str):
            return Technique(id="", framework="attack", status="unknown")
        key = technique_id.strip().upper()
        framework = "atlas" if key.startswith("AML.") else "attack"
        if not _CANONICAL.fullmatch(key) or key not in KNOWN:
            return Technique(id=key, framework=framework, status="unknown")
        name, status, replaced_by = KNOWN[key]
        return Technique(id=key, framework=framework, status=status, name=name, replaced_by=list(replaced_by))

    def versions(self) -> dict[str, str]:
        return {"attack-enterprise": "20.0"}

    # The CLI closes its resolver when a command is done (with CountermapResolver(...) as resolver), so the stand-in
    # supports the same calls. It holds no connection, so closing does nothing.
    def close(self) -> None:
        pass

    def __enter__(self) -> "FakeResolver":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


@pytest.fixture
def parse_text(tmp_path):
    def _parse(name: str, text: str) -> Transcript:
        path = tmp_path / name
        path.write_bytes(text.encode("utf-8"))
        return Transcript.model_validate(parse_paths([path], now="2026-10-15T00:00:00Z"))

    return _parse
