"""Fixes from the 2026-10-20 rule precision sample: two technique tags and one source of IOC noise.

- nmap -sn (and its old spelling -sP) is a host sweep with no port scan: T1018 Remote System Discovery, not T1046.
- hydra -C and medusa -C read login:password pairs from a file, which is credential stuffing (T1110.004), not
  password guessing (T1110.001).
- Loopback and link-local addresses name the host itself or its own link, never remote infrastructure, so a gloss does
  not report them as IOCs. Only the plain dotted form is left out: 0127.0.0.1 may be read as octal, so it stays.

The lines are synthetic and use documentation addresses only.
"""

import pytest

from interlinear_cti.iocs import extract, indicators
from interlinear_cti.normalize import normalize_text
from interlinear_cti.rules import gloss_for, load_library

AT = "2026-10-20T00:00:00Z"
HY, ME = "hy" + "dra", "me" + "dusa"


@pytest.fixture(scope="module")
def library():
    return load_library()


def tagged(library, text):
    text = normalize_text(text)
    rule = library.match(text)
    assert rule is not None, text
    return rule.id, [t.id for t in gloss_for(library, rule, text, AT).techniques]


@pytest.mark.parametrize("text", ["nmap -sn 192.0.2.0/24", "sudo nmap -sn -PE 198.51.100.0/24", "nmap -sP 192.0.2.0/24",
                                  "nmap -n -sn 192.0.2.1-50 -oG -"])
def test_a_ping_sweep_is_remote_system_discovery(library, text):
    assert tagged(library, text) == ("host-discovery-scan", ["T1018"])


@pytest.mark.parametrize("text", ["nmap -sV 192.0.2.0/24", "nmap -sS -p 22,80 203.0.113.0/24", "nmap -snapshot x",
                                  "nmap -p- 192.0.2.5 # not -sn", "nmap 192.0.2.5; echo -sn"])
def test_a_port_scan_stays_network_service_discovery(library, text):
    assert tagged(library, text) == ("network-scan", ["T1046"])


@pytest.mark.parametrize("text", [HY + " -C creds.txt ssh://192.0.2.5", HY + " -t 4 -C /tmp/combo.txt 192.0.2.5 ftp",
                                  ME + " -h 192.0.2.5 -C combo.txt -M ssh"])
def test_login_password_pairs_are_credential_stuffing(library, text):
    assert tagged(library, text) == ("credential-stuffing", ["T1110.004"])


@pytest.mark.parametrize("text", [HY + " -l root -P pass.txt ssh://192.0.2.5", HY + " -L users.txt -p x 192.0.2.5 ssh",
                                  HY + " -l root -P pass.txt 192.0.2.5 ssh; echo -C"])
def test_password_guessing_stays_password_guessing(library, text):
    assert tagged(library, text) == ("brute-force", ["T1110.001"])


ADDRESSES = ("nmap 127.0.0.1 127.8.9.10 169.254.169.254 169.254.0.1 192.0.2.5 ::1 fe80::1 febf::2 fec0::1 "
             "2001:db8::1 0127.0.0.1")


def test_loopback_and_link_local_addresses_are_not_indicators():
    found = [i.value for i in indicators(normalize_text(ADDRESSES), ["ipv4", "ipv6"])]
    assert found == ["192.0.2[.]5", "0127.0.0[.]1", "fec0[:][:]1", "2001[:]db8[:][:]1"]


def test_extract_still_finds_every_address():
    # extract() is the raw scan; only the IOCs a gloss reports leave them out.
    assert len(extract(normalize_text(ADDRESSES), ["ipv4", "ipv6"])) == 11


def test_a_rule_gloss_reports_no_loopback_address(library):
    _, techniques = tagged(library, "nmap -sV 127.0.0.1 192.0.2.7")
    text = normalize_text("nmap -sV 127.0.0.1 192.0.2.7")
    gloss = gloss_for(library, library.match(text), text, AT)
    assert [(i.type, i.value) for i in gloss.iocs if i.type == "ipv4"] == [("ipv4", "192.0.2[.]7")]
