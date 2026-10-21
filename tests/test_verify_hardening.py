"""Regression tests for the hardened technique verification: only canonical technique IDs are verified, revoked
means revoked, a bad database is a clean error, and parse never loads pydantic."""

import subprocess
import sys
import types

import pytest

from conftest import KNOWN, FakeResolver

# References that are not ATT&CK or ATLAS technique IDs. Countermap resolves each of them to some node (a group, a
# tactic, a namespaced node, a technique found by name), so each was once reported as a verified technique.
NOT_TECHNIQUE_IDS = ["G0007", "S0002", "TA0002", "M1036", "DS0017", "C0010", "DET0001", "AN0001", "DC0001",
                     "AML.TA0002", "AML.M0000", "AML.CS0000", "d3fend:D3-AL", "atlas:AML.T0051", "PowerShell",
                     "Local Account"]
MALFORMED = ["attack:T1105", "ATTACK:T1105", "T1059,001", "T 1105", "T1105.1", "T11050", "T1105.0001", "AML T0051",
             "", "   ", "x" * 300]


# A stand-in for Countermap's query layer, with its real semantics: an ID-shaped reference resolves to the node with
# that ID whatever its kind, a name resolves through the name index, and lookup() follows revocations.
class _NotFound(LookupError):
    pass


NODES = {
    "attack:T1105": ("technique", "Ingress Tool Transfer", False, False),
    "attack:T1562.003": ("technique", "Impair Command History Logging", True, False),
    "attack:T1690": ("technique", "Prevent Command History Logging", False, False),
    "attack:T1454": ("technique", "Malicious SMS Message", True, False),
    "attack:T1053.004": ("technique", "Launchd", False, True),
    "attack:T1998": ("software", "Odd Software", False, False),
    "attack:G0007": ("group", "APT28", False, False),
    "attack:TA0002": ("tactic", "Execution", False, False),
    "attack:T1059.001": ("technique", "PowerShell", False, False),
    "atlas:AML.T0051": ("technique", "LLM Prompt Injection", False, False),
    "atlas:AML.TA0002": ("tactic", "Reconnaissance", False, False),
    "f3:T1999": ("technique", "An F3 technique", False, False),
}
REVOKED_BY = {"attack:T1562.003": "attack:T1690"}
CALLS: list[str] = []


class StubCountermap:
    def __init__(self, db_path):
        self.path = db_path

    def source_versions(self):
        return {"attack-enterprise": "20.0", "atlas": "2026.09"}

    def parse_ref(self, ref, framework=None, kind=None):
        CALLS.append(ref)
        ref = ref.strip()
        if ":" in ref and ref.split(":", 1)[0] in ("attack", "atlas", "f3", "d3fend"):
            if ref in NODES:
                return ref
            raise _NotFound(ref)
        upper = ref.upper()
        if upper == "T1999":  # a reference answered with a node outside ATT&CK and ATLAS
            return "f3:T1999"
        candidate = f"{framework or ('atlas' if upper.startswith('AML.') else 'attack')}:{upper}"
        if candidate in NODES:
            return candidate
        for node_id, (node_kind, name, _revoked, _deprecated) in NODES.items():
            if name.lower() == ref.lower() and kind in (None, node_kind):
                return node_id
        raise _NotFound(ref)

    def resolve(self, node_id):
        current = REVOKED_BY.get(node_id, node_id)
        return {"id": current, "chain": list(dict.fromkeys([node_id, current])), "changed": current != node_id}

    def lookup(self, ref, framework=None, desc_chars=1200):
        node_id = self.resolve(ref)["id"]
        kind, name, revoked, deprecated = NODES[node_id]
        out = {"id": node_id, "kind": kind, "name": name}
        if revoked:
            out["revoked"] = True
        if deprecated:
            out["deprecated"] = True
        return out


@pytest.fixture
def stub(monkeypatch):
    query = types.ModuleType("countermap.query")
    query.Countermap, query.NotFound = StubCountermap, _NotFound
    sources = types.ModuleType("countermap.sources")
    sources.default_db_path = lambda: "stub.db"
    package = types.ModuleType("countermap")
    package.query, package.sources = query, sources
    for name, module in (("countermap", package), ("countermap.query", query), ("countermap.sources", sources)):
        monkeypatch.setitem(sys.modules, name, module)
    from interlinear_cti.verify import CountermapResolver

    CALLS.clear()
    return CountermapResolver()


def fields(t):
    return (t.status, t.id, t.framework, t.name, t.replaced_by)


# C1: only canonical technique IDs are verified


@pytest.mark.parametrize("ref", NOT_TECHNIQUE_IDS + MALFORMED)
def test_only_canonical_technique_ids_reach_countermap(stub, ref):
    t = stub.check(ref)
    assert t.status == "unknown"
    assert t.id == ref.strip().upper()
    assert t.name is None and t.replaced_by == []
    assert CALLS == []


@pytest.mark.parametrize("ref", ["T1105", "t1105", " T1105 ", "T1105\n", "\tt1105\r\n"])
def test_case_and_surrounding_whitespace_do_not_matter(stub, ref):
    assert fields(stub.check(ref)) == ("active", "T1105", "attack", "Ingress Tool Transfer", [])


def test_framework_comes_from_the_node_not_the_input(stub):
    assert fields(stub.check("aml.t0051")) == ("active", "AML.T0051", "atlas", "LLM Prompt Injection", [])
    assert fields(stub.check("T1999")) == ("unknown", "T1999", "attack", None, [])


def test_an_id_shaped_node_that_is_not_a_technique_is_unknown(stub):
    assert fields(stub.check("T1998")) == ("unknown", "T1998", "attack", None, [])


NOT_STRINGS = [None, 1105, 1105.0, b"T1105", ["T1105"], {"id": "T1105"}]


@pytest.mark.parametrize("ref", NOT_STRINGS, ids=repr)
def test_a_non_string_id_is_unknown(stub, ref):
    assert fields(stub.check(ref)) == ("unknown", "", "attack", None, [])
    assert fields(FakeResolver().check(ref)) == ("unknown", "", "attack", None, [])
    assert CALLS == []


# I2: revoked means revoked


def test_revoked_without_a_replacement_is_revoked(stub):
    assert fields(stub.check("T1454")) == ("revoked", "T1454", "attack", None, [])


def test_revoked_with_a_replacement_names_it(stub):
    assert fields(stub.check("T1562.003")) == ("revoked", "T1562.003", "attack", None, ["T1690"])
    assert fields(stub.check("T1053.004")) == ("deprecated", "T1053.004", "attack", "Launchd", [])


# M7: the fake resolver applies the same gate


def test_fake_resolver_strips_upper_cases_and_gates():
    fake = FakeResolver()
    assert fields(fake.check(" t1105\n")) == ("active", "T1105", "attack", "Ingress Tool Transfer", [])
    for ref in NOT_TECHNIQUE_IDS + MALFORMED:
        assert fake.check(ref).status == "unknown", ref
        assert fake.check(ref).id == ref.strip().upper()


# I3: a bad database is ResolverUnavailable, not a traceback


def _bad_database(tmp_path, case):
    if case == "directory":
        path = tmp_path / "folder.db"
        path.mkdir()
    else:
        path = tmp_path / f"{case}.db"
        path.write_bytes(b"" if case == "empty" else b"not a database" * 100)
    return str(path)


@pytest.mark.parametrize("case", ["empty", "garbage", "directory"])
def test_bad_database_is_resolver_unavailable(tmp_path, case):
    pytest.importorskip("countermap")
    from interlinear_cti.verify import CountermapResolver, ResolverUnavailable

    path = _bad_database(tmp_path, case)
    with pytest.raises(ResolverUnavailable) as info:
        CountermapResolver(path)
    assert path in str(info.value)


@pytest.mark.parametrize("case", ["empty", "garbage", "directory"])
def test_bad_database_exits_2_through_the_cli(tmp_path, monkeypatch, capsys, case):
    # No subcommand opens the resolver yet, so a stand-in for one does, and main must turn the error into exit 2.
    pytest.importorskip("countermap")
    from interlinear_cti import cli
    from interlinear_cti.verify import CountermapResolver

    path = _bad_database(tmp_path, case)

    def open_resolver(args):
        CountermapResolver(path)
        return 0

    monkeypatch.setattr(cli, "cmd_parse", open_resolver)
    assert cli.main(["parse", "unused", "-o", str(tmp_path / "t.json")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and path in err
    assert "Traceback" not in err


# M6: parse must not load pydantic


def test_errors_module_is_standard_library_only():
    code = ("import sys\n"
            "before = set(sys.modules)\n"
            "import interlinear_cti.errors\n"
            "new = {name.split('.')[0] for name in set(sys.modules) - before}\n"
            "print(sorted(new - set(sys.stdlib_module_names) - {'interlinear_cti'}))\n")
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_verify_still_exports_resolver_unavailable():
    from interlinear_cti import errors, verify

    assert verify.ResolverUnavailable is errors.ResolverUnavailable


def test_interlinear_parse_does_not_load_pydantic(tmp_path):
    history = tmp_path / ".bash_history"
    history.write_bytes(b"id\n")
    out = tmp_path / "t.json"
    code = ("import sys\n"
            "from interlinear_cti.cli import main\n"
            "status = main(sys.argv[1:])\n"
            "print(status, sorted(name for name in sys.modules if name.split('.')[0] == 'pydantic'))\n")
    result = subprocess.run([sys.executable, "-c", code, "parse", str(history), "-o", str(out)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "0 []"  # after parse's own "Wrote ..." line
    assert out.exists()


# Against the real Countermap database


def _real_resolver():
    pytest.importorskip("countermap")
    from countermap.sources import default_db_path

    if not default_db_path().exists():
        pytest.skip("no Countermap database; run `countermap build`")
    from interlinear_cti.verify import CountermapResolver

    return CountermapResolver()


@pytest.mark.countermap
def test_real_database_verifies_only_technique_ids():
    real = _real_resolver()
    for ref in NOT_TECHNIQUE_IDS + MALFORMED:
        assert real.check(ref).status == "unknown", ref


@pytest.mark.countermap
def test_real_database_revoked_without_a_replacement():
    assert fields(_real_resolver().check("T1454")) == ("revoked", "T1454", "attack", None, [])


@pytest.mark.countermap
def test_fake_and_real_resolvers_agree():
    real, fake = _real_resolver(), FakeResolver()
    variants = [form(ref) for ref in KNOWN for form in (str.lower, lambda s: f" {s} ", lambda s: s + "\n",
                                                         lambda s: "\t" + s.lower())]
    for ref in [*KNOWN, *NOT_TECHNIQUE_IDS, *MALFORMED, "T9999", *variants, *NOT_STRINGS]:
        assert fields(real.check(ref)) == fields(fake.check(ref)), repr(ref)
