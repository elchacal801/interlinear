"""The Countermap resolver closes its SQLite connection when done, so nothing is left for the garbage collector.

Python 3.13 and later emit a ResourceWarning for a connection collected while still open; earlier versions say
nothing, so on them these tests pass trivially and the control test is skipped.
"""

import gc
import sys
import warnings

import pytest

NEEDS_WARNING = pytest.mark.skipif(sys.version_info < (3, 13), reason="sqlite3 warns about unclosed connections from 3.13")


def resource_warnings(action):
    # Garbage left by earlier tests (a connection some other code path never closed) is collected first, outside the
    # recording, and the collector is paused, so only what action leaves behind is counted.
    gc.collect()
    gc.disable()
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            action()
            gc.collect()
    finally:
        gc.enable()
    return [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]


def real_database():
    pytest.importorskip("countermap")
    from countermap.sources import default_db_path

    if not default_db_path().exists():
        pytest.skip("no Countermap database; run `countermap build`")


@pytest.mark.parametrize("case", ["empty", "garbage"])
def test_a_bad_database_leaves_no_connection_open(tmp_path, case):
    pytest.importorskip("countermap")
    from interlinear_cti.verify import CountermapResolver, ResolverUnavailable

    path = tmp_path / f"{case}.db"
    path.write_bytes(b"" if case == "empty" else b"not a database" * 100)

    def open_it():
        try:
            CountermapResolver(str(path))
        except ResolverUnavailable:
            pass
        else:
            raise AssertionError("a bad database opened")

    assert resource_warnings(open_it) == []


@pytest.mark.countermap
def test_closing_the_resolver_leaves_no_connection_open():
    real_database()
    from interlinear_cti.verify import CountermapResolver

    def use_it():
        with CountermapResolver() as resolver:
            assert resolver.check("T1105").status == "active"
            assert "attack-enterprise" in resolver.versions()
        resolver.close()  # closing twice is harmless
        assert resolver.check("T1105").status == "active"  # from the cache
        with pytest.raises(ResolverUnavailable, match="closed"):
            resolver.check("T1059")

    from interlinear_cti.verify import ResolverUnavailable

    assert resource_warnings(use_it) == []


@pytest.mark.countermap
@NEEDS_WARNING
def test_an_unclosed_resolver_is_what_these_tests_catch():
    real_database()
    from interlinear_cti.verify import CountermapResolver

    def leak_it():
        CountermapResolver().check("T1105")

    assert resource_warnings(leak_it)


@pytest.mark.countermap
@NEEDS_WARNING
def test_rules_verify_leaves_no_connection_open(capsys):
    real_database()
    from interlinear_cti import cli

    def run_it():
        assert cli.main(["rules", "list", "--verify"]) == 0

    assert resource_warnings(run_it) == []
