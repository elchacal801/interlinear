import sys

import pytest


def test_missing_countermap_gives_an_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "countermap", None)
    monkeypatch.setitem(sys.modules, "countermap.query", None)
    from interlinear_cti.verify import CountermapResolver, ResolverUnavailable

    with pytest.raises(ResolverUnavailable, match=r"interlinear-cti\[countermap\]"):
        CountermapResolver()


@pytest.mark.countermap
def test_countermap_statuses():
    pytest.importorskip("countermap")
    from countermap.sources import default_db_path

    if not default_db_path().exists():
        pytest.skip("no Countermap database; run `countermap build`")
    from interlinear_cti.verify import CountermapResolver

    real = CountermapResolver()
    assert real.check("T1105").status == "active"
    assert real.check("T1105").name == "Ingress Tool Transfer"
    revoked = real.check("T1562.003")
    assert revoked.status == "revoked" and revoked.replaced_by == ["T1690"]
    assert real.check("T1053.004").status == "deprecated"
    assert real.check("T9999").status == "unknown"
    assert real.check("aml.t0051").framework == "atlas"
    assert "attack-enterprise" in real.versions()
