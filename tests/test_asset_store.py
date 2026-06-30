"""Tests for the SQLite-backed AssetStore (in-memory). No network."""
from models.asset import Asset
from models.finding import Finding
from modules.asset_store import AssetStore


def _store():
    return AssetStore(":memory:")


def test_upsert_new_then_merge():
    s = _store()
    a = Asset(asset_type="domain", value="example.com", sources=["crt.sh"],
              attributes={"a": 1}, confidence=0.4)
    s.upsert_asset(a)

    # second sighting from another source merges, keeps earliest first_seen,
    # raises confidence, merges attributes
    b = Asset(asset_type="domain", value="example.com", sources=["subfinder"],
              attributes={"b": 2}, confidence=0.9, org_attribution="ACME")
    merged = s.upsert_asset(b)

    assert s.count_assets() == 1
    assert set(merged.sources) == {"crt.sh", "subfinder"}
    assert merged.attributes == {"a": 1, "b": 2}
    assert merged.confidence == 0.9
    assert merged.org_attribution == "ACME"
    assert merged.first_seen == a.first_seen


def test_get_assets_filters_and_helpers():
    s = _store()
    s.upsert_asset(Asset(asset_type="domain", value="example.com"))
    s.upsert_asset(Asset(asset_type="ip", value="203.0.113.5", parent="example.com"))
    s.upsert_asset(Asset(asset_type="ip", value="203.0.113.6", parent="example.com"))

    assert s.count_assets() == 3
    assert s.count_assets("ip") == 2
    assert s.all_domains() == ["example.com"]
    assert s.all_ips() == ["203.0.113.5", "203.0.113.6"]
    ips = s.get_assets(asset_type="ip", parent="example.com")
    assert len(ips) == 2


def test_get_asset_single():
    s = _store()
    s.upsert_asset(Asset(asset_type="domain", value="x.com"))
    got = s.get_asset("domain", "x.com")
    assert got is not None and got.value == "x.com"
    assert s.get_asset("domain", "nope.com") is None


def test_findings_add_query_count():
    s = _store()
    s.add_finding(Finding("EASM-PORT-001", "DB exposed", "Exposed Service",
                          "CRITICAL", "1.2.3.4", "port", evidence="3306 open"))
    s.add_finding(Finding("EASM-HTTP-001", "Missing HSTS", "Security Header",
                          "MEDIUM", "https://x.com", "url"))
    assert s.count_findings() == 2
    assert s.count_findings("CRITICAL") == 1
    crit = s.get_findings(severity="CRITICAL")
    assert len(crit) == 1 and crit[0].rule_id == "EASM-PORT-001"
    assert crit[0].attributes == {}            # json round-trips to empty dict
    assert len(s.get_findings(category="Security Header")) == 1


def test_context_manager_closes():
    with AssetStore(":memory:") as s:
        s.upsert_asset(Asset(asset_type="domain", value="x.com"))
        assert s.count_assets() == 1
