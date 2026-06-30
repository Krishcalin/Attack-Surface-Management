"""Tests for the Asset and Finding data models. No network."""
from models.asset import Asset, AssetType
from models.finding import Finding, SEVERITY_ORDER


# ---- Asset ----

def test_asset_auto_id_and_timestamps():
    a = Asset(asset_type=AssetType.DOMAIN.value, value="api.example.com")
    assert len(a.id) == 12
    assert a.first_seen and a.last_seen
    assert a.first_seen == a.last_seen


def test_asset_add_source_dedupes():
    a = Asset(asset_type="domain", value="x.com")
    a.add_source("crt.sh")
    a.add_source("crt.sh")
    a.add_source("subfinder")
    assert a.sources == ["crt.sh", "subfinder"]


def test_asset_attrs_roundtrip():
    a = Asset(asset_type="ip", value="203.0.113.5")
    a.set_attr("asn", "AS64500")
    assert a.get_attr("asn") == "AS64500"
    assert a.get_attr("missing", "def") == "def"
    d = a.to_dict()
    b = Asset.from_dict(d)
    assert b == a
    assert b.attributes["asn"] == "AS64500"


def test_asset_equality_and_hash_keyed_on_type_value_parent():
    a = Asset(asset_type="ip", value="1.1.1.1", parent="example.com")
    b = Asset(asset_type="ip", value="1.1.1.1", parent="example.com")
    c = Asset(asset_type="ip", value="1.1.1.1", parent="other.com")
    assert a == b
    assert a != c
    assert len({a, b, c}) == 2          # a and b collapse


def test_from_dict_ignores_unknown_keys():
    a = Asset.from_dict({"asset_type": "domain", "value": "z.com", "bogus": 1})
    assert a.value == "z.com"


# ---- Finding ----

def test_finding_severity_uppercased_and_ranked():
    f = Finding(rule_id="EASM-PORT-001", name="DB exposed", category="Exposed Service",
                severity="critical", asset_value="1.2.3.4", asset_type="port")
    assert f.severity == "CRITICAL"
    assert f.severity_rank == SEVERITY_ORDER["CRITICAL"] == 0


def test_finding_rank_orders_correctly():
    sevs = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    findings = [Finding("r", "n", "c", s, "a", "domain") for s in sevs]
    ranks = [f.severity_rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)   # INFO=4 ... CRITICAL=0


def test_finding_roundtrip():
    f = Finding(rule_id="EASM-TLS-003", name="Expired cert", category="TLS/SSL",
                severity="CRITICAL", asset_value="example.com", asset_type="certificate",
                cwe="CWE-298", evidence="notAfter=2020-01-01")
    g = Finding.from_dict(f.to_dict())
    assert g.to_dict() == f.to_dict()
