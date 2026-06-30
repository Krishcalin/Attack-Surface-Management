"""Tests for STIX 2.1 export. No network. Deterministic via a fixed timestamp."""
import json
from datetime import datetime, timezone

from models.asset import Asset
from models.finding import Finding
from modules.stix_export import (
    StixExporter,
    asset_sco,
    vulnerability_sdo,
    attack_pattern_sdo,
    indicator_for_ti,
    finding_sdo,
    _host,
    _is_ip,
)

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
CBY = "identity--00000000-0000-0000-0000-000000000000"


def _f(rule_id, asset, asset_type="ip", severity="HIGH", cve="", evidence="",
       mitre=None):
    f = Finding(rule_id, rule_id, "cat", severity, asset, asset_type,
                cve=cve, evidence=evidence)
    if mitre:
        f.attributes = {"mitre": mitre}
    return f


# ── helpers / SCOs ──────────────────────────────────────────────────

def test_helpers():
    assert _is_ip("1.2.3.4") and not _is_ip("x.com")
    assert _host("https://a.com/p") == "a.com"
    assert _host("1.2.3.4:443") == "1.2.3.4"


def test_asset_sco_types():
    assert asset_sco("a.com", "domain")["type"] == "domain-name"
    assert asset_sco("1.2.3.4", "ip")["type"] == "ipv4-addr"
    assert asset_sco("2606:4700::1", "ip")["type"] == "ipv6-addr"
    assert asset_sco("https://a.com/p", "url")["type"] == "url"
    assert asset_sco("10.0.0.0/24", "cidr") is None
    sco = asset_sco("a.com", "domain")
    assert sco["spec_version"] == "2.1" and "created" not in sco   # SCOs have no created


def test_object_builders():
    v = vulnerability_sdo("CVE-2024-1", NOW, CBY)
    assert v["type"] == "vulnerability" and v["name"] == "CVE-2024-1"
    assert v["external_references"][0]["external_id"] == "CVE-2024-1"

    ap = attack_pattern_sdo({"id": "T1190", "name": "Exploit", "tactic": "ia",
                             "url": "https://attack.mitre.org/techniques/T1190/"},
                            NOW, CBY)
    assert ap["type"] == "attack-pattern"
    assert ap["external_references"][0]["source_name"] == "mitre-attack"

    ind = indicator_for_ti(_f("EASM-TI-001", "1.2.3.4", "ip"), NOW, CBY)
    assert ind["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert ind["pattern_type"] == "stix"
    ind_d = indicator_for_ti(_f("EASM-TI-002", "bad.com", "domain"), NOW, CBY)
    assert ind_d["pattern"] == "[domain-name:value = 'bad.com']"

    fs = finding_sdo(_f("EASM-MISCONFIG-001", "https://a.com/.env", "url",
                        mitre=[{"id": "T1190"}]), NOW, CBY)
    assert fs["type"] == "x-easm-finding"
    assert fs["x_rule_id"] == "EASM-MISCONFIG-001"
    assert fs["x_mitre_techniques"] == ["T1190"]


# ── bundle ──────────────────────────────────────────────────────────

def _bundle():
    assets = [Asset(asset_type="domain", value="app.example.com"),
              Asset(asset_type="ip", value="203.0.113.20")]
    mitre = [{"id": "T1190", "name": "Exploit Public-Facing Application",
              "tactic": "initial_access",
              "url": "https://attack.mitre.org/techniques/T1190/"}]
    findings = [
        _f("EASM-TI-001", "203.0.113.20", "ip", "CRITICAL", evidence="feodo"),
        _f("EASM-CVE-001", "app.example.com", "domain", cve="CVE-2024-1", mitre=mitre),
        _f("EASM-MISCONFIG-001", "https://app.example.com/.env", "url"),
        _f("EASM-CVE-001", "other.example.com", "domain", cve="CVE-2024-1"),  # dup CVE
    ]
    return StixExporter().build_bundle(assets, findings, now=NOW)


def test_bundle_structure_and_types():
    b = _bundle()
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    types = [o["type"] for o in b["objects"]]
    for t in ("identity", "domain-name", "ipv4-addr", "url", "indicator",
              "x-easm-finding", "vulnerability", "attack-pattern", "relationship"):
        assert t in types, f"missing {t}"
    # SDOs carry spec_version 2.1
    assert all(o.get("spec_version") == "2.1" for o in b["objects"])


def test_bundle_dedupes_vuln_and_attack_pattern():
    b = _bundle()
    types = [o["type"] for o in b["objects"]]
    assert types.count("vulnerability") == 1        # CVE-2024-1 once
    assert types.count("attack-pattern") == 1       # T1190 once


def test_bundle_referential_integrity():
    b = _bundle()
    ids = {o["id"] for o in b["objects"]}
    for o in b["objects"]:
        if o["type"] == "relationship":
            assert o["source_ref"] in ids
            assert o["target_ref"] in ids
        if "created_by_ref" in o:
            assert o["created_by_ref"] in ids


def test_bundle_is_deterministic():
    assert _bundle() == _bundle()                   # same input + now -> identical


def test_save_roundtrip(tmp_path):
    out = tmp_path / "bundle.json"
    StixExporter().save(_bundle(), str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in data["objects"])
