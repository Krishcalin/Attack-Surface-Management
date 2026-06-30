"""Tests for detection pairing (MITRE ATT&CK + Sigma generation). No network."""
from models.finding import Finding
from modules.detection_pairing import (
    DetectionPairer,
    pair_finding,
    to_sigma_yaml,
    _family,
    _host_of,
    _path_of,
)


def _f(rule_id, asset, asset_type="ip", severity="HIGH", evidence=""):
    return Finding(rule_id, rule_id, "cat", severity, asset, asset_type,
                   evidence=evidence)


# ── helpers ─────────────────────────────────────────────────────────

def test_helpers():
    assert _family("EASM-PORT-002") == "EASM-PORT"
    assert _host_of("https://app.example.com/.env") == "app.example.com"
    assert _host_of("203.0.113.10:3389") == "203.0.113.10"
    assert _path_of("https://app.example.com/.git/config") == "/.git/config"
    assert _path_of("203.0.113.10") == ""


# ── per-family pairing ──────────────────────────────────────────────

def test_port_pairing_rdp():
    p = pair_finding(_f("EASM-PORT-002", "203.0.113.10"))
    ids = {m["id"] for m in p.mitre}
    assert "T1133" in ids and "T1021.001" in ids
    assert p.sigma is not None
    sel = p.sigma["detection"]["selection"]
    assert sel["DestinationPort"] == 3389
    assert sel["DestinationIp"] == "203.0.113.10"


def test_threat_intel_pairing_and_tor():
    p = pair_finding(_f("EASM-TI-001", "203.0.113.20", evidence="source=feodo"))
    assert {m["id"] for m in p.mitre} == {"T1071.001"}
    assert p.sigma["detection"]["selection"]["DestinationIp"] == "203.0.113.20"
    tor = pair_finding(_f("EASM-TI-006", "203.0.113.50"))
    assert {m["id"] for m in tor.mitre} == {"T1090.003"}


def test_misconfig_pairing_path():
    p = pair_finding(_f("EASM-MISCONFIG-001", "https://app.example.com/.env",
                        asset_type="url"))
    assert {m["id"] for m in p.mitre} == {"T1190", "T1083"}
    sel = p.sigma["detection"]["selection"]
    assert sel["cs-uri-stem|contains"] == "/.env"
    assert sel["cs-host"] == "app.example.com"


def test_cred_cloud_dns_takeover():
    cred = pair_finding(_f("EASM-CRED-001", "203.0.113.10", severity="CRITICAL"))
    assert {m["id"] for m in cred.mitre} == {"T1078", "T1110"}
    assert cred.sigma["detection"]["selection"]["EventID"] == 4624

    cloud = pair_finding(_f("EASM-CLOUD-001", "mybucket", asset_type="url"))
    assert cloud.mitre[0]["id"] == "T1530"
    assert cloud.sigma["detection"]["selection"]["eventName"] == "GetObject"

    dns = pair_finding(_f("EASM-DNS-006", "example.com", asset_type="domain"))
    assert dns.mitre[0]["id"] == "T1590.002"
    assert dns.sigma["detection"]["selection"]["query_type"] == "AXFR"

    to = pair_finding(_f("EASM-TAKEOVER-001", "old.example.com", asset_type="domain"))
    assert to.mitre[0]["id"] == "T1584.001"


def test_guidance_only_families_have_no_sigma():
    for rid in ("EASM-CVE-001", "EASM-NUCLEI-x", "EASM-TLS-003",
                "EASM-HTTP-001", "EASM-INTEL-001"):
        p = pair_finding(_f(rid, "x.com", asset_type="domain"))
        assert p is not None and p.mitre and p.sigma is None


def test_unknown_family_returns_none():
    assert pair_finding(_f("EASM-WHOIS-001", "x.com", asset_type="domain")) is None


def test_sigma_id_is_deterministic():
    a = pair_finding(_f("EASM-PORT-002", "203.0.113.10"))
    b = pair_finding(_f("EASM-PORT-002", "203.0.113.10"))
    assert a.sigma["id"] == b.sigma["id"]
    c = pair_finding(_f("EASM-PORT-002", "203.0.113.11"))
    assert c.sigma["id"] != a.sigma["id"]


# ── Sigma YAML ──────────────────────────────────────────────────────

def test_sigma_yaml_structure():
    p = pair_finding(_f("EASM-TI-001", "203.0.113.20"))
    y = to_sigma_yaml(p.sigma)
    assert y.startswith("title: ")
    assert "detection:" in y and "condition: 'selection'" in y
    assert "logsource:" in y
    assert "attack.t1071.001" in y
    assert y.endswith("\n")


def test_sigma_yaml_empty_list():
    y = to_sigma_yaml({"references": [], "title": "x"})
    assert "references: []" in y


# ── engine ──────────────────────────────────────────────────────────

def test_pair_all_and_coverage():
    findings = [
        _f("EASM-PORT-002", "203.0.113.10"),
        _f("EASM-TI-001", "203.0.113.20"),
        _f("EASM-CVE-001", "x.com", asset_type="domain"),   # guidance-only
        _f("EASM-WHOIS-001", "x.com", asset_type="domain"), # unmapped -> skipped
    ]
    pairer = DetectionPairer()
    pairings = pairer.pair_all(findings)
    assert len(pairings) == 3                       # WHOIS not paired
    cov = pairer.mitre_coverage(pairings)
    assert cov["paired_findings"] == 3
    assert cov["sigma_rules"] == 2                  # PORT + TI (CVE is guidance)
    assert "T1133" in cov["techniques"] and "T1190" in cov["techniques"]
    assert "initial_access" in cov["tactics"]


def test_annotate_sets_finding_attributes():
    f = _f("EASM-PORT-002", "203.0.113.10")
    DetectionPairer().annotate([f])
    assert f.attributes["mitre"][0]["id"] in ("T1133", "T1021.001")
    det = f.attributes["detection"]
    assert det["has_sigma"] is True and det["log_source"]


def test_write_sigma(tmp_path):
    findings = [_f("EASM-PORT-002", "203.0.113.10"),
                _f("EASM-CVE-001", "x.com", asset_type="domain")]
    pairer = DetectionPairer()
    pairings = pairer.pair_all(findings)
    n = pairer.write_sigma(pairings, str(tmp_path))
    assert n == 1                                   # only PORT has a Sigma rule
    files = list(tmp_path.glob("*.yml"))
    assert len(files) == 1
    assert "title:" in files[0].read_text(encoding="utf-8")
