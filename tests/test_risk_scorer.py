"""Tests for the multi-factor RiskScorer. No network."""
from modules.risk_scorer import RiskScorer


def test_score_to_level_bands():
    rs = RiskScorer()
    assert rs._score_to_level(85) == "CRITICAL"
    assert rs._score_to_level(65) == "HIGH"
    assert rs._score_to_level(45) == "MEDIUM"
    assert rs._score_to_level(25) == "LOW"
    assert rs._score_to_level(5) == "INFO"


def test_bare_critical_finding_components():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="X", severity="CRITICAL", asset_value="a", asset_type="")
    # severity 40 + criticality 17.5 + exploit 0 + temporal 5 = 62.5 -> HIGH
    assert r.severity_component == 40.0
    assert round(r.risk_score, 1) == 62.5
    assert r.risk_level == "HIGH"
    assert not r.auto_escalated


def test_components_sum_to_score_when_not_escalated():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="X", severity="MEDIUM", asset_value="a",
                         asset_type="ip", service="http")
    total = (r.severity_component + r.criticality_component
             + r.exploitability_component + r.temporal_component)
    assert round(total, 1) == round(r.risk_score, 1)


def test_escalation_default_credentials():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="EASM-CRED-001", severity="CRITICAL",
                         asset_value="1.2.3.4", asset_type="port",
                         category="Default Credential")
    assert r.auto_escalated and r.risk_score >= 95 and r.risk_level == "CRITICAL"
    assert "Default credentials" in r.escalation_reason


def test_escalation_subdomain_takeover():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="EASM-TAKEOVER-001", severity="HIGH",
                         asset_value="sub.example.com", asset_type="domain",
                         category="Subdomain Takeover")
    assert r.auto_escalated and r.risk_score >= 85


def test_escalation_cisa_kev():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="EASM-CVE-001", severity="HIGH",
                         asset_value="1.2.3.4", asset_type="ip",
                         category="CVE", cve="CVE-2024-1234", is_kev=True)
    assert r.auto_escalated and r.risk_score >= 90
    assert "KEV" in r.escalation_reason


def test_escalation_public_cloud_bucket():
    rs = RiskScorer()
    r = rs.score_finding(rule_id="EASM-CLOUD-001", severity="CRITICAL",
                         asset_value="bucket", asset_type="cloud_bucket",
                         category="Cloud Storage")
    assert r.auto_escalated and r.risk_score >= 90


def test_kev_raises_exploitability_and_temporal():
    rs = RiskScorer()
    plain = rs.score_finding("X", "HIGH", "a", asset_type="ip", category="CVE",
                             cve="CVE-1")
    kev = rs.score_finding("X", "HIGH", "a", asset_type="ip", category="CVE",
                           cve="CVE-1", is_kev=True)
    assert kev.exploitability_component > plain.exploitability_component
    assert kev.temporal_component >= plain.temporal_component


def test_score_findings_sorted_desc_and_stats():
    rs = RiskScorer()
    findings = [
        {"rule_id": "low", "severity": "LOW", "asset_value": "a", "asset_type": "domain"},
        {"rule_id": "crit", "severity": "CRITICAL", "asset_value": "b",
         "asset_type": "port", "category": "Default Credential"},
        {"rule_id": "med", "severity": "MEDIUM", "asset_value": "c", "asset_type": "ip"},
    ]
    scored = rs.score_findings(findings)
    assert [s.finding_rule_id for s in scored][0] == "crit"   # highest first
    assert all(scored[i].risk_score >= scored[i + 1].risk_score
               for i in range(len(scored) - 1))
    stats = RiskScorer.aggregate_stats(scored)
    assert stats["count"] == 3
    assert stats["auto_escalated"] >= 1
    assert stats["max_score"] >= stats["min_score"]


def test_aggregate_stats_empty():
    assert RiskScorer.aggregate_stats([])["count"] == 0
