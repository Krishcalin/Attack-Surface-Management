"""Smoke tests: the whole module graph imports cleanly with only the required
deps (requests, dnspython), and the orchestrator exposes a stable version.

Importing easm_scanner pulls in every pipeline module, so this catches syntax
errors and bad imports across the codebase in one shot. No network."""
import importlib

import easm_scanner


def test_orchestrator_version():
    assert easm_scanner.__version__ == "4.0.0"


def test_all_pipeline_modules_import():
    mods = [
        "models.asset", "models.finding",
        "modules.asset_store", "modules.seed_manager",
        "modules.subdomain_discovery", "modules.dns_resolver",
        "modules.port_scanner", "modules.http_prober", "modules.asn_mapper",
        "modules.ct_monitor", "modules.whois_enrichment",
        "modules.tech_fingerprint", "modules.tls_analyzer",
        "modules.geoip_enrichment", "modules.screenshot_capture",
        "modules.attribution_engine", "modules.asset_graph",
        "modules.vuln_detector", "modules.nuclei_scanner",
        "modules.subdomain_takeover", "modules.misconfig_detector",
        "modules.default_creds", "modules.dns_security", "modules.cloud_enum",
        "modules.risk_scorer", "modules.alerting", "modules.siem_export",
        "modules.jira_integration", "modules.scheduler",
        "modules.intel_discovery", "modules.threat_intel", "modules.trends",
    ]
    for m in mods:
        assert importlib.import_module(m) is not None


def test_severity_order_constant():
    from models.finding import SEVERITY_ORDER
    assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["INFO"]


def test_orchestrator_wires_intel_discovery(tmp_path):
    # EASMScanner exposes the intel engine and the summary carries the
    # intelligence block (network-free: just construction + summary).
    s = easm_scanner.EASMScanner(db_path=":memory:",
                                 screenshot_dir=str(tmp_path / "shots"))
    from modules.intel_discovery import IntelDiscovery
    assert isinstance(s.intel, IntelDiscovery)
    assert s.discovered_assets == []
    from modules.threat_intel import ThreatIntel
    assert isinstance(s.ti, ThreatIntel) and s.ti_matches == []
    summ = s.summary()
    assert summ["intelligence"]["related_assets_discovered"] == 0
    assert summ["threat_intel"]["matches"] == 0
