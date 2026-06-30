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
    ]
    for m in mods:
        assert importlib.import_module(m) is not None


def test_severity_order_constant():
    from models.finding import SEVERITY_ORDER
    assert SEVERITY_ORDER["CRITICAL"] < SEVERITY_ORDER["INFO"]
