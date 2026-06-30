"""Tests for the dashboard data payload (Intelligence view). No network / fastapi.

DashboardRenderer._build_scan_data is pure (stdlib only); the live API endpoint
is a thin mirror of this payload."""
import easm_scanner
from api.dashboard import DashboardRenderer
from modules.intel_discovery import DiscoveredAsset


def _scanner(tmp_path):
    s = easm_scanner.EASMScanner(db_path=":memory:",
                                 screenshot_dir=str(tmp_path / "shots"))
    s.end_time = 1.0          # mark "scan complete" so the payload is built
    return s


def test_payload_has_empty_intelligence_by_default(tmp_path):
    payload = DashboardRenderer(_scanner(tmp_path))._build_scan_data()
    assert payload["intelligence"] == {"count": 0, "discovered": []}


def test_payload_includes_discovered_assets(tmp_path):
    s = _scanner(tmp_path)
    s.discovered_assets = [
        DiscoveredAsset(value="acme-labs.io", asset_type="domain",
                        methods=["cert-san-pivot", "reverse-whois"],
                        confidence=0.95, confidence_label="HIGH",
                        reasons=["shares a TLS certificate with a seed domain"],
                        registrant_org="ACME Corporation"),
        DiscoveredAsset(value="203.0.113.0/24", asset_type="cidr",
                        methods=["asn-org"], confidence=0.95,
                        confidence_label="HIGH"),
    ]
    intel = DashboardRenderer(s)._build_scan_data()["intelligence"]
    assert intel["count"] == 2
    first = intel["discovered"][0]
    assert first["value"] == "acme-labs.io"
    assert first["asset_type"] == "domain"
    assert "reverse-whois" in first["methods"]
    assert first["confidence_label"] == "HIGH"
    # the CIDR discovery is carried through too
    assert any(d["asset_type"] == "cidr" for d in intel["discovered"])


def test_render_has_intel_nav_page_and_injected_data(tmp_path):
    s = _scanner(tmp_path)
    s.discovered_assets = [
        DiscoveredAsset(value="acme-labs.io", asset_type="domain",
                        methods=["cert-san-pivot"], confidence=0.9,
                        confidence_label="HIGH"),
    ]
    html = DashboardRenderer(s).render()
    assert 'data-page="intel"' in html        # nav item
    assert 'id="page-intel"' in html          # page section
    assert 'id="intel-body"' in html          # table body
    assert "window.__EASM_DATA__" in html     # data injected
    assert "acme-labs.io" in html             # discovered asset in payload
