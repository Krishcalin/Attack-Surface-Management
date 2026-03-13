"""
EASM Scanner -- Dashboard Serving Module
Generates and serves the interactive HTML dashboard with live data injection.

Used by the FastAPI server to provide a rich single-page dashboard
with severity charts, asset inventory, risk heat-map, and findings table.
"""

from __future__ import annotations

import html as html_mod
import json
from pathlib import Path
from typing import Any, Optional


TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class DashboardRenderer:
    """Render the interactive dashboard with scan data."""

    def __init__(self, scanner: Any = None) -> None:
        self.scanner = scanner

    def render(self) -> str:
        """Render the dashboard HTML with injected scan data."""
        template_path = TEMPLATE_DIR / "dashboard.html"
        if not template_path.exists():
            return self._fallback_html()

        html_content = template_path.read_text(encoding="utf-8")

        # Inject scan data as JSON into the template
        if self.scanner and self.scanner.end_time:
            scan_data = self._build_scan_data()
            data_json = json.dumps(scan_data, default=str)
            # Replace placeholder in template
            html_content = html_content.replace(
                "/* __SCAN_DATA_PLACEHOLDER__ */",
                f"window.__EASM_DATA__ = {data_json};",
            )

        return html_content

    def _build_scan_data(self) -> dict[str, Any]:
        """Build scan data payload for the dashboard."""
        scanner = self.scanner
        summary = scanner.summary()

        # Severity distribution
        sev_dist = summary.get("findings", {})

        # Category distribution
        cat_dist: dict[str, int] = {}
        for f in scanner.findings:
            cat_dist[f.category] = cat_dist.get(f.category, 0) + 1

        # Top findings (first 50)
        from models.finding import SEVERITY_ORDER
        sorted_findings = sorted(
            scanner.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 4),
        )
        top_findings = [
            f.to_dict() for f in sorted_findings[:50]
        ]

        # Top risk scores
        top_risks = [
            r.to_dict() for r in scanner.risk_scores[:30]
        ]

        # Asset counts
        asset_counts = summary.get("assets", {})

        return {
            "summary": summary,
            "severity_distribution": sev_dist,
            "category_distribution": cat_dist,
            "top_findings": top_findings,
            "top_risk_scores": top_risks,
            "asset_counts": asset_counts,
            "enrichment": summary.get("enrichment", {}),
            "vuln_assessment": summary.get("vuln_assessment", {}),
        }

    @staticmethod
    def _fallback_html() -> str:
        return (
            "<!DOCTYPE html><html><body style='background:#0d1117;"
            "color:#c9d1d9;font-family:sans-serif;padding:40px;"
            "text-align:center'>"
            "<h1>EASM Scanner Dashboard</h1>"
            "<p>Dashboard template not found.</p>"
            "</body></html>"
        )
