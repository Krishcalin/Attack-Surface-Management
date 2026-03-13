"""
EASM Scanner -- FastAPI REST API Server
Provides REST endpoints for scan management, asset/finding queries,
dashboard serving, and integration configuration.

Endpoints:
  GET  /api/health              -- Health check
  POST /api/scan                -- Launch a new scan
  GET  /api/scan/status         -- Current scan status
  GET  /api/scan/history        -- Scan history (from scheduler)
  GET  /api/summary             -- Latest scan summary
  GET  /api/assets              -- Asset inventory (filterable)
  GET  /api/findings            -- Security findings (filterable)
  GET  /api/risk-scores         -- Risk score data
  GET  /api/graph               -- Asset relationship graph
  GET  /api/export/{fmt}        -- Export findings (json, csv, jsonl)
  POST /api/alerts/test         -- Send a test alert
  GET  /                        -- Interactive dashboard
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Optional

try:
    from fastapi import FastAPI, HTTPException, Query, Request
    from fastapi.responses import (
        FileResponse,
        HTMLResponse,
        JSONResponse,
        StreamingResponse,
    )
    from fastapi.staticfiles import StaticFiles
    import uvicorn

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# ── Path setup ────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def create_app(scanner: Any = None) -> "FastAPI":
    """Create and configure the FastAPI application.

    Args:
        scanner: An EASMScanner instance (injected from CLI or tests).
    """
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI + uvicorn required: pip install fastapi uvicorn"
        )

    app = FastAPI(
        title="EASM Scanner API",
        description="External Attack Surface Management REST API",
        version="4.0.0",
    )

    # ── Shared state ──────────────────────────────────────────
    state: dict[str, Any] = {
        "scanner": scanner,
        "scan_running": False,
        "scan_thread": None,
        "last_scan_time": None,
        "last_scan_error": None,
        "scan_progress": "",
        "scheduler": None,
        "alert_engine": None,
    }

    # ── Health ────────────────────────────────────────────────

    @app.get("/api/health")
    def health() -> dict:
        return {
            "status": "ok",
            "version": "4.0.0",
            "scan_running": state["scan_running"],
            "last_scan_time": state["last_scan_time"],
        }

    # ── Scan management ───────────────────────────────────────

    @app.post("/api/scan")
    def start_scan(
        domains: list[str] = [],
        ips: list[str] = [],
        asns: list[str] = [],
        cidrs: list[str] = [],
        org_name: str = "",
        skip_ports: bool = False,
        skip_http: bool = False,
        skip_enrichment: bool = False,
        skip_vuln_assessment: bool = False,
        skip_nuclei: bool = False,
        skip_cred_test: bool = False,
    ) -> dict:
        """Launch a new scan in a background thread."""
        if state["scan_running"]:
            raise HTTPException(409, "A scan is already running")

        if not state["scanner"]:
            raise HTTPException(
                500, "Scanner not initialised -- start with CLI"
            )

        if not any([domains, ips, asns, cidrs]):
            raise HTTPException(
                400, "Provide at least one seed (domains, ips, asns, cidrs)"
            )

        def _run_scan() -> None:
            state["scan_running"] = True
            state["scan_progress"] = "running"
            state["last_scan_error"] = None
            try:
                state["scanner"].run(
                    domains=domains or None,
                    ips=ips or None,
                    asns=asns or None,
                    cidrs=cidrs or None,
                    org_name=org_name,
                    skip_ports=skip_ports,
                    skip_http=skip_http,
                    skip_enrichment=skip_enrichment,
                    skip_vuln_assessment=skip_vuln_assessment,
                    skip_nuclei=skip_nuclei,
                    skip_cred_test=skip_cred_test,
                )
                state["last_scan_time"] = (
                    datetime.now(timezone.utc).isoformat()
                )
                state["scan_progress"] = "completed"
            except Exception as exc:
                state["last_scan_error"] = str(exc)
                state["scan_progress"] = "failed"
            finally:
                state["scan_running"] = False

        t = threading.Thread(target=_run_scan, daemon=True)
        t.start()
        state["scan_thread"] = t

        return {"status": "scan_started", "message": "Scan launched"}

    @app.get("/api/scan/status")
    def scan_status() -> dict:
        return {
            "running": state["scan_running"],
            "progress": state["scan_progress"],
            "last_scan_time": state["last_scan_time"],
            "last_error": state["last_scan_error"],
        }

    @app.get("/api/scan/history")
    def scan_history(
        profile: str = "default",
        limit: int = Query(10, ge=1, le=100),
    ) -> list[dict]:
        """Get scan history from scheduler."""
        if state.get("scheduler"):
            return state["scheduler"].get_history(profile, limit)
        return []

    # ── Summary ───────────────────────────────────────────────

    @app.get("/api/summary")
    def get_summary() -> dict:
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")
        if not state["scanner"].end_time:
            return {"message": "No scan results available yet"}
        return state["scanner"].summary()

    # ── Assets ────────────────────────────────────────────────

    @app.get("/api/assets")
    def get_assets(
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(500, ge=1, le=5000),
        offset: int = Query(0, ge=0),
    ) -> dict:
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")

        store = state["scanner"].store
        assets = store.get_assets(asset_type=asset_type)

        # Search filter
        if search:
            search_lower = search.lower()
            assets = [
                a for a in assets
                if search_lower in a.value.lower()
                or search_lower in a.parent.lower()
            ]

        total = len(assets)
        assets = assets[offset : offset + limit]

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "assets": [a.to_dict() for a in assets],
        }

    # ── Findings ──────────────────────────────────────────────

    @app.get("/api/findings")
    def get_findings(
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(500, ge=1, le=5000),
        offset: int = Query(0, ge=0),
    ) -> dict:
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")

        findings = list(state["scanner"].findings)

        if severity:
            sev_upper = severity.upper()
            findings = [
                f for f in findings if f.severity == sev_upper
            ]

        if category:
            cat_lower = category.lower()
            findings = [
                f for f in findings
                if cat_lower in f.category.lower()
            ]

        if search:
            search_lower = search.lower()
            findings = [
                f for f in findings
                if search_lower in f.name.lower()
                or search_lower in f.asset_value.lower()
                or search_lower in f.rule_id.lower()
            ]

        # Sort by severity
        from models.finding import SEVERITY_ORDER
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        total = len(findings)
        findings = findings[offset : offset + limit]

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "findings": [f.to_dict() for f in findings],
        }

    # ── Risk Scores ───────────────────────────────────────────

    @app.get("/api/risk-scores")
    def get_risk_scores(
        min_score: float = Query(0.0, ge=0, le=100),
        limit: int = Query(100, ge=1, le=1000),
    ) -> dict:
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")

        scores = state["scanner"].risk_scores
        if min_score > 0:
            scores = [s for s in scores if s.risk_score >= min_score]

        from modules.risk_scorer import RiskScorer
        stats = RiskScorer.aggregate_stats(scores)

        return {
            "stats": stats,
            "scores": [s.to_dict() for s in scores[:limit]],
        }

    # ── Asset Graph ───────────────────────────────────────────

    @app.get("/api/graph")
    def get_graph() -> dict:
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")
        return state["scanner"].graph.to_dict()

    # ── Export ────────────────────────────────────────────────

    @app.get("/api/export/{fmt}")
    def export_findings(fmt: str) -> Any:
        """Export findings in json, csv, or jsonl format."""
        if not state["scanner"]:
            raise HTTPException(500, "Scanner not initialised")

        findings = [f.to_dict() for f in state["scanner"].findings]

        if fmt == "json":
            return JSONResponse(
                content=findings,
                media_type="application/json",
                headers={
                    "Content-Disposition":
                        "attachment; filename=easm_findings.json"
                },
            )

        elif fmt == "csv":
            import csv
            buf = StringIO()
            if findings:
                writer = csv.DictWriter(
                    buf, fieldnames=list(findings[0].keys()),
                )
                writer.writeheader()
                writer.writerows(findings)
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition":
                        "attachment; filename=easm_findings.csv"
                },
            )

        elif fmt == "jsonl":
            lines = "\n".join(
                json.dumps(f, default=str) for f in findings
            )
            return StreamingResponse(
                iter([lines]),
                media_type="application/x-ndjson",
                headers={
                    "Content-Disposition":
                        "attachment; filename=easm_findings.jsonl"
                },
            )

        else:
            raise HTTPException(
                400, f"Unsupported format: {fmt}. Use json, csv, jsonl"
            )

    # ── Alerts ────────────────────────────────────────────────

    @app.post("/api/alerts/test")
    def test_alert() -> dict:
        """Send a test alert through configured channels."""
        if not state.get("alert_engine"):
            return {
                "status": "skipped",
                "message": "No alert channels configured",
            }

        test_finding = {
            "rule_id": "EASM-TEST-001",
            "name": "Test Alert",
            "severity": "HIGH",
            "asset_value": "test.example.com",
            "evidence": "This is a test alert from EASM Scanner",
        }

        results = state["alert_engine"].send_alerts(
            [test_finding], {"scan_time": "test"},
        )
        return {
            "status": "sent",
            "results": [
                {
                    "channel": r.channel,
                    "success": r.success,
                    "error": r.error,
                }
                for r in results
            ],
        }

    # ── Dashboard ─────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        """Serve the interactive dashboard."""
        template_path = ROOT / "templates" / "dashboard.html"
        if template_path.exists():
            return HTMLResponse(
                content=template_path.read_text(encoding="utf-8"),
            )
        return HTMLResponse(
            content=(
                "<html><body style='background:#0d1117;color:#c9d1d9;"
                "font-family:sans-serif;padding:40px;text-align:center'>"
                "<h1>EASM Scanner Dashboard</h1>"
                "<p>Dashboard template not found. Place "
                "<code>templates/dashboard.html</code> in the project "
                "root.</p></body></html>"
            ),
        )

    # ── Inject helpers ────────────────────────────────────────

    def set_scanner(s: Any) -> None:
        state["scanner"] = s

    def set_scheduler(sched: Any) -> None:
        state["scheduler"] = sched

    def set_alert_engine(engine: Any) -> None:
        state["alert_engine"] = engine

    app.set_scanner = set_scanner
    app.set_scheduler = set_scheduler
    app.set_alert_engine = set_alert_engine

    return app


def run_server(
    scanner: Any = None,
    host: str = "0.0.0.0",
    port: int = 8888,
) -> None:
    """Start the API server."""
    if not HAS_FASTAPI:
        print(
            "  [ERROR] FastAPI + uvicorn required: "
            "pip install fastapi uvicorn"
        )
        return

    app = create_app(scanner)
    print(f"\n  EASM Scanner API starting on http://{host}:{port}")
    print(f"  Dashboard: http://localhost:{port}/")
    print(f"  API docs:  http://localhost:{port}/docs\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
