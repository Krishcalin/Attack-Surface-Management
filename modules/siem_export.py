"""
EASM Scanner -- SIEM Export Module
Exports findings and asset data to SIEM platforms.

Supported formats:
  - Splunk HTTP Event Collector (HEC)
  - Elasticsearch / OpenSearch (bulk API)
  - Syslog CEF (Common Event Format)
  - CSV export (for manual SIEM import)
  - JSON Lines (.jsonl) for streaming pipelines
"""

from __future__ import annotations

import csv
import io
import json
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── CEF severity mapping ──────────────────────────────────────────

CEF_SEVERITY = {
    "CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 0,
}


@dataclass
class SIEMConfig:
    """Configuration for a SIEM export target."""
    target: str                # "splunk_hec", "elasticsearch", "syslog_cef", "csv", "jsonl"
    enabled: bool = True

    # Splunk HEC
    splunk_url: str = ""       # https://splunk:8088/services/collector
    splunk_token: str = ""
    splunk_index: str = "easm"
    splunk_sourcetype: str = "easm:finding"
    splunk_verify_ssl: bool = True

    # Elasticsearch
    es_url: str = ""           # https://es:9200
    es_index: str = "easm-findings"
    es_username: str = ""
    es_password: str = ""
    es_api_key: str = ""
    es_verify_ssl: bool = True

    # Syslog CEF
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # "udp" or "tcp"
    cef_vendor: str = "EASM"
    cef_product: str = "AttackSurfaceScanner"
    cef_version: str = "4.0"

    # File export
    output_path: str = ""      # for CSV / JSONL

    def to_dict(self) -> dict[str, Any]:
        d = {"target": self.target, "enabled": self.enabled}
        if self.target == "splunk_hec":
            d["splunk_url"] = self.splunk_url
            d["splunk_index"] = self.splunk_index
        elif self.target == "elasticsearch":
            d["es_url"] = self.es_url
            d["es_index"] = self.es_index
        elif self.target == "syslog_cef":
            d["syslog_host"] = self.syslog_host
            d["syslog_port"] = self.syslog_port
        elif self.target in ("csv", "jsonl"):
            d["output_path"] = self.output_path
        return d


@dataclass
class ExportResult:
    """Result of a SIEM export operation."""
    target: str
    success: bool
    events_sent: int = 0
    error: str = ""


class SIEMExporter:
    """Export EASM findings to SIEM platforms."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def export(
        self,
        config: SIEMConfig,
        findings: list[dict[str, Any]],
        assets: Optional[list[dict]] = None,
        scan_summary: Optional[dict] = None,
    ) -> ExportResult:
        """Export findings to the configured SIEM target."""
        if not config.enabled:
            return ExportResult(
                target=config.target, success=False,
                error="Export target disabled",
            )

        handlers = {
            "splunk_hec": self._export_splunk,
            "elasticsearch": self._export_elasticsearch,
            "syslog_cef": self._export_syslog_cef,
            "csv": self._export_csv,
            "jsonl": self._export_jsonl,
        }

        handler = handlers.get(config.target)
        if not handler:
            return ExportResult(
                target=config.target, success=False,
                error=f"Unknown target: {config.target}",
            )

        result = handler(config, findings, assets, scan_summary)
        self._vprint(
            f"    [siem] {config.target}: "
            f"{'OK' if result.success else 'FAILED'} "
            f"({result.events_sent} events)"
        )
        return result

    def bulk_export(
        self,
        configs: list[SIEMConfig],
        findings: list[dict],
        assets: Optional[list[dict]] = None,
        scan_summary: Optional[dict] = None,
    ) -> list[ExportResult]:
        """Export to multiple SIEM targets."""
        results = []
        for config in configs:
            results.append(
                self.export(config, findings, assets, scan_summary)
            )
        return results

    # ── Splunk HEC ───────────────────────────────────────────

    def _export_splunk(
        self,
        config: SIEMConfig,
        findings: list[dict],
        assets: Optional[list[dict]],
        summary: Optional[dict],
    ) -> ExportResult:
        """Export to Splunk via HTTP Event Collector."""
        result = ExportResult(target="splunk_hec", success=False)

        if not HAS_REQUESTS or not config.splunk_url:
            result.error = "Splunk HEC URL not configured"
            return result

        headers = {
            "Authorization": f"Splunk {config.splunk_token}",
            "Content-Type": "application/json",
        }

        events = []
        now = time.time()

        for f in findings:
            events.append({
                "time": now,
                "index": config.splunk_index,
                "sourcetype": config.splunk_sourcetype,
                "source": "easm_scanner",
                "event": {
                    "event_type": "finding",
                    **f,
                },
            })

        # Batch send (max 100 per request)
        batch_size = 100
        sent = 0

        try:
            for i in range(0, len(events), batch_size):
                batch = events[i:i + batch_size]
                payload = "\n".join(json.dumps(e) for e in batch)

                resp = _requests.post(
                    config.splunk_url,
                    data=payload,
                    headers=headers,
                    timeout=30,
                    verify=config.splunk_verify_ssl,
                )

                if resp.status_code != 200:
                    result.error = (
                        f"HTTP {resp.status_code}: {resp.text[:200]}"
                    )
                    result.events_sent = sent
                    return result

                sent += len(batch)

            result.success = True
            result.events_sent = sent

        except Exception as exc:
            result.error = str(exc)
            result.events_sent = sent

        return result

    # ── Elasticsearch ────────────────────────────────────────

    def _export_elasticsearch(
        self,
        config: SIEMConfig,
        findings: list[dict],
        assets: Optional[list[dict]],
        summary: Optional[dict],
    ) -> ExportResult:
        """Export to Elasticsearch via bulk API."""
        result = ExportResult(target="elasticsearch", success=False)

        if not HAS_REQUESTS or not config.es_url:
            result.error = "Elasticsearch URL not configured"
            return result

        # Build auth
        auth = None
        headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
        if config.es_api_key:
            headers["Authorization"] = f"ApiKey {config.es_api_key}"
        elif config.es_username:
            auth = (config.es_username, config.es_password)

        # Build bulk body
        now = datetime.now(timezone.utc).isoformat()
        lines: list[str] = []

        for f in findings:
            action = json.dumps({
                "index": {"_index": config.es_index}
            })
            doc = json.dumps({
                "@timestamp": now,
                "source": "easm_scanner",
                "event_type": "finding",
                **f,
            })
            lines.append(action)
            lines.append(doc)

        if not lines:
            result.success = True
            return result

        body = "\n".join(lines) + "\n"

        try:
            url = f"{config.es_url.rstrip('/')}/_bulk"
            resp = _requests.post(
                url,
                data=body,
                headers=headers,
                auth=auth,
                timeout=30,
                verify=config.es_verify_ssl,
            )

            if resp.status_code in (200, 201):
                data = resp.json()
                if not data.get("errors"):
                    result.success = True
                    result.events_sent = len(findings)
                else:
                    result.error = "Some documents had errors"
                    result.events_sent = len(findings)
                    result.success = True  # partial success
            else:
                result.error = f"HTTP {resp.status_code}"

        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Syslog CEF ───────────────────────────────────────────

    def _export_syslog_cef(
        self,
        config: SIEMConfig,
        findings: list[dict],
        assets: Optional[list[dict]],
        summary: Optional[dict],
    ) -> ExportResult:
        """Export to Syslog in CEF format."""
        result = ExportResult(target="syslog_cef", success=False)

        if not config.syslog_host:
            result.error = "Syslog host not configured"
            return result

        try:
            if config.syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((config.syslog_host, config.syslog_port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(10)

            sent = 0
            for f in findings:
                cef = self._build_cef(config, f)
                data = cef.encode("utf-8")

                if config.syslog_protocol == "tcp":
                    sock.send(data + b"\n")
                else:
                    sock.sendto(
                        data,
                        (config.syslog_host, config.syslog_port),
                    )
                sent += 1

            sock.close()
            result.success = True
            result.events_sent = sent

        except Exception as exc:
            result.error = str(exc)

        return result

    @staticmethod
    def _build_cef(config: SIEMConfig, finding: dict) -> str:
        """Build a CEF-formatted syslog message."""
        sev = finding.get("severity", "INFO")
        cef_sev = CEF_SEVERITY.get(sev, 0)

        # Escape CEF special chars
        def esc(s: str) -> str:
            return (s.replace("\\", "\\\\")
                     .replace("|", "\\|")
                     .replace("=", "\\=")
                     .replace("\n", " "))

        rule_id = esc(finding.get("rule_id", ""))
        name = esc(finding.get("name", ""))
        asset = esc(finding.get("asset_value", ""))
        evidence = esc(finding.get("evidence", "")[:200])
        category = esc(finding.get("category", ""))

        cef = (
            f"CEF:0|{config.cef_vendor}|{config.cef_product}"
            f"|{config.cef_version}|{rule_id}|{name}|{cef_sev}"
            f"|dst={asset} cat={category} msg={evidence}"
        )
        return cef

    # ── CSV ──────────────────────────────────────────────────

    def _export_csv(
        self,
        config: SIEMConfig,
        findings: list[dict],
        assets: Optional[list[dict]],
        summary: Optional[dict],
    ) -> ExportResult:
        """Export findings to CSV file."""
        result = ExportResult(target="csv", success=False)

        if not config.output_path:
            result.error = "Output path not configured"
            return result

        fields = [
            "rule_id", "name", "category", "severity",
            "asset_value", "asset_type", "description",
            "recommendation", "cwe", "cve", "evidence",
        ]

        try:
            with open(config.output_path, "w", newline="",
                       encoding="utf-8") as fh:
                writer = csv.DictWriter(
                    fh, fieldnames=fields, extrasaction="ignore",
                )
                writer.writeheader()
                for f in findings:
                    writer.writerow(f)

            result.success = True
            result.events_sent = len(findings)

        except Exception as exc:
            result.error = str(exc)

        return result

    # ── JSON Lines ───────────────────────────────────────────

    def _export_jsonl(
        self,
        config: SIEMConfig,
        findings: list[dict],
        assets: Optional[list[dict]],
        summary: Optional[dict],
    ) -> ExportResult:
        """Export findings to JSON Lines file."""
        result = ExportResult(target="jsonl", success=False)

        if not config.output_path:
            result.error = "Output path not configured"
            return result

        try:
            now = datetime.now(timezone.utc).isoformat()
            with open(config.output_path, "w",
                       encoding="utf-8") as fh:
                for f in findings:
                    event = {
                        "timestamp": now,
                        "source": "easm_scanner",
                        "event_type": "finding",
                        **f,
                    }
                    fh.write(json.dumps(event, default=str) + "\n")

            result.success = True
            result.events_sent = len(findings)

        except Exception as exc:
            result.error = str(exc)

        return result

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
