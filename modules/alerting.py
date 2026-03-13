"""
EASM Scanner -- Alerting & Notification Engine
Sends alerts when new critical/high findings are discovered.

Channels:
  - Email (SMTP)
  - Slack (webhook)
  - Microsoft Teams (webhook)
  - Generic webhook (POST JSON)
  - Console (stdout fallback)

Supports filtering by severity threshold and deduplication
via finding rule_id + asset_value hash.
"""

from __future__ import annotations

import hashlib
import json
import smtplib
import ssl
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Alert severity thresholds ──────────────────────────────────────

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class AlertConfig:
    """Configuration for an alert channel."""
    channel: str               # "email", "slack", "teams", "webhook", "console"
    enabled: bool = True
    min_severity: str = "HIGH"  # minimum severity to trigger alerts

    # Email settings
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    email_from: str = ""
    email_to: list[str] = field(default_factory=list)

    # Slack settings
    slack_webhook_url: str = ""

    # Teams settings
    teams_webhook_url: str = ""

    # Generic webhook settings
    webhook_url: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "channel": self.channel,
            "enabled": self.enabled,
            "min_severity": self.min_severity,
        }
        if self.channel == "email":
            d["smtp_host"] = self.smtp_host
            d["email_to"] = self.email_to
        elif self.channel == "slack":
            d["slack_webhook_url"] = "***" if self.slack_webhook_url else ""
        elif self.channel == "teams":
            d["teams_webhook_url"] = "***" if self.teams_webhook_url else ""
        elif self.channel == "webhook":
            d["webhook_url"] = self.webhook_url
        return d


@dataclass
class AlertResult:
    """Result of sending an alert."""
    channel: str
    success: bool
    findings_count: int = 0
    error: str = ""


class AlertEngine:
    """Multi-channel alert notification engine."""

    def __init__(
        self,
        configs: Optional[list[AlertConfig]] = None,
        verbose: bool = False,
    ) -> None:
        self.configs = configs or []
        self.verbose = verbose
        self._sent_hashes: set[str] = set()

    # ── Public API ──────────────────────────────────────────

    def send_alerts(
        self,
        findings: list[dict[str, Any]],
        scan_summary: Optional[dict] = None,
    ) -> list[AlertResult]:
        """Send alerts for findings that meet severity threshold."""
        results: list[AlertResult] = []

        for config in self.configs:
            if not config.enabled:
                continue

            # Filter findings by severity threshold
            min_rank = SEVERITY_RANK.get(config.min_severity.upper(), 1)
            filtered = [
                f for f in findings
                if SEVERITY_RANK.get(f.get("severity", "INFO"), 4) <= min_rank
            ]

            # Deduplicate
            new_findings = self._deduplicate(filtered)
            if not new_findings:
                continue

            # Send via appropriate channel
            result = self._dispatch(config, new_findings, scan_summary)
            results.append(result)

            self._vprint(
                f"    [alert] {config.channel}: "
                f"{'sent' if result.success else 'FAILED'} "
                f"({result.findings_count} finding(s))"
            )

        return results

    def add_config(self, config: AlertConfig) -> None:
        """Add an alert channel configuration."""
        self.configs.append(config)

    # ── Dispatch ─────────────────────────────────────────────

    def _dispatch(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Route alert to the correct channel handler."""
        handlers = {
            "email": self._send_email,
            "slack": self._send_slack,
            "teams": self._send_teams,
            "webhook": self._send_webhook,
            "console": self._send_console,
        }
        handler = handlers.get(config.channel, self._send_console)
        return handler(config, findings, summary)

    # ── Email ────────────────────────────────────────────────

    def _send_email(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Send alert via SMTP email."""
        result = AlertResult(
            channel="email", success=False,
            findings_count=len(findings),
        )

        if not config.smtp_host or not config.email_to:
            result.error = "SMTP host or recipients not configured"
            return result

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = (
                f"[EASM Alert] {len(findings)} new finding(s) detected"
            )
            msg["From"] = config.email_from or config.smtp_user
            msg["To"] = ", ".join(config.email_to)

            # Plain text body
            text_body = self._format_text(findings, summary)
            msg.attach(MIMEText(text_body, "plain"))

            # HTML body
            html_body = self._format_html(findings, summary)
            msg.attach(MIMEText(html_body, "html"))

            # Connect and send
            if config.smtp_use_tls:
                ctx = ssl.create_default_context()
                server = smtplib.SMTP(config.smtp_host, config.smtp_port)
                server.starttls(context=ctx)
            else:
                server = smtplib.SMTP(config.smtp_host, config.smtp_port)

            if config.smtp_user and config.smtp_password:
                server.login(config.smtp_user, config.smtp_password)

            server.sendmail(
                msg["From"], config.email_to, msg.as_string(),
            )
            server.quit()

            result.success = True

        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Slack ────────────────────────────────────────────────

    def _send_slack(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Send alert via Slack webhook."""
        result = AlertResult(
            channel="slack", success=False,
            findings_count=len(findings),
        )

        if not HAS_REQUESTS or not config.slack_webhook_url:
            result.error = "Slack webhook URL not configured"
            return result

        sev_emoji = {
            "CRITICAL": ":red_circle:",
            "HIGH": ":large_orange_circle:",
            "MEDIUM": ":large_yellow_circle:",
            "LOW": ":large_blue_circle:",
            "INFO": ":white_circle:",
        }

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"EASM Alert: {len(findings)} New Finding(s)",
                },
            },
        ]

        if summary:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Scan time:* {summary.get('scan_time', 'N/A')}\n"
                        f"*Total assets:* {summary.get('total_assets', 0)}\n"
                        f"*Total findings:* {summary.get('total_findings', 0)}"
                    ),
                },
            })

        # Add findings (max 10 to avoid message size limits)
        for f in findings[:10]:
            sev = f.get("severity", "INFO")
            emoji = sev_emoji.get(sev, ":white_circle:")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *[{sev}]* {f.get('rule_id', '')}"
                        f" -- {f.get('name', '')}\n"
                        f"Asset: `{f.get('asset_value', '')}`\n"
                        f"Evidence: {f.get('evidence', '')[:100]}"
                    ),
                },
            })

        if len(findings) > 10:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"_...and {len(findings) - 10} more_",
                },
            })

        payload = {"blocks": blocks}

        try:
            resp = _requests.post(
                config.slack_webhook_url,
                json=payload,
                timeout=15,
            )
            if resp.status_code == 200:
                result.success = True
            else:
                result.error = f"HTTP {resp.status_code}: {resp.text[:100]}"
        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Microsoft Teams ──────────────────────────────────────

    def _send_teams(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Send alert via Microsoft Teams webhook."""
        result = AlertResult(
            channel="teams", success=False,
            findings_count=len(findings),
        )

        if not HAS_REQUESTS or not config.teams_webhook_url:
            result.error = "Teams webhook URL not configured"
            return result

        sev_color = {
            "CRITICAL": "FF0000", "HIGH": "FF4500",
            "MEDIUM": "FFA500", "LOW": "1E90FF", "INFO": "808080",
        }

        # Build findings text
        findings_text = ""
        for f in findings[:15]:
            sev = f.get("severity", "INFO")
            findings_text += (
                f"- **[{sev}]** {f.get('rule_id', '')} "
                f"-- {f.get('name', '')} "
                f"| Asset: `{f.get('asset_value', '')}`\n"
            )

        top_sev = findings[0].get("severity", "INFO") if findings else "INFO"

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": sev_color.get(top_sev, "808080"),
            "summary": f"EASM Alert: {len(findings)} findings",
            "sections": [
                {
                    "activityTitle": (
                        f"EASM Alert: {len(findings)} "
                        f"New Finding(s)"
                    ),
                    "activitySubtitle": (
                        f"Scan time: "
                        f"{summary.get('scan_time', 'N/A') if summary else 'N/A'}"
                    ),
                    "text": findings_text,
                    "markdown": True,
                },
            ],
        }

        try:
            resp = _requests.post(
                config.teams_webhook_url,
                json=payload,
                timeout=15,
            )
            if resp.status_code == 200:
                result.success = True
            else:
                result.error = f"HTTP {resp.status_code}"
        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Generic Webhook ──────────────────────────────────────

    def _send_webhook(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Send alert via generic webhook (POST JSON)."""
        result = AlertResult(
            channel="webhook", success=False,
            findings_count=len(findings),
        )

        if not HAS_REQUESTS or not config.webhook_url:
            result.error = "Webhook URL not configured"
            return result

        payload = {
            "source": "easm-scanner",
            "alert_type": "new_findings",
            "findings_count": len(findings),
            "findings": findings[:50],
            "summary": summary or {},
        }

        headers = {"Content-Type": "application/json"}
        headers.update(config.webhook_headers)

        try:
            resp = _requests.post(
                config.webhook_url,
                json=payload,
                headers=headers,
                timeout=15,
            )
            if resp.status_code < 400:
                result.success = True
            else:
                result.error = f"HTTP {resp.status_code}"
        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Console ──────────────────────────────────────────────

    def _send_console(
        self,
        config: AlertConfig,
        findings: list[dict],
        summary: Optional[dict],
    ) -> AlertResult:
        """Print alert to console (fallback)."""
        print(f"\n  === EASM ALERT: {len(findings)} new finding(s) ===")
        for f in findings[:20]:
            sev = f.get("severity", "INFO")
            print(
                f"  [{sev}] {f.get('rule_id', '')} -- "
                f"{f.get('name', '')} | {f.get('asset_value', '')}"
            )
        if len(findings) > 20:
            print(f"  ...and {len(findings) - 20} more")
        print()

        return AlertResult(
            channel="console", success=True,
            findings_count=len(findings),
        )

    # ── Formatting helpers ───────────────────────────────────

    @staticmethod
    def _format_text(
        findings: list[dict], summary: Optional[dict],
    ) -> str:
        """Format findings as plain text for email."""
        lines = ["EASM Scanner - Alert Notification", "=" * 40, ""]
        if summary:
            lines.append(f"Scan time: {summary.get('scan_time', 'N/A')}")
            lines.append(
                f"Total assets: {summary.get('total_assets', 0)}"
            )
            lines.append(
                f"Total findings: {summary.get('total_findings', 0)}"
            )
            lines.append("")

        lines.append(f"New findings: {len(findings)}")
        lines.append("-" * 40)

        for f in findings:
            lines.append(
                f"[{f.get('severity', '')}] {f.get('rule_id', '')} "
                f"-- {f.get('name', '')}"
            )
            lines.append(f"  Asset: {f.get('asset_value', '')}")
            if f.get("evidence"):
                lines.append(f"  Evidence: {f['evidence'][:150]}")
            if f.get("recommendation"):
                lines.append(f"  Fix: {f['recommendation'][:150]}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _format_html(
        findings: list[dict], summary: Optional[dict],
    ) -> str:
        """Format findings as HTML for email."""
        sev_color = {
            "CRITICAL": "#f85149", "HIGH": "#ff4500",
            "MEDIUM": "#d29922", "LOW": "#39d2c0", "INFO": "#8b949e",
        }

        rows = ""
        for f in findings:
            sev = f.get("severity", "INFO")
            color = sev_color.get(sev, "#8b949e")
            rows += (
                f"<tr>"
                f"<td style='color:{color};font-weight:bold'>{sev}</td>"
                f"<td>{f.get('rule_id', '')}</td>"
                f"<td>{f.get('name', '')}</td>"
                f"<td><code>{f.get('asset_value', '')}</code></td>"
                f"<td>{f.get('evidence', '')[:100]}</td>"
                f"</tr>"
            )

        return f"""
        <html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px">
        <h2 style="color:#58a6ff">EASM Scanner Alert</h2>
        <p>{len(findings)} new finding(s) detected.</p>
        <table style="border-collapse:collapse;width:100%">
        <tr style="background:#161b22">
            <th style="padding:8px;text-align:left;border-bottom:1px solid #30363d">Severity</th>
            <th style="padding:8px;text-align:left;border-bottom:1px solid #30363d">Rule</th>
            <th style="padding:8px;text-align:left;border-bottom:1px solid #30363d">Name</th>
            <th style="padding:8px;text-align:left;border-bottom:1px solid #30363d">Asset</th>
            <th style="padding:8px;text-align:left;border-bottom:1px solid #30363d">Evidence</th>
        </tr>
        {rows}
        </table>
        </body></html>
        """

    # ── Deduplication ────────────────────────────────────────

    def _deduplicate(
        self, findings: list[dict],
    ) -> list[dict]:
        """Filter out already-alerted findings."""
        new: list[dict] = []
        for f in findings:
            h = self._finding_hash(f)
            if h not in self._sent_hashes:
                self._sent_hashes.add(h)
                new.append(f)
        return new

    @staticmethod
    def _finding_hash(finding: dict) -> str:
        key = (
            f"{finding.get('rule_id', '')}:"
            f"{finding.get('asset_value', '')}:"
            f"{finding.get('severity', '')}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
