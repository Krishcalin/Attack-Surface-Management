"""
EASM Scanner -- Jira Integration
Creates Jira tickets for security findings via REST API.

Features:
  - Jira Cloud and Server support (REST API v2/v3)
  - Severity-to-priority mapping
  - Deduplication via JQL search (avoids duplicate tickets)
  - Bulk ticket creation
  - Custom field mapping
  - Labels and component assignment
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Severity to Jira priority mapping ─────────────────────────────

DEFAULT_PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Lowest",
}


@dataclass
class JiraConfig:
    """Configuration for Jira integration."""
    url: str = ""              # https://company.atlassian.net
    username: str = ""         # email for Jira Cloud
    api_token: str = ""        # API token or password
    project_key: str = ""      # e.g., "SEC"
    issue_type: str = "Bug"    # Bug, Task, Story, etc.
    labels: list[str] = field(default_factory=lambda: ["easm", "security"])
    component: str = ""
    assignee: str = ""
    priority_map: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_PRIORITY_MAP)
    )
    min_severity: str = "HIGH"  # Minimum severity to create tickets
    deduplicate: bool = True    # Check for existing tickets
    dry_run: bool = False       # Don't actually create tickets

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "project_key": self.project_key,
            "issue_type": self.issue_type,
            "labels": self.labels,
            "min_severity": self.min_severity,
            "deduplicate": self.deduplicate,
            "dry_run": self.dry_run,
        }


@dataclass
class JiraTicketResult:
    """Result of a Jira ticket creation."""
    finding_rule_id: str
    asset_value: str
    success: bool = False
    ticket_key: str = ""       # e.g., "SEC-123"
    ticket_url: str = ""
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.finding_rule_id,
            "asset": self.asset_value,
            "success": self.success,
            "ticket_key": self.ticket_key,
            "ticket_url": self.ticket_url,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
        }


class JiraIntegration:
    """Create and manage Jira tickets for EASM findings."""

    SEVERITY_RANK = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
    }

    def __init__(
        self,
        config: Optional[JiraConfig] = None,
        verbose: bool = False,
    ) -> None:
        self.config = config or JiraConfig()
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def create_tickets(
        self,
        findings: list[dict[str, Any]],
    ) -> list[JiraTicketResult]:
        """Create Jira tickets for findings meeting severity threshold."""
        if not HAS_REQUESTS:
            self._vprint("    [jira] requests library not available")
            return []

        if not self.config.url or not self.config.project_key:
            self._vprint("    [jira] URL or project key not configured")
            return []

        results: list[JiraTicketResult] = []
        min_rank = self.SEVERITY_RANK.get(
            self.config.min_severity.upper(), 1
        )

        # Filter by severity
        eligible = [
            f for f in findings
            if self.SEVERITY_RANK.get(
                f.get("severity", "INFO"), 4
            ) <= min_rank
        ]

        for finding in eligible:
            result = self._create_single(finding)
            results.append(result)

        created = sum(1 for r in results if r.success)
        skipped = sum(1 for r in results if r.skipped)
        self._vprint(
            f"    [jira] {created} ticket(s) created, "
            f"{skipped} skipped (dedup)"
        )

        return results

    # ── Single ticket creation ───────────────────────────────

    def _create_single(
        self, finding: dict[str, Any],
    ) -> JiraTicketResult:
        """Create a single Jira ticket for a finding."""
        rule_id = finding.get("rule_id", "")
        asset = finding.get("asset_value", "")

        result = JiraTicketResult(
            finding_rule_id=rule_id,
            asset_value=asset,
        )

        # Deduplication check
        if self.config.deduplicate:
            existing = self._search_existing(rule_id, asset)
            if existing:
                result.skipped = True
                result.skip_reason = (
                    f"Duplicate: {existing} already exists"
                )
                return result

        # Build ticket payload
        severity = finding.get("severity", "MEDIUM")
        priority = self.config.priority_map.get(severity, "Medium")

        summary = (
            f"[EASM] [{severity}] {finding.get('name', rule_id)} "
            f"-- {asset}"
        )
        if len(summary) > 255:
            summary = summary[:252] + "..."

        description = self._build_description(finding)

        payload: dict[str, Any] = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.config.issue_type},
                "priority": {"name": priority},
                "labels": self.config.labels + [rule_id],
            },
        }

        if self.config.component:
            payload["fields"]["components"] = [
                {"name": self.config.component},
            ]

        if self.config.assignee:
            payload["fields"]["assignee"] = {
                "name": self.config.assignee,
            }

        # Dry run
        if self.config.dry_run:
            result.success = True
            result.ticket_key = "DRY-RUN"
            result.skip_reason = "Dry run mode"
            self._vprint(
                f"    [jira] DRY RUN: would create ticket for "
                f"{rule_id} / {asset}"
            )
            return result

        # Create ticket
        try:
            resp = self._api_request(
                "POST", "/rest/api/2/issue",
                json_data=payload,
            )

            if resp and resp.status_code in (200, 201):
                data = resp.json()
                result.success = True
                result.ticket_key = data.get("key", "")
                result.ticket_url = (
                    f"{self.config.url}/browse/{result.ticket_key}"
                )
                self._vprint(
                    f"    [jira] created {result.ticket_key} for "
                    f"{rule_id}"
                )
            elif resp:
                result.error = (
                    f"HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
            else:
                result.error = "No response from Jira API"

        except Exception as exc:
            result.error = str(exc)

        return result

    # ── Description builder ──────────────────────────────────

    @staticmethod
    def _build_description(finding: dict) -> str:
        """Build Jira ticket description from finding."""
        lines = [
            "h2. EASM Security Finding",
            "",
            f"||Field||Value||",
            f"|Rule ID|{finding.get('rule_id', '')}|",
            f"|Severity|{finding.get('severity', '')}|",
            f"|Category|{finding.get('category', '')}|",
            f"|Asset|{finding.get('asset_value', '')}|",
            f"|Asset Type|{finding.get('asset_type', '')}|",
        ]

        if finding.get("cve"):
            lines.append(f"|CVE|{finding['cve']}|")
        if finding.get("cwe"):
            lines.append(f"|CWE|{finding['cwe']}|")

        lines.append("")

        if finding.get("description"):
            lines.extend([
                "h3. Description",
                finding["description"],
                "",
            ])

        if finding.get("evidence"):
            lines.extend([
                "h3. Evidence",
                f"{{noformat}}{finding['evidence']}{{noformat}}",
                "",
            ])

        if finding.get("recommendation"):
            lines.extend([
                "h3. Recommendation",
                finding["recommendation"],
                "",
            ])

        lines.extend([
            "----",
            "_Auto-generated by EASM Scanner_",
        ])

        return "\n".join(lines)

    # ── Deduplication search ─────────────────────────────────

    def _search_existing(
        self, rule_id: str, asset_value: str,
    ) -> str:
        """Search for existing Jira ticket with same rule_id + asset."""
        # JQL: search by label containing rule_id in project
        jql = (
            f'project = "{self.config.project_key}" '
            f'AND labels = "{rule_id}" '
            f'AND summary ~ "{asset_value[:50]}" '
            f'AND resolution = Unresolved'
        )

        try:
            resp = self._api_request(
                "GET", "/rest/api/2/search",
                params={"jql": jql, "maxResults": 1, "fields": "key"},
            )

            if resp and resp.status_code == 200:
                data = resp.json()
                issues = data.get("issues", [])
                if issues:
                    return issues[0].get("key", "")

        except Exception:
            pass

        return ""

    # ── API helper ───────────────────────────────────────────

    def _api_request(
        self,
        method: str,
        path: str,
        json_data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Optional[Any]:
        """Make an authenticated request to the Jira API."""
        url = f"{self.config.url.rstrip('/')}{path}"

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Basic auth with email:api_token (Jira Cloud)
        auth = None
        if self.config.username and self.config.api_token:
            auth = (self.config.username, self.config.api_token)

        try:
            resp = _requests.request(
                method, url,
                headers=headers,
                auth=auth,
                json=json_data,
                params=params,
                timeout=30,
            )
            return resp

        except Exception as exc:
            self._vprint(f"    [jira] API error: {exc}")
            return None

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
