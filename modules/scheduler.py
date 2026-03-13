"""
EASM Scanner -- Scan Scheduler
Provides scheduled/continuous scanning with diff detection.

Features:
  - Interval-based scan scheduling
  - Finding diff detection (new, resolved, unchanged)
  - Scan history tracking (SQLite)
  - Alert triggers on new findings
  - Configurable scan profiles
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional


@dataclass
class ScanProfile:
    """Configuration for a scheduled scan."""
    name: str
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    org_name: str = ""
    seed_file: str = ""
    interval_minutes: int = 1440   # default: 24 hours
    skip_ports: bool = False
    skip_http: bool = False
    skip_enrichment: bool = False
    skip_vuln_assessment: bool = False
    skip_nuclei: bool = False
    skip_cred_test: bool = False
    json_output: str = ""
    html_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domains": self.domains,
            "ips": self.ips,
            "asns": self.asns,
            "cidrs": self.cidrs,
            "org_name": self.org_name,
            "interval_minutes": self.interval_minutes,
        }


@dataclass
class ScanDiff:
    """Diff between two scan results."""
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    unchanged_findings: list[dict] = field(default_factory=list)
    new_assets: list[dict] = field(default_factory=list)
    removed_assets: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_findings or self.resolved_findings
            or self.new_assets or self.removed_assets
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
            "unchanged_findings": len(self.unchanged_findings),
            "new_assets": len(self.new_assets),
            "removed_assets": len(self.removed_assets),
            "has_changes": self.has_changes,
        }


class ScanScheduler:
    """Manage scheduled EASM scans with history and diff detection."""

    def __init__(
        self,
        db_path: str = "easm_scheduler.db",
        verbose: bool = False,
    ) -> None:
        self.db_path = db_path
        self.verbose = verbose
        self._init_db()

    # ── Database setup ───────────────────────────────────────

    def _init_db(self) -> None:
        """Initialize the scheduler database."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_name TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                duration_seconds REAL,
                total_assets INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                summary_json TEXT,
                findings_hash TEXT
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS finding_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_hash TEXT NOT NULL,
                rule_id TEXT,
                severity TEXT,
                asset_value TEXT,
                name TEXT,
                finding_json TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_history(id)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS asset_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                asset_hash TEXT NOT NULL,
                asset_type TEXT,
                value TEXT,
                FOREIGN KEY (scan_id) REFERENCES scan_history(id)
            )
        """)

        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_finding_hash
            ON finding_snapshots(scan_id, finding_hash)
        """)

        conn.commit()
        conn.close()

    # ── Public API ──────────────────────────────────────────

    def record_scan(
        self,
        profile_name: str,
        findings: list[dict],
        assets: list[dict],
        summary: dict,
        duration: float,
    ) -> int:
        """Record a scan result and return scan ID."""
        now = datetime.now(timezone.utc).isoformat()
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Compute overall findings hash for quick diff
        all_hashes = sorted(
            self._finding_hash(f) for f in findings
        )
        findings_hash = hashlib.sha256(
            "|".join(all_hashes).encode()
        ).hexdigest()[:32]

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            INSERT INTO scan_history
            (profile_name, scan_time, duration_seconds,
             total_assets, total_findings, critical_count,
             high_count, summary_json, findings_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile_name, now, duration,
            len(assets), len(findings),
            sev_counts.get("CRITICAL", 0),
            sev_counts.get("HIGH", 0),
            json.dumps(summary, default=str),
            findings_hash,
        ))
        scan_id = c.lastrowid

        # Record finding snapshots
        for f in findings:
            fh = self._finding_hash(f)
            c.execute("""
                INSERT INTO finding_snapshots
                (scan_id, finding_hash, rule_id, severity,
                 asset_value, name, finding_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id, fh,
                f.get("rule_id", ""),
                f.get("severity", ""),
                f.get("asset_value", ""),
                f.get("name", ""),
                json.dumps(f, default=str),
            ))

        # Record asset snapshots
        for a in assets:
            ah = self._asset_hash(a)
            c.execute("""
                INSERT INTO asset_snapshots
                (scan_id, asset_hash, asset_type, value)
                VALUES (?, ?, ?, ?)
            """, (
                scan_id, ah,
                a.get("asset_type", ""),
                a.get("value", ""),
            ))

        conn.commit()
        conn.close()

        self._vprint(
            f"    [scheduler] recorded scan #{scan_id} "
            f"({len(findings)} findings, {len(assets)} assets)"
        )
        return scan_id

    def compute_diff(
        self,
        profile_name: str,
        current_findings: list[dict],
        current_assets: list[dict],
    ) -> ScanDiff:
        """Compute diff between current scan and last recorded scan."""
        diff = ScanDiff()

        # Get previous scan
        prev = self._get_last_scan(profile_name)
        if not prev:
            # First scan -- everything is new
            diff.new_findings = current_findings
            diff.new_assets = [
                {"asset_type": a.get("asset_type", ""),
                 "value": a.get("value", "")}
                for a in current_assets
            ]
            return diff

        prev_scan_id = prev[0]

        # Get previous finding hashes
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            SELECT finding_hash, finding_json
            FROM finding_snapshots WHERE scan_id = ?
        """, (prev_scan_id,))
        prev_findings: dict[str, dict] = {}
        for row in c.fetchall():
            prev_findings[row[0]] = json.loads(row[1])

        c.execute("""
            SELECT asset_hash, asset_type, value
            FROM asset_snapshots WHERE scan_id = ?
        """, (prev_scan_id,))
        prev_assets: set[str] = set()
        prev_asset_data: dict[str, dict] = {}
        for row in c.fetchall():
            prev_assets.add(row[0])
            prev_asset_data[row[0]] = {
                "asset_type": row[1], "value": row[2],
            }

        conn.close()

        # Diff findings
        current_hashes: dict[str, dict] = {}
        for f in current_findings:
            fh = self._finding_hash(f)
            current_hashes[fh] = f

        for fh, finding in current_hashes.items():
            if fh in prev_findings:
                diff.unchanged_findings.append(finding)
            else:
                diff.new_findings.append(finding)

        for fh, finding in prev_findings.items():
            if fh not in current_hashes:
                diff.resolved_findings.append(finding)

        # Diff assets
        current_asset_hashes: set[str] = set()
        current_asset_data: dict[str, dict] = {}
        for a in current_assets:
            ah = self._asset_hash(a)
            current_asset_hashes.add(ah)
            current_asset_data[ah] = {
                "asset_type": a.get("asset_type", ""),
                "value": a.get("value", ""),
            }

        for ah in current_asset_hashes - prev_assets:
            diff.new_assets.append(current_asset_data[ah])

        for ah in prev_assets - current_asset_hashes:
            diff.removed_assets.append(prev_asset_data[ah])

        self._vprint(
            f"    [scheduler] diff: {len(diff.new_findings)} new, "
            f"{len(diff.resolved_findings)} resolved, "
            f"{len(diff.unchanged_findings)} unchanged"
        )

        return diff

    def get_history(
        self,
        profile_name: str,
        limit: int = 10,
    ) -> list[dict]:
        """Get scan history for a profile."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("""
            SELECT id, scan_time, duration_seconds,
                   total_assets, total_findings,
                   critical_count, high_count
            FROM scan_history
            WHERE profile_name = ?
            ORDER BY scan_time DESC
            LIMIT ?
        """, (profile_name, limit))

        history = []
        for row in c.fetchall():
            history.append({
                "scan_id": row[0],
                "scan_time": row[1],
                "duration": row[2],
                "total_assets": row[3],
                "total_findings": row[4],
                "critical": row[5],
                "high": row[6],
            })

        conn.close()
        return history

    def run_scheduled(
        self,
        profile: ScanProfile,
        scan_callback: Callable,
        on_new_findings: Optional[Callable] = None,
        max_runs: int = 0,
    ) -> None:
        """Run scans on a schedule. Blocks until interrupted."""
        runs = 0
        self._vprint(
            f"    [scheduler] starting scheduled scans "
            f"for '{profile.name}' "
            f"every {profile.interval_minutes} minute(s)"
        )

        while True:
            if max_runs > 0 and runs >= max_runs:
                break

            self._vprint(
                f"    [scheduler] starting scan run "
                f"#{runs + 1}..."
            )
            start = time.time()

            try:
                # Run the scan via callback
                result = scan_callback(profile)
                duration = time.time() - start

                findings = result.get("findings", [])
                assets = result.get("assets", [])
                summary = result.get("summary", {})

                # Compute diff
                diff = self.compute_diff(
                    profile.name, findings, assets,
                )

                # Record scan
                self.record_scan(
                    profile.name, findings, assets,
                    summary, duration,
                )

                # Trigger on new findings
                if diff.new_findings and on_new_findings:
                    on_new_findings(diff.new_findings, summary)

                self._vprint(
                    f"    [scheduler] scan complete in "
                    f"{duration:.1f}s "
                    f"({len(diff.new_findings)} new findings)"
                )

            except Exception as exc:
                self._vprint(
                    f"    [scheduler] scan error: {exc}"
                )

            runs += 1

            if max_runs > 0 and runs >= max_runs:
                break

            # Wait for next interval
            self._vprint(
                f"    [scheduler] next scan in "
                f"{profile.interval_minutes} minute(s)"
            )
            time.sleep(profile.interval_minutes * 60)

    # ── Helpers ──────────────────────────────────────────────

    def _get_last_scan(
        self, profile_name: str,
    ) -> Optional[tuple]:
        """Get the most recent scan for a profile."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT id, scan_time, findings_hash
            FROM scan_history
            WHERE profile_name = ?
            ORDER BY scan_time DESC LIMIT 1
        """, (profile_name,))
        row = c.fetchone()
        conn.close()
        return row

    @staticmethod
    def _finding_hash(finding: dict) -> str:
        """Compute a stable hash for a finding."""
        key = (
            f"{finding.get('rule_id', '')}:"
            f"{finding.get('asset_value', '')}:"
            f"{finding.get('severity', '')}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def _asset_hash(asset: dict) -> str:
        """Compute a stable hash for an asset."""
        key = (
            f"{asset.get('asset_type', '')}:"
            f"{asset.get('value', '')}"
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
