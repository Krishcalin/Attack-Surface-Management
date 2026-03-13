"""
EASM Scanner — Asset Store
SQLite-backed storage for discovered assets and findings.
Lightweight, zero-dependency (stdlib only), upgradable to PostgreSQL later.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.asset import Asset, AssetType
from models.finding import Finding


_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          TEXT PRIMARY KEY,
    asset_type  TEXT NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    sources     TEXT NOT NULL DEFAULT '[]',
    attributes  TEXT NOT NULL DEFAULT '{}',
    parent      TEXT NOT NULL DEFAULT '',
    org         TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 0.0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_uniq
    ON assets(asset_type, value, parent);

CREATE TABLE IF NOT EXISTS findings (
    rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    asset_value TEXT NOT NULL,
    asset_type  TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    cwe         TEXT NOT NULL DEFAULT '',
    cve         TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    attributes  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_finding_asset
    ON findings(asset_value);
CREATE INDEX IF NOT EXISTS idx_finding_sev
    ON findings(severity);
"""


class AssetStore:
    """SQLite-backed asset and finding storage."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ── Assets ──────────────────────────────────────────────

    def upsert_asset(self, asset: Asset) -> Asset:
        """Insert or merge an asset.  On conflict, merge sources and update
        last_seen; keep earliest first_seen."""
        cur = self._conn.execute(
            "SELECT * FROM assets WHERE asset_type=? AND value=? AND parent=?",
            (asset.asset_type, asset.value, asset.parent),
        )
        row = cur.fetchone()
        if row:
            existing = self._row_to_asset(row)
            for s in asset.sources:
                existing.add_source(s)
            merged_attrs = {**existing.attributes, **asset.attributes}
            existing.attributes = merged_attrs
            if asset.confidence > existing.confidence:
                existing.confidence = asset.confidence
            if asset.org_attribution:
                existing.org_attribution = asset.org_attribution
            self._conn.execute(
                """UPDATE assets SET last_seen=?, sources=?, attributes=?,
                   org=?, confidence=? WHERE id=?""",
                (
                    existing.last_seen,
                    json.dumps(existing.sources),
                    json.dumps(existing.attributes),
                    existing.org_attribution,
                    existing.confidence,
                    existing.id,
                ),
            )
            self._conn.commit()
            return existing

        self._conn.execute(
            """INSERT INTO assets
               (id, asset_type, value, first_seen, last_seen,
                sources, attributes, parent, org, confidence)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                asset.id,
                asset.asset_type,
                asset.value,
                asset.first_seen,
                asset.last_seen,
                json.dumps(asset.sources),
                json.dumps(asset.attributes),
                asset.parent,
                asset.org_attribution,
                asset.confidence,
            ),
        )
        self._conn.commit()
        return asset

    def get_assets(
        self,
        asset_type: Optional[str] = None,
        parent: Optional[str] = None,
    ) -> list[Asset]:
        """Retrieve assets, optionally filtered by type and/or parent."""
        sql = "SELECT * FROM assets WHERE 1=1"
        params: list[str] = []
        if asset_type:
            sql += " AND asset_type=?"
            params.append(asset_type)
        if parent is not None:
            sql += " AND parent=?"
            params.append(parent)
        sql += " ORDER BY last_seen DESC"
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def get_asset(self, asset_type: str, value: str,
                  parent: str = "") -> Optional[Asset]:
        cur = self._conn.execute(
            "SELECT * FROM assets WHERE asset_type=? AND value=? AND parent=?",
            (asset_type, value, parent),
        )
        row = cur.fetchone()
        return self._row_to_asset(row) if row else None

    def count_assets(self, asset_type: Optional[str] = None) -> int:
        if asset_type:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM assets WHERE asset_type=?",
                (asset_type,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM assets").fetchone()
        return row[0] if row else 0

    def all_domains(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT value FROM assets WHERE asset_type='domain' "
            "ORDER BY value"
        ).fetchall()
        return [r[0] for r in rows]

    def all_ips(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT value FROM assets WHERE asset_type='ip' "
            "ORDER BY value"
        ).fetchall()
        return [r[0] for r in rows]

    # ── Findings ────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        self._conn.execute(
            """INSERT INTO findings
               (rule_id, name, category, severity, asset_value, asset_type,
                description, recommendation, cwe, cve, evidence,
                first_seen, last_seen, attributes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.rule_id,
                finding.name,
                finding.category,
                finding.severity,
                finding.asset_value,
                finding.asset_type,
                finding.description,
                finding.recommendation,
                finding.cwe,
                finding.cve,
                finding.evidence,
                finding.first_seen,
                finding.last_seen,
                json.dumps(finding.attributes),
            ),
        )
        self._conn.commit()

    def get_findings(
        self,
        severity: Optional[str] = None,
        asset_value: Optional[str] = None,
        category: Optional[str] = None,
    ) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE 1=1"
        params: list[str] = []
        if severity:
            sql += " AND severity=?"
            params.append(severity.upper())
        if asset_value:
            sql += " AND asset_value=?"
            params.append(asset_value)
        if category:
            sql += " AND category=?"
            params.append(category)
        sql += " ORDER BY rowid"
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def count_findings(self, severity: Optional[str] = None) -> int:
        if severity:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity=?",
                (severity.upper(),),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()
        return row[0] if row else 0

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _row_to_asset(row: sqlite3.Row) -> Asset:
        return Asset(
            id=row["id"],
            asset_type=row["asset_type"],
            value=row["value"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            sources=json.loads(row["sources"]),
            attributes=json.loads(row["attributes"]),
            parent=row["parent"],
            org_attribution=row["org"],
            confidence=row["confidence"],
        )

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            rule_id=row["rule_id"],
            name=row["name"],
            category=row["category"],
            severity=row["severity"],
            asset_value=row["asset_value"],
            asset_type=row["asset_type"],
            description=row["description"],
            recommendation=row["recommendation"],
            cwe=row["cwe"],
            cve=row["cve"],
            evidence=row["evidence"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            attributes=json.loads(row["attributes"]),
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> AssetStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
