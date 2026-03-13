"""
EASM Scanner -- Risk Scoring Engine
Multi-factor risk scoring for discovered assets and vulnerabilities.

Formula:
  Risk = (Severity x 0.40) + (Asset_Criticality x 0.35)
       + (Exploitability x 0.15) + (Temporal x 0.10)

Output: 0-100 normalized score with auto-escalation rules.

Factors:
  - Severity: CVSS base or rule severity (CRITICAL=10, HIGH=8, MEDIUM=5, LOW=2, INFO=0)
  - Asset Criticality: internet-facing + data sensitivity + service type
  - Exploitability: EPSS score, CISA KEV, public exploit, attack complexity
  - Temporal: days since disclosure, patch availability
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ── Severity weights ───────────────────────────────────────────────

SEVERITY_SCORE: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# ── Asset criticality factors ─────────────────────────────────────

ASSET_CRITICALITY: dict[str, float] = {
    # By asset type
    "url": 8.0,           # Web application (internet-facing)
    "domain": 7.0,        # Domain (brand, email)
    "ip": 6.0,            # IP address
    "port": 7.0,          # Open port (service)
    "certificate": 5.0,   # TLS certificate
    "asn": 3.0,           # ASN (infrastructure)
    "cidr": 3.0,          # CIDR block
    "cloud_bucket": 9.0,  # Cloud storage
}

# Service criticality multipliers
SERVICE_MULTIPLIER: dict[str, float] = {
    # Database services
    "mysql": 1.5,
    "postgres": 1.5,
    "mssql": 1.5,
    "oracle": 1.5,
    "mongodb": 1.5,
    "redis": 1.3,
    "elasticsearch": 1.3,
    # Management services
    "ssh": 1.2,
    "rdp": 1.4,
    "vnc": 1.3,
    "telnet": 1.4,
    "smb": 1.4,
    # Web services
    "http": 1.0,
    "https": 1.0,
    # Other
    "ftp": 1.2,
    "snmp": 1.2,
    "dns": 0.8,
    "smtp": 1.1,
}

# Finding category criticality boost
CATEGORY_BOOST: dict[str, float] = {
    "Subdomain Takeover": 2.0,
    "Default Credential": 2.0,
    "CVE": 1.5,
    "Misconfiguration": 1.2,
    "Cloud Storage": 1.8,
    "Exposed Service": 1.3,
    "TLS/SSL": 1.0,
    "Security Header": 0.8,
    "DNS Security": 1.0,
    "Domain": 0.9,
    "Information Disclosure": 0.7,
}


@dataclass
class RiskScore:
    """Computed risk score for a finding."""
    finding_rule_id: str
    asset_value: str
    severity: str
    risk_score: float = 0.0          # 0-100
    risk_level: str = ""             # CRITICAL, HIGH, MEDIUM, LOW, INFO
    severity_component: float = 0.0  # 0-40
    criticality_component: float = 0.0  # 0-35
    exploitability_component: float = 0.0  # 0-15
    temporal_component: float = 0.0  # 0-10
    auto_escalated: bool = False
    escalation_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_rule_id,
            "asset": self.asset_value,
            "severity": self.severity,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "components": {
                "severity": round(self.severity_component, 1),
                "criticality": round(self.criticality_component, 1),
                "exploitability": round(self.exploitability_component, 1),
                "temporal": round(self.temporal_component, 1),
            },
            "auto_escalated": self.auto_escalated,
            "escalation_reason": self.escalation_reason,
        }


class RiskScorer:
    """Multi-factor risk scoring engine for EASM findings."""

    # Weight allocation
    W_SEVERITY = 0.40
    W_CRITICALITY = 0.35
    W_EXPLOITABILITY = 0.15
    W_TEMPORAL = 0.10

    # Risk thresholds
    THRESHOLD_CRITICAL = 80
    THRESHOLD_HIGH = 60
    THRESHOLD_MEDIUM = 40
    THRESHOLD_LOW = 20

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def score_finding(
        self,
        rule_id: str,
        severity: str,
        asset_value: str,
        asset_type: str = "",
        category: str = "",
        service: str = "",
        epss_score: float = 0.0,
        cvss_score: float = 0.0,
        is_kev: bool = False,
        has_public_exploit: bool = False,
        cve: str = "",
    ) -> RiskScore:
        """Compute risk score for a single finding."""
        result = RiskScore(
            finding_rule_id=rule_id,
            asset_value=asset_value,
            severity=severity.upper(),
        )

        # ── Component 1: Severity (0-40) ────────────────────
        sev_raw = SEVERITY_SCORE.get(severity.upper(), 0.0)
        if cvss_score > 0:
            sev_raw = cvss_score  # Use CVSS if available
        result.severity_component = (sev_raw / 10.0) * 40.0

        # ── Component 2: Asset Criticality (0-35) ───────────
        base_crit = ASSET_CRITICALITY.get(asset_type, 5.0)
        multiplier = SERVICE_MULTIPLIER.get(service.lower(), 1.0) if service else 1.0
        cat_boost = CATEGORY_BOOST.get(category, 1.0)
        crit_raw = min(10.0, base_crit * multiplier * cat_boost)
        result.criticality_component = (crit_raw / 10.0) * 35.0

        # ── Component 3: Exploitability (0-15) ──────────────
        exploit_raw = 0.0

        # EPSS contribution (0-5)
        if epss_score > 0:
            exploit_raw += epss_score * 5.0

        # CISA KEV (known exploited = +4)
        if is_kev:
            exploit_raw += 4.0

        # Public exploit available (+3)
        if has_public_exploit:
            exploit_raw += 3.0

        # CVE exists (+1)
        if cve:
            exploit_raw += 1.0

        exploit_raw = min(10.0, exploit_raw)
        result.exploitability_component = (exploit_raw / 10.0) * 15.0

        # ── Component 4: Temporal (0-10) ────────────────────
        # Simplified: severity-based temporal factor
        # (Full version would consider disclosure date and patch status)
        temporal_raw = 5.0  # baseline
        if is_kev:
            temporal_raw = 9.0  # actively exploited
        elif has_public_exploit:
            temporal_raw = 7.0
        elif cve:
            temporal_raw = 6.0

        result.temporal_component = (temporal_raw / 10.0) * 10.0

        # ── Aggregate ───────────────────────────────────────
        result.risk_score = (
            result.severity_component
            + result.criticality_component
            + result.exploitability_component
            + result.temporal_component
        )
        result.risk_score = min(100.0, result.risk_score)

        # ── Auto-escalation rules ───────────────────────────
        self._apply_escalation(result, severity, category,
                               is_kev, has_public_exploit)

        # ── Risk level ──────────────────────────────────────
        result.risk_level = self._score_to_level(result.risk_score)

        return result

    def score_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[RiskScore]:
        """Score multiple findings. Each dict should have:
        rule_id, severity, asset_value, asset_type, category,
        and optionally: service, epss_score, cvss_score, is_kev,
        has_public_exploit, cve.
        """
        results: list[RiskScore] = []
        for f in findings:
            score = self.score_finding(
                rule_id=f.get("rule_id", ""),
                severity=f.get("severity", "INFO"),
                asset_value=f.get("asset_value", ""),
                asset_type=f.get("asset_type", ""),
                category=f.get("category", ""),
                service=f.get("service", ""),
                epss_score=f.get("epss_score", 0.0),
                cvss_score=f.get("cvss_score", 0.0),
                is_kev=f.get("is_kev", False),
                has_public_exploit=f.get("has_public_exploit", False),
                cve=f.get("cve", ""),
            )
            results.append(score)

        # Sort by risk score descending
        results.sort(key=lambda r: r.risk_score, reverse=True)

        if results:
            levels = {}
            for r in results:
                levels[r.risk_level] = levels.get(r.risk_level, 0) + 1
            self._vprint(
                f"    [risk] scored {len(results)} finding(s): "
                + ", ".join(
                    f"{cnt} {lvl}" for lvl, cnt in
                    sorted(levels.items(),
                           key=lambda x: self._level_rank(x[0]))
                )
            )

        return results

    # ── Escalation rules ────────────────────────────────────

    def _apply_escalation(
        self,
        result: RiskScore,
        severity: str,
        category: str,
        is_kev: bool,
        has_public_exploit: bool,
    ) -> None:
        """Apply auto-escalation rules."""

        # Rule 1: CISA KEV + internet-facing = auto-CRITICAL
        if is_kev and result.risk_score >= 50:
            result.risk_score = max(result.risk_score, 90.0)
            result.auto_escalated = True
            result.escalation_reason = (
                "CISA KEV (actively exploited in the wild)"
            )

        # Rule 2: Default credentials = auto-CRITICAL
        if category == "Default Credential" and severity.upper() == "CRITICAL":
            result.risk_score = max(result.risk_score, 95.0)
            result.auto_escalated = True
            result.escalation_reason = (
                "Default credentials on exposed service"
            )

        # Rule 3: Subdomain takeover confirmed = auto-HIGH
        if category == "Subdomain Takeover" and severity.upper() in (
            "CRITICAL", "HIGH"
        ):
            result.risk_score = max(result.risk_score, 85.0)
            result.auto_escalated = True
            result.escalation_reason = (
                "Confirmed subdomain takeover vulnerability"
            )

        # Rule 4: Public cloud bucket with data = auto-CRITICAL
        if category == "Cloud Storage" and severity.upper() == "CRITICAL":
            result.risk_score = max(result.risk_score, 90.0)
            result.auto_escalated = True
            result.escalation_reason = (
                "Publicly accessible cloud storage with data"
            )

        # Rule 5: CRITICAL CVE with public exploit
        if (severity.upper() == "CRITICAL"
                and has_public_exploit
                and result.risk_score >= 60):
            result.risk_score = max(result.risk_score, 88.0)
            result.auto_escalated = True
            result.escalation_reason = (
                "Critical CVE with publicly available exploit"
            )

    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to risk level."""
        if score >= self.THRESHOLD_CRITICAL:
            return "CRITICAL"
        elif score >= self.THRESHOLD_HIGH:
            return "HIGH"
        elif score >= self.THRESHOLD_MEDIUM:
            return "MEDIUM"
        elif score >= self.THRESHOLD_LOW:
            return "LOW"
        return "INFO"

    @staticmethod
    def _level_rank(level: str) -> int:
        ranks = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return ranks.get(level, 99)

    # ── Statistics ───────────────────────────────────────────

    @staticmethod
    def aggregate_stats(
        scores: list[RiskScore],
    ) -> dict[str, Any]:
        """Compute aggregate risk statistics."""
        if not scores:
            return {"count": 0, "avg_score": 0, "max_score": 0}

        risk_scores = [s.risk_score for s in scores]
        levels = {}
        for s in scores:
            levels[s.risk_level] = levels.get(s.risk_level, 0) + 1

        escalated = sum(1 for s in scores if s.auto_escalated)

        return {
            "count": len(scores),
            "avg_score": round(sum(risk_scores) / len(risk_scores), 1),
            "max_score": round(max(risk_scores), 1),
            "min_score": round(min(risk_scores), 1),
            "by_level": levels,
            "auto_escalated": escalated,
        }

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
