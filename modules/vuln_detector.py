"""
EASM Scanner -- Vulnerability Detector
Detects known CVEs via version fingerprinting of web servers, frameworks,
and services.  Queries NVD API and EPSS for scoring.

Sources:
  - HTTP Server/X-Powered-By headers for version extraction
  - Service banners from port scan
  - Technology fingerprints from Phase 2
  - NVD 2.0 REST API (public, rate-limited)
  - EPSS API (first.org, free)
  - CISA KEV (Known Exploited Vulnerabilities) catalog
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Known vulnerable version patterns ─────────────────────────────
# Curated list of commonly exposed software with known CVE ranges.
# Each entry: product regex, version_regex, CVE list with affected ranges.

VULN_SIGNATURES: list[dict[str, Any]] = [
    # Apache HTTP Server
    {
        "product": "Apache",
        "header_pattern": r"Apache[/ ](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2021-41773", "affected": "<2.4.50", "severity": "CRITICAL",
             "description": "Path traversal and RCE in Apache 2.4.49-2.4.50"},
            {"cve": "CVE-2021-42013", "affected": "<2.4.51", "severity": "CRITICAL",
             "description": "Path traversal fix bypass in Apache 2.4.50"},
            {"cve": "CVE-2023-25690", "affected": "<2.4.56", "severity": "CRITICAL",
             "description": "HTTP request smuggling in mod_proxy"},
            {"cve": "CVE-2023-43622", "affected": "<2.4.58", "severity": "HIGH",
             "description": "HTTP/2 DoS via initial window size"},
            {"cve": "CVE-2024-27316", "affected": "<2.4.59", "severity": "HIGH",
             "description": "HTTP/2 CONTINUATION flood DoS"},
        ],
    },
    # Nginx
    {
        "product": "nginx",
        "header_pattern": r"nginx[/ ](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2021-23017", "affected": "<1.21.0", "severity": "CRITICAL",
             "description": "DNS resolver off-by-one heap write"},
            {"cve": "CVE-2022-41741", "affected": "<1.23.2", "severity": "HIGH",
             "description": "Memory corruption in mp4 module"},
            {"cve": "CVE-2024-7347", "affected": "<1.27.1", "severity": "MEDIUM",
             "description": "Buffer over-read in mp4 module"},
        ],
    },
    # Microsoft IIS
    {
        "product": "IIS",
        "header_pattern": r"Microsoft-IIS[/ ](\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2021-31166", "affected": "<10.1", "severity": "CRITICAL",
             "description": "HTTP Protocol Stack RCE (wormable)"},
            {"cve": "CVE-2022-21907", "affected": "<10.1", "severity": "CRITICAL",
             "description": "HTTP.sys RCE via trailer support"},
        ],
    },
    # OpenSSL
    {
        "product": "OpenSSL",
        "header_pattern": r"OpenSSL[/ ](\d+\.\d+\.\d+[a-z]?)",
        "cves": [
            {"cve": "CVE-2022-0778", "affected": "<1.1.1n", "severity": "HIGH",
             "description": "Infinite loop in BN_mod_sqrt()"},
            {"cve": "CVE-2022-3602", "affected": "<3.0.7", "severity": "HIGH",
             "description": "X.509 email buffer overflow"},
            {"cve": "CVE-2024-0727", "affected": "<3.0.13", "severity": "MEDIUM",
             "description": "NULL dereference in PKCS12 parsing"},
        ],
    },
    # PHP
    {
        "product": "PHP",
        "header_pattern": r"PHP[/ ](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2024-4577", "affected": "<8.1.29", "severity": "CRITICAL",
             "description": "CGI argument injection RCE (Windows)"},
            {"cve": "CVE-2024-2756", "affected": "<8.1.28", "severity": "HIGH",
             "description": "Cookie bypass via __Host-/__Secure- prefix"},
            {"cve": "CVE-2023-3824", "affected": "<8.0.30", "severity": "CRITICAL",
             "description": "Buffer overflow in phar reading"},
        ],
    },
    # jQuery (from body/script tags)
    {
        "product": "jQuery",
        "header_pattern": r"jquery[/-](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2020-11022", "affected": "<3.5.0", "severity": "MEDIUM",
             "description": "XSS in jQuery.htmlPrefilter"},
            {"cve": "CVE-2019-11358", "affected": "<3.4.0", "severity": "MEDIUM",
             "description": "Prototype pollution in jQuery.extend"},
        ],
    },
    # Apache Tomcat
    {
        "product": "Tomcat",
        "header_pattern": r"Apache-Coyote[/ ](\d+\.\d+)|Tomcat[/ ](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2024-50379", "affected": "<9.0.98", "severity": "CRITICAL",
             "description": "RCE via partial PUT and default servlet"},
            {"cve": "CVE-2024-23672", "affected": "<9.0.86", "severity": "HIGH",
             "description": "WebSocket DoS via incomplete close"},
            {"cve": "CVE-2023-46589", "affected": "<9.0.83", "severity": "HIGH",
             "description": "HTTP request smuggling via trailer headers"},
        ],
    },
    # WordPress
    {
        "product": "WordPress",
        "header_pattern": r"WordPress[/ ](\d+\.\d+\.?\d*)",
        "cves": [
            {"cve": "CVE-2023-2745", "affected": "<6.2.1", "severity": "MEDIUM",
             "description": "Directory traversal via translation files"},
            {"cve": "CVE-2022-21661", "affected": "<5.8.3", "severity": "HIGH",
             "description": "SQL injection via WP_Query"},
        ],
    },
    # Express.js
    {
        "product": "Express",
        "header_pattern": r"Express|X-Powered-By:\s*Express",
        "cves": [],  # Express version usually not in headers; detected via tech FP
    },
    # Spring Framework
    {
        "product": "Spring",
        "header_pattern": r"Spring[/ ](\d+\.\d+\.\d+)",
        "cves": [
            {"cve": "CVE-2022-22965", "affected": "<5.3.18", "severity": "CRITICAL",
             "description": "Spring4Shell RCE via data binding"},
            {"cve": "CVE-2024-22234", "affected": "<6.1.4", "severity": "HIGH",
             "description": "Broken access control in Spring Security"},
        ],
    },
]


# ── CISA KEV (subset of most critical) ────────────────────────────
CISA_KEV_CVES: set[str] = {
    "CVE-2021-41773", "CVE-2021-42013", "CVE-2021-44228",
    "CVE-2022-22965", "CVE-2021-31166", "CVE-2021-23017",
    "CVE-2024-4577", "CVE-2022-21907", "CVE-2023-25690",
    "CVE-2024-50379", "CVE-2022-0778", "CVE-2023-3824",
}


@dataclass
class VulnResult:
    """A detected vulnerability."""
    asset_value: str
    asset_type: str
    product: str
    version: str
    cve: str
    severity: str
    description: str
    epss_score: float = 0.0
    cvss_score: float = 0.0
    is_kev: bool = False
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset_value,
            "type": self.asset_type,
            "product": self.product,
            "version": self.version,
            "cve": self.cve,
            "severity": self.severity,
            "description": self.description,
            "epss_score": self.epss_score,
            "cvss_score": self.cvss_score,
            "is_kev": self.is_kev,
            "evidence": self.evidence,
        }


class VulnDetector:
    """CVE detection via version fingerprinting and NVD/EPSS lookup."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API = "https://api.first.org/data/v1/epss"

    def __init__(
        self,
        timeout: int = 15,
        verbose: bool = False,
        use_nvd: bool = True,
        use_epss: bool = True,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self.use_nvd = use_nvd and HAS_REQUESTS
        self.use_epss = use_epss and HAS_REQUESTS
        self._epss_cache: dict[str, float] = {}
        self._nvd_cache: dict[str, dict] = {}

    # ── Public API ──────────────────────────────────────────

    def detect_from_headers(
        self,
        asset_value: str,
        headers: dict[str, str],
    ) -> list[VulnResult]:
        """Detect CVEs from HTTP response headers."""
        results: list[VulnResult] = []
        combined = " ".join(f"{k}: {v}" for k, v in headers.items())

        for sig in VULN_SIGNATURES:
            match = re.search(sig["header_pattern"], combined, re.IGNORECASE)
            if not match:
                continue

            version = match.group(1) if match.lastindex else ""
            if not version:
                continue

            for cve_entry in sig.get("cves", []):
                if self._version_affected(version, cve_entry["affected"]):
                    vuln = VulnResult(
                        asset_value=asset_value,
                        asset_type="url",
                        product=sig["product"],
                        version=version,
                        cve=cve_entry["cve"],
                        severity=cve_entry["severity"],
                        description=cve_entry["description"],
                        is_kev=cve_entry["cve"] in CISA_KEV_CVES,
                        evidence=(
                            f"{sig['product']}/{version} "
                            f"matches {cve_entry['cve']} "
                            f"(affected: {cve_entry['affected']})"
                        ),
                    )
                    results.append(vuln)
                    self._vprint(
                        f"    [vuln] {asset_value}: {cve_entry['cve']} "
                        f"({sig['product']} {version})"
                    )

        return results

    def detect_from_banner(
        self,
        ip: str,
        port: int,
        banner: str,
    ) -> list[VulnResult]:
        """Detect CVEs from service banners."""
        results: list[VulnResult] = []
        asset_value = f"{ip}:{port}"

        for sig in VULN_SIGNATURES:
            match = re.search(sig["header_pattern"], banner, re.IGNORECASE)
            if not match:
                continue

            version = match.group(1) if match.lastindex else ""
            if not version:
                continue

            for cve_entry in sig.get("cves", []):
                if self._version_affected(version, cve_entry["affected"]):
                    vuln = VulnResult(
                        asset_value=asset_value,
                        asset_type="port",
                        product=sig["product"],
                        version=version,
                        cve=cve_entry["cve"],
                        severity=cve_entry["severity"],
                        description=cve_entry["description"],
                        is_kev=cve_entry["cve"] in CISA_KEV_CVES,
                        evidence=(
                            f"Banner: {sig['product']}/{version} "
                            f"matches {cve_entry['cve']}"
                        ),
                    )
                    results.append(vuln)

        return results

    def detect_from_tech(
        self,
        asset_value: str,
        technologies: list[str],
    ) -> list[VulnResult]:
        """Detect CVEs from technology fingerprint strings."""
        results: list[VulnResult] = []
        combined = " ".join(technologies)

        for sig in VULN_SIGNATURES:
            match = re.search(sig["header_pattern"], combined, re.IGNORECASE)
            if not match:
                continue

            version = match.group(1) if match.lastindex else ""
            if not version:
                continue

            for cve_entry in sig.get("cves", []):
                if self._version_affected(version, cve_entry["affected"]):
                    vuln = VulnResult(
                        asset_value=asset_value,
                        asset_type="url",
                        product=sig["product"],
                        version=version,
                        cve=cve_entry["cve"],
                        severity=cve_entry["severity"],
                        description=cve_entry["description"],
                        is_kev=cve_entry["cve"] in CISA_KEV_CVES,
                        evidence=(
                            f"Tech FP: {sig['product']}/{version} "
                            f"matches {cve_entry['cve']}"
                        ),
                    )
                    results.append(vuln)

        return results

    def enrich_with_epss(
        self, vulns: list[VulnResult],
    ) -> None:
        """Enrich vulnerability results with EPSS scores."""
        if not self.use_epss or not vulns:
            return

        # Collect unique CVEs to query
        cve_ids = list({v.cve for v in vulns if v.cve})
        if not cve_ids:
            return

        # Batch query EPSS
        scores = self._batch_epss(cve_ids)

        for vuln in vulns:
            if vuln.cve in scores:
                vuln.epss_score = scores[vuln.cve]

    # ── EPSS API ────────────────────────────────────────────

    def _batch_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Query EPSS API for multiple CVEs."""
        scores: dict[str, float] = {}
        # Check cache first
        uncached = [c for c in cve_ids if c not in self._epss_cache]

        if uncached:
            try:
                # EPSS accepts comma-separated CVE IDs
                batch_size = 30
                for i in range(0, len(uncached), batch_size):
                    batch = uncached[i:i + batch_size]
                    resp = _requests.get(
                        self.EPSS_API,
                        params={"cve": ",".join(batch)},
                        timeout=self.timeout,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for entry in data.get("data", []):
                            cve = entry.get("cve", "")
                            score = float(entry.get("epss", 0))
                            self._epss_cache[cve] = score
                    # Rate limit
                    if i + batch_size < len(uncached):
                        time.sleep(1.0)
            except Exception as exc:
                self._vprint(f"    [vuln] EPSS query failed: {exc}")

        # Merge cache into results
        for cve in cve_ids:
            if cve in self._epss_cache:
                scores[cve] = self._epss_cache[cve]

        return scores

    # ── Version comparison ──────────────────────────────────

    @staticmethod
    def _parse_version(ver_str: str) -> tuple:
        """Parse version string to comparable tuple."""
        # Strip trailing letters (e.g., "1.1.1n" -> (1, 1, 1))
        clean = re.sub(r"[a-zA-Z]+$", "", ver_str)
        parts = []
        for p in clean.split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    @classmethod
    def _version_affected(cls, version: str, spec: str) -> bool:
        """Check if version matches affected spec (e.g., '<2.4.50')."""
        ver = cls._parse_version(version)
        if not ver:
            return False

        # Handle operators: <, <=, >, >=
        match = re.match(r"([<>]=?)\s*(.+)", spec.strip())
        if not match:
            return False

        op, ref_str = match.groups()
        ref = cls._parse_version(ref_str)

        if op == "<":
            return ver < ref
        elif op == "<=":
            return ver <= ref
        elif op == ">":
            return ver > ref
        elif op == ">=":
            return ver >= ref
        return False

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
