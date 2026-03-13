"""
EASM Scanner -- Misconfiguration Detector
Detects common web misconfigurations via active HTTP probing:
  - Exposed sensitive files (.env, .git, backups, configs)
  - CORS misconfiguration (wildcard, credential reflection)
  - Open redirect parameters
  - Debug endpoints (Spring Actuator, Django debug, phpinfo)
  - Directory listing
  - Exposed admin panels
  - Exposed API documentation (Swagger/OpenAPI)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Sensitive paths to probe ───────────────────────────────────────

SENSITIVE_PATHS: list[dict[str, Any]] = [
    # Environment / config files
    {"path": "/.env", "fingerprint": ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY"],
     "rule_id": "EASM-MISCONFIG-001", "name": "Exposed .env File",
     "severity": "CRITICAL", "cwe": "CWE-538"},
    {"path": "/.env.local", "fingerprint": ["DB_", "SECRET", "KEY="],
     "rule_id": "EASM-MISCONFIG-001", "name": "Exposed .env.local File",
     "severity": "CRITICAL", "cwe": "CWE-538"},
    {"path": "/.env.production", "fingerprint": ["DB_", "SECRET", "KEY="],
     "rule_id": "EASM-MISCONFIG-001", "name": "Exposed .env.production File",
     "severity": "CRITICAL", "cwe": "CWE-538"},
    {"path": "/.env.backup", "fingerprint": ["DB_", "SECRET", "KEY="],
     "rule_id": "EASM-MISCONFIG-001", "name": "Exposed .env.backup File",
     "severity": "CRITICAL", "cwe": "CWE-538"},

    # Git / version control
    {"path": "/.git/HEAD", "fingerprint": ["ref: refs/"],
     "rule_id": "EASM-MISCONFIG-002", "name": "Exposed .git Directory",
     "severity": "HIGH", "cwe": "CWE-538"},
    {"path": "/.git/config", "fingerprint": ["[core]", "[remote"],
     "rule_id": "EASM-MISCONFIG-002", "name": "Exposed .git/config",
     "severity": "HIGH", "cwe": "CWE-538"},
    {"path": "/.svn/entries", "fingerprint": ["dir", "svn"],
     "rule_id": "EASM-MISCONFIG-002", "name": "Exposed .svn Directory",
     "severity": "HIGH", "cwe": "CWE-538"},

    # Backup files
    {"path": "/backup.sql", "fingerprint": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
     "rule_id": "EASM-MISCONFIG-003", "name": "Exposed Database Backup",
     "severity": "CRITICAL", "cwe": "CWE-530"},
    {"path": "/backup.zip", "fingerprint": None,  # check status only
     "rule_id": "EASM-MISCONFIG-003", "name": "Exposed Backup Archive",
     "severity": "HIGH", "cwe": "CWE-530"},
    {"path": "/dump.sql", "fingerprint": ["CREATE TABLE", "INSERT INTO"],
     "rule_id": "EASM-MISCONFIG-003", "name": "Exposed SQL Dump",
     "severity": "CRITICAL", "cwe": "CWE-530"},
    {"path": "/db.sql", "fingerprint": ["CREATE TABLE", "INSERT INTO"],
     "rule_id": "EASM-MISCONFIG-003", "name": "Exposed Database Dump",
     "severity": "CRITICAL", "cwe": "CWE-530"},

    # Config files
    {"path": "/web.config", "fingerprint": ["<configuration", "connectionString"],
     "rule_id": "EASM-MISCONFIG-004", "name": "Exposed web.config",
     "severity": "HIGH", "cwe": "CWE-538"},
    {"path": "/wp-config.php.bak", "fingerprint": ["DB_NAME", "DB_PASSWORD"],
     "rule_id": "EASM-MISCONFIG-004", "name": "Exposed WordPress Config Backup",
     "severity": "CRITICAL", "cwe": "CWE-538"},
    {"path": "/config.php.bak", "fingerprint": ["password", "database"],
     "rule_id": "EASM-MISCONFIG-004", "name": "Exposed PHP Config Backup",
     "severity": "HIGH", "cwe": "CWE-538"},
    {"path": "/application.yml", "fingerprint": ["spring:", "datasource:", "password:"],
     "rule_id": "EASM-MISCONFIG-004", "name": "Exposed Spring Config",
     "severity": "HIGH", "cwe": "CWE-538"},
    {"path": "/docker-compose.yml", "fingerprint": ["services:", "image:", "ports:"],
     "rule_id": "EASM-MISCONFIG-004", "name": "Exposed Docker Compose",
     "severity": "MEDIUM", "cwe": "CWE-538"},

    # Debug endpoints
    {"path": "/actuator", "fingerprint": ["_links", "self", "href"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed Spring Actuator",
     "severity": "HIGH", "cwe": "CWE-215"},
    {"path": "/actuator/env", "fingerprint": ["propertySources", "activeProfiles"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed Spring Actuator /env",
     "severity": "CRITICAL", "cwe": "CWE-215"},
    {"path": "/actuator/health", "fingerprint": ["status", "UP"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed Spring Actuator /health",
     "severity": "INFO", "cwe": "CWE-215"},
    {"path": "/debug", "fingerprint": ["Traceback", "DEBUG", "settings.py"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Debug Mode Enabled",
     "severity": "HIGH", "cwe": "CWE-215"},
    {"path": "/phpinfo.php", "fingerprint": ["phpinfo()", "PHP Version", "Configuration"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed phpinfo()",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/info.php", "fingerprint": ["phpinfo()", "PHP Version"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed phpinfo()",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/server-status", "fingerprint": ["Apache Server Status", "Total accesses"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed Apache Server-Status",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/server-info", "fingerprint": ["Apache Server Information"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed Apache Server-Info",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/__debug__/", "fingerprint": ["djdt", "django", "debug toolbar"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Django Debug Toolbar Exposed",
     "severity": "HIGH", "cwe": "CWE-215"},
    {"path": "/elmah.axd", "fingerprint": ["Error Log", "ELMAH"],
     "rule_id": "EASM-MISCONFIG-005", "name": "Exposed ELMAH Error Log",
     "severity": "HIGH", "cwe": "CWE-215"},

    # Admin panels
    {"path": "/admin", "fingerprint": None,  # 200 status check
     "rule_id": "EASM-MISCONFIG-006", "name": "Exposed Admin Panel",
     "severity": "MEDIUM", "cwe": "CWE-284"},
    {"path": "/wp-admin/", "fingerprint": ["wp-login", "WordPress"],
     "rule_id": "EASM-MISCONFIG-006", "name": "Exposed WordPress Admin",
     "severity": "LOW", "cwe": "CWE-284"},
    {"path": "/phpmyadmin/", "fingerprint": ["phpMyAdmin", "pma_"],
     "rule_id": "EASM-MISCONFIG-006", "name": "Exposed phpMyAdmin",
     "severity": "HIGH", "cwe": "CWE-284"},
    {"path": "/adminer.php", "fingerprint": ["Adminer", "Login"],
     "rule_id": "EASM-MISCONFIG-006", "name": "Exposed Adminer",
     "severity": "HIGH", "cwe": "CWE-284"},

    # API documentation
    {"path": "/swagger-ui.html", "fingerprint": ["swagger", "api"],
     "rule_id": "EASM-MISCONFIG-007", "name": "Exposed Swagger UI",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/swagger-ui/", "fingerprint": ["swagger", "api"],
     "rule_id": "EASM-MISCONFIG-007", "name": "Exposed Swagger UI",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/api-docs", "fingerprint": ["openapi", "swagger", "paths"],
     "rule_id": "EASM-MISCONFIG-007", "name": "Exposed API Documentation",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/v1/api-docs", "fingerprint": ["openapi", "swagger", "paths"],
     "rule_id": "EASM-MISCONFIG-007", "name": "Exposed API Documentation",
     "severity": "MEDIUM", "cwe": "CWE-200"},
    {"path": "/graphql", "fingerprint": None,  # 200 status check for GraphQL
     "rule_id": "EASM-MISCONFIG-007", "name": "Exposed GraphQL Endpoint",
     "severity": "MEDIUM", "cwe": "CWE-200"},

    # Sensitive info files
    {"path": "/robots.txt", "fingerprint": ["Disallow"],
     "rule_id": "EASM-MISCONFIG-008", "name": "robots.txt Reveals Hidden Paths",
     "severity": "INFO", "cwe": "CWE-200"},
    {"path": "/.well-known/security.txt", "fingerprint": ["Contact"],
     "rule_id": "EASM-MISCONFIG-008", "name": "Security.txt Present",
     "severity": "INFO", "cwe": ""},
    {"path": "/crossdomain.xml", "fingerprint": ["allow-access-from", "domain=\"*\""],
     "rule_id": "EASM-MISCONFIG-008", "name": "Permissive crossdomain.xml",
     "severity": "MEDIUM", "cwe": "CWE-942"},
    {"path": "/clientaccesspolicy.xml",
     "fingerprint": ["allow-from", "domain uri=\"*\""],
     "rule_id": "EASM-MISCONFIG-008", "name": "Permissive clientaccesspolicy.xml",
     "severity": "MEDIUM", "cwe": "CWE-942"},
]


# ── Open redirect parameters ──────────────────────────────────────

REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_uri", "redirectUrl",
    "return", "returnTo", "return_url", "returnUrl",
    "next", "url", "target", "goto", "dest", "destination",
    "continue", "rurl", "out", "view", "login_url",
]

REDIRECT_PAYLOAD = "https://evil.example.com"


@dataclass
class MisconfigResult:
    """A detected misconfiguration."""
    url: str
    rule_id: str
    name: str
    severity: str
    cwe: str = ""
    evidence: str = ""
    category: str = "Misconfiguration"
    path_checked: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "category": self.category,
            "path_checked": self.path_checked,
        }


class MisconfigDetector:
    """Detect web misconfigurations via active HTTP probing."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
        max_paths: int = 50,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self.max_paths = max_paths

    # ── Public API ──────────────────────────────────────────

    def scan_url(self, base_url: str) -> list[MisconfigResult]:
        """Run all misconfig checks against a single URL."""
        if not HAS_REQUESTS:
            self._vprint("    [misconfig] requests library not available")
            return []

        results: list[MisconfigResult] = []

        # 1. Sensitive path probing
        results.extend(self._probe_paths(base_url))

        # 2. CORS misconfiguration
        cors = self._check_cors(base_url)
        if cors:
            results.append(cors)

        # 3. Open redirect
        redir = self._check_open_redirect(base_url)
        if redir:
            results.append(redir)

        # 4. Directory listing
        dirlist = self._check_directory_listing(base_url)
        if dirlist:
            results.append(dirlist)

        return results

    def bulk_scan(
        self, urls: list[str], max_urls: int = 100,
    ) -> list[MisconfigResult]:
        """Scan multiple URLs for misconfigurations."""
        all_results: list[MisconfigResult] = []
        targets = urls[:max_urls]

        for url in targets:
            results = self.scan_url(url)
            all_results.extend(results)

        self._vprint(
            f"    [misconfig] scanned {len(targets)} URL(s), "
            f"found {len(all_results)} issue(s)"
        )
        return all_results

    # ── Path probing ────────────────────────────────────────

    def _probe_paths(self, base_url: str) -> list[MisconfigResult]:
        """Probe for sensitive exposed paths."""
        results: list[MisconfigResult] = []
        paths_checked = 0

        for entry in SENSITIVE_PATHS:
            if paths_checked >= self.max_paths:
                break

            full_url = urljoin(base_url.rstrip("/") + "/", entry["path"].lstrip("/"))
            paths_checked += 1

            try:
                resp = _requests.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                    headers={
                        "User-Agent": "EASM-Scanner/3.0",
                        "Accept": "*/*",
                    },
                )

                if resp.status_code not in (200, 301, 302):
                    continue

                # For redirect responses, only flag admin panels
                if resp.status_code in (301, 302):
                    if entry["rule_id"] == "EASM-MISCONFIG-006":
                        # Admin panel redirects (likely login page)
                        pass
                    else:
                        continue

                # Check body fingerprints
                if entry["fingerprint"]:
                    body_lower = resp.text[:10000].lower()
                    matched = any(
                        fp.lower() in body_lower
                        for fp in entry["fingerprint"]
                    )
                    if not matched:
                        continue

                # Skip INFO-only if no interesting content
                if entry["severity"] == "INFO" and resp.status_code != 200:
                    continue

                result = MisconfigResult(
                    url=full_url,
                    rule_id=entry["rule_id"],
                    name=entry["name"],
                    severity=entry["severity"],
                    cwe=entry.get("cwe", ""),
                    path_checked=entry["path"],
                    evidence=(
                        f"HTTP {resp.status_code} at {entry['path']} "
                        f"({len(resp.content)} bytes)"
                    ),
                )
                results.append(result)
                self._vprint(
                    f"    [misconfig] {base_url}{entry['path']}: "
                    f"{entry['name']} ({entry['severity']})"
                )

            except Exception:
                continue

        return results

    # ── CORS check ──────────────────────────────────────────

    def _check_cors(self, url: str) -> Optional[MisconfigResult]:
        """Check for CORS misconfiguration."""
        try:
            # Send request with a foreign Origin header
            evil_origin = "https://evil.example.com"
            resp = _requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                headers={
                    "User-Agent": "EASM-Scanner/3.0",
                    "Origin": evil_origin,
                },
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get(
                "Access-Control-Allow-Credentials", ""
            ).lower()

            # Critical: reflects arbitrary origin + credentials
            if acao == evil_origin and acac == "true":
                return MisconfigResult(
                    url=url,
                    rule_id="EASM-MISCONFIG-009",
                    name="CORS Origin Reflection with Credentials",
                    severity="CRITICAL",
                    cwe="CWE-942",
                    evidence=(
                        f"ACAO reflects '{evil_origin}' "
                        f"with Allow-Credentials: true"
                    ),
                )

            # High: wildcard with credentials
            if acao == "*" and acac == "true":
                return MisconfigResult(
                    url=url,
                    rule_id="EASM-MISCONFIG-009",
                    name="CORS Wildcard with Credentials",
                    severity="HIGH",
                    cwe="CWE-942",
                    evidence="ACAO: * with Allow-Credentials: true",
                )

            # Medium: reflects arbitrary origin (no credentials)
            if acao == evil_origin:
                return MisconfigResult(
                    url=url,
                    rule_id="EASM-MISCONFIG-009",
                    name="CORS Origin Reflection",
                    severity="MEDIUM",
                    cwe="CWE-942",
                    evidence=f"ACAO reflects arbitrary origin '{evil_origin}'",
                )

            # Low: wildcard (common but noted)
            if acao == "*":
                return MisconfigResult(
                    url=url,
                    rule_id="EASM-MISCONFIG-009",
                    name="CORS Wildcard Origin",
                    severity="LOW",
                    cwe="CWE-942",
                    evidence="Access-Control-Allow-Origin: *",
                )

        except Exception:
            pass

        return None

    # ── Open redirect check ─────────────────────────────────

    def _check_open_redirect(
        self, url: str,
    ) -> Optional[MisconfigResult]:
        """Check for open redirect via common parameter names."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for param in REDIRECT_PARAMS[:8]:  # check first 8 params
            test_url = f"{base}/?{param}={REDIRECT_PAYLOAD}"
            try:
                resp = _requests.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "EASM-Scanner/3.0"},
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        return MisconfigResult(
                            url=url,
                            rule_id="EASM-MISCONFIG-010",
                            name="Open Redirect",
                            severity="MEDIUM",
                            cwe="CWE-601",
                            evidence=(
                                f"Parameter '{param}' redirects to "
                                f"external domain: {location[:100]}"
                            ),
                        )

            except Exception:
                continue

        return None

    # ── Directory listing check ─────────────────────────────

    def _check_directory_listing(
        self, url: str,
    ) -> Optional[MisconfigResult]:
        """Check if directory listing is enabled."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for test_path in ("/", "/images/", "/uploads/", "/assets/",
                          "/static/", "/files/", "/media/"):
            try:
                resp = _requests.get(
                    f"{base}{test_path}",
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": "EASM-Scanner/3.0"},
                )

                if resp.status_code != 200:
                    continue

                body = resp.text[:5000].lower()
                # Common directory listing indicators
                indicators = [
                    "index of /",
                    "directory listing for",
                    "<title>directory listing",
                    "parent directory",
                    "[to parent directory]",
                ]
                if any(ind in body for ind in indicators):
                    return MisconfigResult(
                        url=f"{base}{test_path}",
                        rule_id="EASM-MISCONFIG-010",
                        name="Directory Listing Enabled",
                        severity="MEDIUM",
                        cwe="CWE-548",
                        evidence=f"Directory listing at {test_path}",
                    )

            except Exception:
                continue

        return None

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
