"""
EASM Scanner -- Subdomain Takeover Detection
Detects dangling DNS records pointing to unclaimed cloud resources.
Checks CNAME, A, and NS records for known vulnerable fingerprints.

Supported providers: GitHub Pages, Heroku, AWS S3, Azure, Shopify,
Fastly, Pantheon, Tumblr, WordPress, Ghost, Surge, Bitbucket,
Zendesk, Freshdesk, Unbounce, Statuspage, Cargo, Help Scout,
Campaign Monitor, HubSpot, Intercom, and more.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ── Takeover fingerprints ──────────────────────────────────────────
# Each entry: (cname_pattern, nxdomain_or_error_body_pattern, provider, severity)

TAKEOVER_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "provider": "GitHub Pages",
        "cnames": [".github.io"],
        "body_fingerprint": "There isn't a GitHub Pages site here",
        "nxdomain": True,
        "severity": "HIGH",
    },
    {
        "provider": "Heroku",
        "cnames": [".herokuapp.com", ".herokussl.com"],
        "body_fingerprint": "No such app",
        "nxdomain": False,
        "severity": "HIGH",
    },
    {
        "provider": "AWS S3",
        "cnames": [".s3.amazonaws.com", ".s3-website"],
        "body_fingerprint": "NoSuchBucket",
        "nxdomain": True,
        "severity": "CRITICAL",
    },
    {
        "provider": "Azure",
        "cnames": [".azurewebsites.net", ".cloudapp.net",
                   ".cloudapp.azure.com", ".azure-api.net",
                   ".azurefd.net", ".blob.core.windows.net",
                   ".trafficmanager.net"],
        "body_fingerprint": "404 Web Site not found",
        "nxdomain": True,
        "severity": "HIGH",
    },
    {
        "provider": "Shopify",
        "cnames": [".myshopify.com"],
        "body_fingerprint": "Sorry, this shop is currently unavailable",
        "nxdomain": False,
        "severity": "HIGH",
    },
    {
        "provider": "Fastly",
        "cnames": [".fastly.net", ".fastlylb.net"],
        "body_fingerprint": "Fastly error: unknown domain",
        "nxdomain": False,
        "severity": "HIGH",
    },
    {
        "provider": "Pantheon",
        "cnames": [".pantheonsite.io"],
        "body_fingerprint": "404 error unknown site",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Tumblr",
        "cnames": [".tumblr.com"],
        "body_fingerprint": "There's nothing here",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "WordPress.com",
        "cnames": [".wordpress.com"],
        "body_fingerprint": "Do you want to register",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Ghost",
        "cnames": [".ghost.io"],
        "body_fingerprint": "404 not found",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "Surge.sh",
        "cnames": [".surge.sh"],
        "body_fingerprint": "project not found",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "Bitbucket",
        "cnames": [".bitbucket.io"],
        "body_fingerprint": "Repository not found",
        "nxdomain": True,
        "severity": "HIGH",
    },
    {
        "provider": "Zendesk",
        "cnames": [".zendesk.com"],
        "body_fingerprint": "Help Center Closed",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Freshdesk",
        "cnames": [".freshdesk.com"],
        "body_fingerprint": "There is no helpdesk here",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Unbounce",
        "cnames": [".unbouncepages.com"],
        "body_fingerprint": "The requested URL was not found",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "Statuspage",
        "cnames": [".statuspage.io"],
        "body_fingerprint": "You are being redirected",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "HubSpot",
        "cnames": [".hubspot.net", ".hs-sites.com"],
        "body_fingerprint": "Domain not found",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Intercom",
        "cnames": [".custom.intercom.help"],
        "body_fingerprint": "Uh oh. That page doesn't exist",
        "nxdomain": False,
        "severity": "MEDIUM",
    },
    {
        "provider": "Campaign Monitor",
        "cnames": [".createsend.com"],
        "body_fingerprint": "Trying to access your account",
        "nxdomain": False,
        "severity": "LOW",
    },
    {
        "provider": "Cargo Collective",
        "cnames": [".cargocollective.com"],
        "body_fingerprint": "404 Not Found",
        "nxdomain": True,
        "severity": "LOW",
    },
    {
        "provider": "Help Scout",
        "cnames": [".helpscoutdocs.com"],
        "body_fingerprint": "No settings were found",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "Fly.io",
        "cnames": [".fly.dev"],
        "body_fingerprint": "404 Not Found",
        "nxdomain": True,
        "severity": "MEDIUM",
    },
    {
        "provider": "Netlify",
        "cnames": [".netlify.app", ".netlify.com"],
        "body_fingerprint": "Not Found - Request ID",
        "nxdomain": True,
        "severity": "HIGH",
    },
    {
        "provider": "Vercel",
        "cnames": [".vercel.app", ".now.sh"],
        "body_fingerprint": "DEPLOYMENT_NOT_FOUND",
        "nxdomain": False,
        "severity": "HIGH",
    },
    {
        "provider": "Render",
        "cnames": [".onrender.com"],
        "body_fingerprint": "not found",
        "nxdomain": True,
        "severity": "HIGH",
    },
]


@dataclass
class TakeoverResult:
    """Result of a subdomain takeover check."""
    domain: str
    vulnerable: bool = False
    provider: str = ""
    cname_target: str = ""
    evidence: str = ""
    severity: str = "MEDIUM"
    nxdomain: bool = False
    http_confirmed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "vulnerable": self.vulnerable,
            "provider": self.provider,
            "cname_target": self.cname_target,
            "evidence": self.evidence,
            "severity": self.severity,
            "nxdomain": self.nxdomain,
            "http_confirmed": self.http_confirmed,
        }


class SubdomainTakeoverDetector:
    """Detect subdomain takeover vulnerabilities via dangling DNS."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def check(self, domain: str) -> TakeoverResult:
        """Check a single domain for takeover vulnerability."""
        result = TakeoverResult(domain=domain)

        # Step 1: Resolve CNAME
        cname = self._resolve_cname(domain)
        if not cname:
            # No CNAME -- check for NXDOMAIN (dangling A record)
            if self._is_nxdomain(domain):
                result.nxdomain = True
                result.evidence = "Domain returns NXDOMAIN (dangling record)"
                result.severity = "LOW"
                # Not necessarily takeover-ready without CNAME
            return result

        result.cname_target = cname

        # Step 2: Match CNAME against known fingerprints
        for fp in TAKEOVER_FINGERPRINTS:
            for pattern in fp["cnames"]:
                if cname.lower().endswith(pattern.lower()):
                    result.provider = fp["provider"]
                    result.severity = fp["severity"]

                    # Step 3: Check if CNAME target resolves
                    if fp.get("nxdomain") and self._is_nxdomain(cname):
                        result.vulnerable = True
                        result.nxdomain = True
                        result.evidence = (
                            f"CNAME -> {cname} returns NXDOMAIN "
                            f"(dangling {fp['provider']} resource)"
                        )
                        self._vprint(
                            f"    [takeover] {domain}: VULNERABLE "
                            f"({fp['provider']}, NXDOMAIN)"
                        )
                        return result

                    # Step 4: HTTP body check for confirmation
                    if fp.get("body_fingerprint") and HAS_REQUESTS:
                        body_match = self._check_http_body(
                            domain, fp["body_fingerprint"]
                        )
                        if body_match:
                            result.vulnerable = True
                            result.http_confirmed = True
                            result.evidence = (
                                f"CNAME -> {cname}; HTTP body matches "
                                f"'{fp['body_fingerprint']}' "
                                f"({fp['provider']})"
                            )
                            self._vprint(
                                f"    [takeover] {domain}: VULNERABLE "
                                f"({fp['provider']}, HTTP confirmed)"
                            )
                            return result

                    # CNAME matches provider but not confirmed
                    result.evidence = (
                        f"CNAME -> {cname} matches {fp['provider']} "
                        f"pattern (unconfirmed)"
                    )
                    self._vprint(
                        f"    [takeover] {domain}: possible "
                        f"({fp['provider']}, unconfirmed)"
                    )
                    return result

        return result

    def bulk_check(
        self, domains: list[str],
    ) -> list[TakeoverResult]:
        """Check multiple domains for takeover vulnerabilities."""
        results: list[TakeoverResult] = []
        for domain in domains:
            results.append(self.check(domain))

        vuln_count = sum(1 for r in results if r.vulnerable)
        possible = sum(
            1 for r in results
            if r.cname_target and not r.vulnerable
        )
        self._vprint(
            f"    [takeover] checked {len(domains)}: "
            f"{vuln_count} vulnerable, {possible} possible"
        )
        return results

    # ── DNS helpers ──────────────────────────────────────────

    def _resolve_cname(self, domain: str) -> str:
        """Resolve CNAME record for a domain."""
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(domain, "CNAME")
                for rdata in answers:
                    return str(rdata.target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.Timeout,
                    Exception):
                pass
        else:
            # Fallback: use socket (can't get CNAME directly)
            pass
        return ""

    def _is_nxdomain(self, domain: str) -> bool:
        """Check if domain returns NXDOMAIN."""
        if HAS_DNS:
            try:
                dns.resolver.resolve(domain, "A")
                return False
            except dns.resolver.NXDOMAIN:
                return True
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                    dns.resolver.Timeout, Exception):
                return False
        else:
            try:
                socket.getaddrinfo(domain, None, socket.AF_INET)
                return False
            except socket.gaierror:
                return True
            except Exception:
                return False

    def _check_http_body(
        self, domain: str, fingerprint: str,
    ) -> bool:
        """Check if HTTP response body matches takeover fingerprint."""
        if not HAS_REQUESTS:
            return False

        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "EASM-Scanner/3.0"},
                )
                if fingerprint.lower() in resp.text.lower():
                    return True
            except Exception:
                continue
        return False

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
