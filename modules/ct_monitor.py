"""
EASM Scanner — Certificate Transparency Monitor
Discovers domains from CT logs via crt.sh.
Provides certificate metadata (issuer, validity, SANs) for attribution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


@dataclass
class CertInfo:
    """Certificate metadata from CT logs."""
    serial: str = ""
    issuer: str = ""
    common_name: str = ""
    sans: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    entry_timestamp: str = ""
    id: int = 0


class CTMonitor:
    """Certificate Transparency log monitor via crt.sh."""

    CRTSH_URL = "https://crt.sh"

    def __init__(
        self,
        timeout: int = 30,
        include_expired: bool = False,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.include_expired = include_expired
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def search_domain(self, domain: str) -> list[CertInfo]:
        """Search crt.sh for all certificates matching a domain.
        Returns certificate metadata including SANs."""
        if not _HAS_REQUESTS:
            self._vprint("    [ct] skipped — requests not installed")
            return []

        certs: list[CertInfo] = []
        try:
            resp = _requests.get(
                f"{self.CRTSH_URL}/?q=%.{domain}&output=json",
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                self._vprint(f"    [ct] HTTP {resp.status_code} for {domain}")
                return []

            data = resp.json()
            seen_serials: set[str] = set()

            for entry in data:
                serial = entry.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)

                name_value = entry.get("name_value", "")
                sans = [
                    s.strip().lower()
                    for s in name_value.split("\n")
                    if s.strip() and "*" not in s
                ]

                not_before = entry.get("not_before", "")
                not_after = entry.get("not_after", "")

                # Skip expired certs unless requested
                if not self.include_expired and not_after:
                    try:
                        exp = datetime.fromisoformat(
                            not_after.replace("T", " ").split(".")[0]
                        )
                        if exp < datetime.now():
                            continue
                    except (ValueError, TypeError):
                        pass

                ci = CertInfo(
                    serial=serial,
                    issuer=entry.get("issuer_name", ""),
                    common_name=entry.get("common_name", ""),
                    sans=sans,
                    not_before=not_before,
                    not_after=not_after,
                    entry_timestamp=entry.get("entry_timestamp", ""),
                    id=entry.get("id", 0),
                )
                certs.append(ci)

            self._vprint(
                f"    [ct] {domain}: {len(certs)} certificate(s), "
                f"{sum(len(c.sans) for c in certs)} SAN(s)"
            )

        except Exception as exc:
            self._vprint(f"    [ct] error for {domain}: {exc}")

        return certs

    def extract_domains(self, domain: str) -> set[str]:
        """Extract all unique domain names from CT logs for a root domain."""
        certs = self.search_domain(domain)
        domains: set[str] = set()

        for cert in certs:
            cn = cert.common_name.lower().strip()
            if cn and "*" not in cn:
                domains.add(cn)
            for san in cert.sans:
                san = san.lower().strip()
                if san and "*" not in san:
                    domains.add(san)

        # Filter to related domains (must contain the root domain)
        base = domain.lower()
        related = {
            d for d in domains
            if d == base or d.endswith("." + base)
        }

        # Also capture sibling/associated domains from SANs
        # (these could be related org domains on the same cert)
        associated = domains - related

        self._vprint(
            f"    [ct] {domain}: {len(related)} in-scope, "
            f"{len(associated)} associated domain(s)"
        )

        return related

    def get_associated_domains(self, domain: str) -> set[str]:
        """Get domains that appear on the same certificates as the target
        domain but are NOT subdomains of it (potential org-owned domains)."""
        certs = self.search_domain(domain)
        base = domain.lower()
        associated: set[str] = set()

        for cert in certs:
            all_names: set[str] = set()
            cn = cert.common_name.lower().strip()
            if cn and "*" not in cn:
                all_names.add(cn)
            for san in cert.sans:
                san = san.lower().strip()
                if san and "*" not in san:
                    all_names.add(san)

            # Check if any name is our domain or subdomain
            has_target = any(
                n == base or n.endswith("." + base) for n in all_names
            )
            if has_target:
                for n in all_names:
                    if not (n == base or n.endswith("." + base)):
                        associated.add(n)

        self._vprint(
            f"    [ct] {domain}: {len(associated)} associated domain(s) "
            f"from shared certificates"
        )
        return associated

    def get_cert_details(self, cert_id: int) -> Optional[dict]:
        """Fetch full certificate details from crt.sh by ID."""
        if not _HAS_REQUESTS:
            return None

        try:
            resp = _requests.get(
                f"{self.CRTSH_URL}/?id={cert_id}&output=json",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
