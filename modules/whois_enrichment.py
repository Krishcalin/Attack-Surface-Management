"""
EASM Scanner -- WHOIS / RDAP Enrichment Module
Queries WHOIS/RDAP for domain registration data: registrant, registrar,
name servers, creation/expiry dates.  Used for attribution and expiry alerts.

Uses RDAP (REST) via rdap.org as primary; falls back to whois CLI if available.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


@dataclass
class WHOISRecord:
    """Parsed WHOIS/RDAP information for a domain."""
    domain: str
    registrar: str = ""
    registrant_org: str = ""
    registrant_name: str = ""
    registrant_email: str = ""
    registrant_country: str = ""
    creation_date: str = ""
    expiry_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    dnssec: str = ""
    raw: str = ""
    source: str = ""              # "rdap" or "whois-cli"

    @property
    def days_to_expiry(self) -> Optional[int]:
        if not self.expiry_date:
            return None
        try:
            exp = datetime.fromisoformat(
                self.expiry_date.replace("Z", "+00:00")
            )
            return (exp - datetime.now(exp.tzinfo)).days
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "registrant_org": self.registrant_org,
            "registrant_name": self.registrant_name,
            "registrant_email": self.registrant_email,
            "registrant_country": self.registrant_country,
            "creation_date": self.creation_date,
            "expiry_date": self.expiry_date,
            "updated_date": self.updated_date,
            "name_servers": self.name_servers,
            "status": self.status,
            "dnssec": self.dnssec,
            "days_to_expiry": self.days_to_expiry,
            "source": self.source,
        }


class WHOISEnrichment:
    """WHOIS/RDAP enrichment for domains."""

    RDAP_BOOTSTRAP = "https://rdap.org/domain/"

    def __init__(
        self,
        timeout: int = 15,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self._cache: dict[str, WHOISRecord] = {}

    # ── Public API ──────────────────────────────────────────

    def lookup(self, domain: str) -> WHOISRecord:
        """Look up WHOIS for a domain.  Tries RDAP first, then whois CLI."""
        domain = self._extract_root(domain)
        if domain in self._cache:
            return self._cache[domain]

        # Try RDAP
        record = self._rdap_lookup(domain)
        if record and (record.registrar or record.registrant_org):
            self._cache[domain] = record
            return record

        # Fallback: whois CLI
        record = self._whois_cli(domain)
        if record:
            self._cache[domain] = record
            return record

        empty = WHOISRecord(domain=domain)
        self._cache[domain] = empty
        return empty

    def bulk_lookup(self, domains: list[str]) -> dict[str, WHOISRecord]:
        """Look up WHOIS for multiple domains (dedupes to root domains)."""
        roots = list({self._extract_root(d) for d in domains if d})
        results: dict[str, WHOISRecord] = {}
        for root in roots:
            results[root] = self.lookup(root)
        self._vprint(f"    [whois] enriched {len(results)} root domain(s)")
        return results

    # ── RDAP ────────────────────────────────────────────────

    def _rdap_lookup(self, domain: str) -> Optional[WHOISRecord]:
        if not _HAS_REQUESTS:
            return None

        try:
            resp = _requests.get(
                f"{self.RDAP_BOOTSTRAP}{domain}",
                timeout=self.timeout,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code != 200:
                self._vprint(
                    f"    [rdap] {domain}: HTTP {resp.status_code}"
                )
                return None

            data = resp.json()
            rec = WHOISRecord(domain=domain, source="rdap")

            # Events
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date = ev.get("eventDate", "")
                if action == "registration":
                    rec.creation_date = date
                elif action == "expiration":
                    rec.expiry_date = date
                elif action == "last changed":
                    rec.updated_date = date

            # Nameservers
            for ns in data.get("nameservers", []):
                name = ns.get("ldhName", "")
                if name:
                    rec.name_servers.append(name.lower())

            # Status
            rec.status = data.get("status", [])

            # Entities (registrar, registrant)
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])
                vcard_items = vcard[1] if len(vcard) > 1 else []

                if "registrar" in roles:
                    rec.registrar = self._vcard_field(
                        vcard_items, "fn"
                    ) or entity.get("handle", "")

                if "registrant" in roles:
                    rec.registrant_name = self._vcard_field(
                        vcard_items, "fn"
                    )
                    rec.registrant_org = self._vcard_field(
                        vcard_items, "org"
                    )
                    rec.registrant_email = self._vcard_field(
                        vcard_items, "email"
                    )
                    # Country from adr
                    for item in vcard_items:
                        if item[0] == "adr" and isinstance(item[3], dict):
                            cc = item[3].get("cc", "")
                            if cc:
                                rec.registrant_country = cc

            # DNSSEC
            sec_dns = data.get("secureDNS", {})
            if sec_dns.get("delegationSigned"):
                rec.dnssec = "signed"
            else:
                rec.dnssec = "unsigned"

            self._vprint(
                f"    [rdap] {domain}: registrar={rec.registrar}, "
                f"org={rec.registrant_org}, "
                f"expiry={rec.expiry_date[:10] if rec.expiry_date else 'N/A'}"
            )
            return rec

        except Exception as exc:
            self._vprint(f"    [rdap] {domain}: error {exc}")
            return None

    @staticmethod
    def _vcard_field(items: list, field_name: str) -> str:
        """Extract a field from a jCard/vCard array."""
        for item in items:
            if isinstance(item, list) and len(item) >= 4:
                if item[0] == field_name:
                    val = item[3]
                    if isinstance(val, list):
                        return " ".join(str(v) for v in val if v).strip()
                    return str(val).strip()
        return ""

    # ── whois CLI fallback ──────────────────────────────────

    def _whois_cli(self, domain: str) -> Optional[WHOISRecord]:
        binary = shutil.which("whois")
        if not binary:
            self._vprint("    [whois-cli] whois binary not found")
            return None

        try:
            proc = subprocess.run(
                [binary, domain],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw = proc.stdout
            if not raw:
                return None

            rec = WHOISRecord(domain=domain, source="whois-cli", raw=raw)
            rec.registrar = self._grep(raw, r"Registrar:\s*(.+)")
            rec.registrant_org = self._grep(
                raw, r"Registrant\s+Organi[sz]ation:\s*(.+)"
            )
            rec.registrant_name = self._grep(
                raw, r"Registrant\s+Name:\s*(.+)"
            )
            rec.registrant_email = self._grep(
                raw, r"Registrant\s+Email:\s*(.+)"
            )
            rec.registrant_country = self._grep(
                raw, r"Registrant\s+Country:\s*(.+)"
            )
            rec.creation_date = self._grep(
                raw, r"Creation\s+Date:\s*(.+)"
            )
            rec.expiry_date = self._grep(
                raw,
                r"(?:Registry\s+Expiry|Expir(?:ation|y))\s+Date:\s*(.+)",
            )
            rec.updated_date = self._grep(
                raw, r"Updated?\s+Date:\s*(.+)"
            )
            rec.dnssec = self._grep(raw, r"DNSSEC:\s*(.+)")

            # Name servers
            for m in re.finditer(
                r"Name\s+Server:\s*(\S+)", raw, re.IGNORECASE
            ):
                ns = m.group(1).lower().rstrip(".")
                if ns not in rec.name_servers:
                    rec.name_servers.append(ns)

            self._vprint(
                f"    [whois-cli] {domain}: registrar={rec.registrar}"
            )
            return rec

        except (subprocess.TimeoutExpired, Exception) as exc:
            self._vprint(f"    [whois-cli] {domain}: error {exc}")
            return None

    @staticmethod
    def _grep(text: str, pattern: str) -> str:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1).strip() if m else ""

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _extract_root(domain: str) -> str:
        """Extract root domain from FQDN (e.g., www.foo.example.com -> example.com)."""
        parts = domain.lower().rstrip(".").split(".")
        if len(parts) <= 2:
            return ".".join(parts)
        # Handle common 2-part TLDs
        two_part_tlds = {
            "co.uk", "co.jp", "co.kr", "co.in", "co.za",
            "com.au", "com.br", "com.cn", "com.mx", "com.sg",
            "org.uk", "net.au", "ac.uk", "gov.uk", "edu.au",
        }
        last_two = ".".join(parts[-2:])
        if last_two in two_part_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
