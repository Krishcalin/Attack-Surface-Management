"""
EASM Scanner — ASN Mapper Module
Maps ASNs to IP prefixes and performs IP-to-ASN lookups.
Uses public APIs (RIPE RIS, Team Cymru DNS, BGPView); wraps asnmap if installed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


@dataclass
class ASNInfo:
    """Information about an Autonomous System Number."""
    asn: str                      # e.g. "AS15169"
    name: str = ""                # e.g. "GOOGLE"
    description: str = ""
    country: str = ""
    prefixes: list[str] = None    # CIDR blocks

    def __post_init__(self) -> None:
        if self.prefixes is None:
            self.prefixes = []


@dataclass
class IPASNInfo:
    """ASN information for a given IP address."""
    ip: str
    asn: str = ""
    asn_name: str = ""
    prefix: str = ""
    country: str = ""


class ASNMapper:
    """Map ASNs to IP prefixes and IPs to ASNs."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def get_prefixes(self, asn: str) -> ASNInfo:
        """Get IP prefixes for an ASN.
        Tries asnmap first, then BGPView API, then RIPE RIS."""
        asn = self._normalize_asn(asn)

        # Try asnmap
        result = self._asnmap(asn)
        if result and result.prefixes:
            return result

        # Try BGPView API
        result = self._bgpview_asn(asn)
        if result and result.prefixes:
            return result

        # Try RIPE RIS
        result = self._ripe_ris(asn)
        if result:
            return result

        return ASNInfo(asn=asn)

    def ip_to_asn(self, ip: str) -> IPASNInfo:
        """Look up ASN for a given IP address.
        Tries Team Cymru DNS, then BGPView API."""

        # Team Cymru DNS lookup
        result = self._cymru_dns(ip)
        if result and result.asn:
            return result

        # BGPView API fallback
        result = self._bgpview_ip(ip)
        if result:
            return result

        return IPASNInfo(ip=ip)

    def bulk_ip_to_asn(self, ips: list[str]) -> dict[str, IPASNInfo]:
        """Look up ASN for multiple IPs."""
        results: dict[str, IPASNInfo] = {}
        for ip in ips:
            results[ip] = self.ip_to_asn(ip)
        return results

    # ── asnmap wrapper ──────────────────────────────────────

    def _asnmap(self, asn: str) -> Optional[ASNInfo]:
        binary = shutil.which("asnmap")
        if not binary:
            return None

        try:
            proc = subprocess.run(
                [binary, "-a", asn, "-silent"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            prefixes: list[str] = []
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    prefixes.append(line)

            if prefixes:
                self._vprint(
                    f"    [asnmap] {asn}: {len(prefixes)} prefix(es)"
                )
                return ASNInfo(asn=asn, prefixes=prefixes)

        except (subprocess.TimeoutExpired, Exception) as exc:
            self._vprint(f"    [asnmap] error: {exc}")

        return None

    # ── BGPView API ─────────────────────────────────────────

    def _bgpview_asn(self, asn: str) -> Optional[ASNInfo]:
        if not _HAS_REQUESTS:
            return None

        asn_num = asn.replace("AS", "")
        try:
            resp = _requests.get(
                f"https://api.bgpview.io/asn/{asn_num}/prefixes",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            prefixes: list[str] = []
            for p in data.get("ipv4_prefixes", []):
                prefix = p.get("prefix", "")
                if prefix:
                    prefixes.append(prefix)

            # Get ASN details
            detail_resp = _requests.get(
                f"https://api.bgpview.io/asn/{asn_num}",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            name = ""
            desc = ""
            country = ""
            if detail_resp.status_code == 200:
                d = detail_resp.json().get("data", {})
                name = d.get("name", "")
                desc = d.get("description_short", "")
                country = d.get("country_code", "")

            self._vprint(
                f"    [bgpview] {asn}: {len(prefixes)} prefix(es), "
                f"name={name}"
            )
            return ASNInfo(
                asn=asn, name=name, description=desc,
                country=country, prefixes=prefixes,
            )

        except Exception as exc:
            self._vprint(f"    [bgpview] error: {exc}")
            return None

    def _bgpview_ip(self, ip: str) -> Optional[IPASNInfo]:
        if not _HAS_REQUESTS:
            return None

        try:
            resp = _requests.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=15,
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            prefixes = data.get("prefixes", [])
            if prefixes:
                p = prefixes[0]
                asn_data = p.get("asn", {})
                return IPASNInfo(
                    ip=ip,
                    asn=f"AS{asn_data.get('asn', '')}",
                    asn_name=asn_data.get("name", ""),
                    prefix=p.get("prefix", ""),
                    country=asn_data.get("country_code", ""),
                )
        except Exception:
            pass
        return None

    # ── RIPE RIS ────────────────────────────────────────────

    def _ripe_ris(self, asn: str) -> Optional[ASNInfo]:
        if not _HAS_REQUESTS:
            return None

        asn_num = asn.replace("AS", "")
        try:
            resp = _requests.get(
                f"https://stat.ripe.net/data/announced-prefixes/data.json"
                f"?resource=AS{asn_num}",
                timeout=15,
            )
            if resp.status_code != 200:
                return None

            data = resp.json().get("data", {})
            prefixes: list[str] = []
            for p in data.get("prefixes", []):
                prefix = p.get("prefix", "")
                if prefix and ":" not in prefix:  # IPv4 only
                    prefixes.append(prefix)

            self._vprint(
                f"    [ripe-ris] {asn}: {len(prefixes)} prefix(es)"
            )
            return ASNInfo(asn=asn, prefixes=prefixes)

        except Exception as exc:
            self._vprint(f"    [ripe-ris] error: {exc}")
            return None

    # ── Team Cymru DNS ──────────────────────────────────────

    def _cymru_dns(self, ip: str) -> Optional[IPASNInfo]:
        """Use Team Cymru DNS-based ASN lookup.
        Query format: reversed-ip.origin.asn.cymru.com TXT"""
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return None

            query = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
            answers = socket.getaddrinfo(
                query, None, socket.AF_INET, socket.SOCK_STREAM
            )
            # This approach is limited; full TXT lookup needs dnspython
            return None  # Fall through to API methods

        except Exception:
            return None

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _normalize_asn(asn: str) -> str:
        asn = asn.strip().upper()
        if not asn.startswith("AS"):
            asn = f"AS{asn}"
        return asn

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
