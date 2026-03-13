"""
EASM Scanner — Seed Manager
Manages organizational seed data: root domains, IPs, ASNs, CIDRs, and org names.
Seeds are the starting points for the entire discovery pipeline.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SeedData:
    """Container for all seed inputs provided by the user."""

    org_name: str = ""
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (
            self.org_name or self.domains or self.ips
            or self.cidrs or self.asns
        )

    @property
    def summary(self) -> str:
        parts: list[str] = []
        if self.org_name:
            parts.append(f"org={self.org_name!r}")
        if self.domains:
            parts.append(f"{len(self.domains)} domain(s)")
        if self.ips:
            parts.append(f"{len(self.ips)} IP(s)")
        if self.cidrs:
            parts.append(f"{len(self.cidrs)} CIDR(s)")
        if self.asns:
            parts.append(f"{len(self.asns)} ASN(s)")
        return ", ".join(parts) if parts else "(empty)"


class SeedManager:
    """Parse and validate seed inputs from CLI arguments or files."""

    _DOMAIN_RE = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
    )
    _ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.seeds = SeedData()

    def set_org(self, name: str) -> None:
        self.seeds.org_name = name.strip()

    def add_domain(self, domain: str) -> bool:
        d = domain.strip().lower().rstrip(".")
        if not d:
            return False
        if not self._DOMAIN_RE.match(d):
            self._warn(f"Invalid domain skipped: {d!r}")
            return False
        if d not in self.seeds.domains:
            self.seeds.domains.append(d)
            self._vprint(f"  [seed] domain: {d}")
        return True

    def add_ip(self, ip: str) -> bool:
        ip = ip.strip()
        try:
            addr = ipaddress.ip_address(ip)
            s = str(addr)
            if s not in self.seeds.ips:
                self.seeds.ips.append(s)
                self._vprint(f"  [seed] IP: {s}")
            return True
        except ValueError:
            self._warn(f"Invalid IP skipped: {ip!r}")
            return False

    def add_cidr(self, cidr: str) -> bool:
        cidr = cidr.strip()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            s = str(net)
            if s not in self.seeds.cidrs:
                self.seeds.cidrs.append(s)
                self._vprint(f"  [seed] CIDR: {s} ({net.num_addresses} hosts)")
            return True
        except ValueError:
            self._warn(f"Invalid CIDR skipped: {cidr!r}")
            return False

    def add_asn(self, asn: str) -> bool:
        asn = asn.strip()
        m = self._ASN_RE.match(asn)
        if not m:
            self._warn(f"Invalid ASN skipped: {asn!r}")
            return False
        normalized = f"AS{m.group(1)}"
        if normalized not in self.seeds.asns:
            self.seeds.asns.append(normalized)
            self._vprint(f"  [seed] ASN: {normalized}")
        return True

    def load_from_file(self, filepath: str) -> int:
        """Load seeds from a text file.  Each line is auto-classified as
        domain, IP, CIDR, or ASN.  Lines starting with # are comments."""
        count = 0
        with open(filepath, "r", encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if self._try_add(line):
                    count += 1
        self._vprint(f"  [seed] loaded {count} seeds from {filepath}")
        return count

    def parse_targets(self, targets: list[str]) -> None:
        """Auto-classify a list of target strings."""
        for t in targets:
            t = t.strip()
            if not t:
                continue
            self._try_add(t)

    def expand_cidrs(self) -> list[str]:
        """Expand all CIDRs into individual IP addresses.
        Limits expansion to /16 (65536 hosts) to avoid OOM."""
        ips: list[str] = []
        for cidr in self.seeds.cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.num_addresses > 65536:
                self._warn(
                    f"CIDR {cidr} has {net.num_addresses} hosts — "
                    f"skipping expansion (max /16)"
                )
                continue
            for addr in net.hosts():
                ips.append(str(addr))
        return ips

    def _try_add(self, value: str) -> bool:
        """Try to classify and add a value as domain, IP, CIDR, or ASN."""
        if "/" in value:
            return self.add_cidr(value)
        if self._ASN_RE.match(value):
            return self.add_asn(value)
        try:
            ipaddress.ip_address(value)
            return self.add_ip(value)
        except ValueError:
            pass
        return self.add_domain(value)

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    @staticmethod
    def _warn(msg: str) -> None:
        print(f"  \033[33m[WARN]\033[0m {msg}")
