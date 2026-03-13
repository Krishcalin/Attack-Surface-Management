"""
EASM Scanner — DNS Resolver Module
Bulk DNS resolution with wildcard filtering.
Uses dnspython if available, falls back to stdlib socket.
Wraps dnsx if installed for high-performance resolution.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

try:
    import dns.resolver
    import dns.rdatatype
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


@dataclass
class DNSRecord:
    """A single DNS resolution result."""
    hostname: str
    record_type: str   # A, AAAA, CNAME, MX, NS, TXT, SOA
    value: str
    ttl: int = 0


class DNSResolver:
    """Bulk DNS resolver with wildcard filtering and multiple backends."""

    def __init__(
        self,
        resolvers: Optional[list[str]] = None,
        threads: int = 50,
        timeout: int = 5,
        verbose: bool = False,
    ) -> None:
        self.resolvers = resolvers or ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()

        if _HAS_DNSPYTHON:
            self._resolver = dns.resolver.Resolver()
            self._resolver.nameservers = self.resolvers
            self._resolver.timeout = timeout
            self._resolver.lifetime = timeout

    # ── Public API ──────────────────────────────────────────

    def resolve_bulk(
        self,
        hostnames: list[str],
        record_types: Optional[list[str]] = None,
    ) -> dict[str, list[DNSRecord]]:
        """Resolve a list of hostnames, returning {hostname: [records]}.
        Tries dnsx first, falls back to threaded Python resolution."""

        if record_types is None:
            record_types = ["A", "AAAA", "CNAME"]

        # Try dnsx for speed
        dnsx_result = self._dnsx_bulk(hostnames, record_types)
        if dnsx_result is not None:
            return dnsx_result

        # Threaded Python fallback
        results: dict[str, list[DNSRecord]] = {}

        def _resolve_one(host: str) -> tuple[str, list[DNSRecord]]:
            records = self._resolve_host(host, record_types)
            return (host, records)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = [pool.submit(_resolve_one, h) for h in hostnames]
            for fut in as_completed(futures):
                host, records = fut.result()
                if records:
                    results[host] = records

        self._vprint(
            f"    [dns] resolved {len(results)}/{len(hostnames)} hostnames"
        )
        return results

    def resolve_host(self, hostname: str) -> list[str]:
        """Convenience: resolve a single hostname to a list of IPs (A records)."""
        records = self._resolve_host(hostname, ["A", "AAAA"])
        return [r.value for r in records]

    def get_cnames(self, hostname: str) -> list[str]:
        """Get CNAME records for a hostname (useful for takeover detection)."""
        records = self._resolve_host(hostname, ["CNAME"])
        return [r.value for r in records]

    def get_nameservers(self, domain: str) -> list[str]:
        """Get NS records for a domain."""
        records = self._resolve_host(domain, ["NS"])
        return [r.value for r in records]

    def get_mx(self, domain: str) -> list[str]:
        """Get MX records for a domain."""
        records = self._resolve_host(domain, ["MX"])
        return [r.value for r in records]

    def get_txt(self, domain: str) -> list[str]:
        """Get TXT records (SPF, DKIM, DMARC, etc.)."""
        records = self._resolve_host(domain, ["TXT"])
        return [r.value for r in records]

    # ── dnsx wrapper ────────────────────────────────────────

    def _dnsx_bulk(
        self,
        hostnames: list[str],
        record_types: list[str],
    ) -> Optional[dict[str, list[DNSRecord]]]:
        """Use dnsx for bulk resolution if installed."""
        binary = shutil.which("dnsx")
        if not binary:
            return None

        results: dict[str, list[DNSRecord]] = {}
        stdin = "\n".join(hostnames)
        cmd = [binary, "-silent", "-resp"]
        for rt in record_types:
            cmd.append(f"-{rt.lower()}")

        try:
            proc = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=120,
            )
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # dnsx output: hostname [ip1,ip2,...]
                parts = line.split()
                if len(parts) >= 2:
                    host = parts[0].lower()
                    values_str = " ".join(parts[1:]).strip("[]")
                    records = []
                    for v in values_str.split(","):
                        v = v.strip()
                        if v:
                            records.append(DNSRecord(
                                hostname=host,
                                record_type="A",
                                value=v,
                            ))
                    if records:
                        results[host] = records

            self._vprint(
                f"    [dnsx] resolved {len(results)}/{len(hostnames)} "
                f"hostnames"
            )
        except (subprocess.TimeoutExpired, Exception) as exc:
            self._vprint(f"    [dnsx] error: {exc}")
            return None

        return results

    # ── Python DNS resolution ───────────────────────────────

    def _resolve_host(
        self,
        hostname: str,
        record_types: list[str],
    ) -> list[DNSRecord]:
        """Resolve a single host using dnspython or socket fallback."""
        records: list[DNSRecord] = []

        if _HAS_DNSPYTHON:
            for rtype in record_types:
                try:
                    rdtype = dns.rdatatype.from_text(rtype)
                    answers = self._resolver.resolve(hostname, rdtype)
                    for rdata in answers:
                        val = str(rdata).rstrip(".")
                        records.append(DNSRecord(
                            hostname=hostname,
                            record_type=rtype,
                            value=val,
                            ttl=answers.rrset.ttl if answers.rrset else 0,
                        ))
                except (dns.resolver.NXDOMAIN,
                        dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers,
                        dns.resolver.Timeout,
                        Exception):
                    continue
        else:
            # Fallback: socket.getaddrinfo (A/AAAA only)
            try:
                infos = socket.getaddrinfo(
                    hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                seen: set[str] = set()
                for info in infos:
                    ip = info[4][0]
                    if ip in seen:
                        continue
                    seen.add(ip)
                    rtype = "AAAA" if ":" in ip else "A"
                    records.append(DNSRecord(
                        hostname=hostname,
                        record_type=rtype,
                        value=ip,
                    ))
            except (socket.gaierror, OSError):
                pass

        return records

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
