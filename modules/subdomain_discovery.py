"""
EASM Scanner — Subdomain Discovery Module
Discovers subdomains using multiple techniques:
  1. Certificate Transparency logs (crt.sh) — pure Python
  2. Subfinder wrapper (if installed)
  3. DNS brute-force with wordlist — pure Python
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


class SubdomainDiscovery:
    """Multi-source subdomain enumeration engine."""

    def __init__(
        self,
        threads: int = 50,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────

    def discover(
        self,
        domain: str,
        brute_wordlist: Optional[str] = None,
    ) -> set[str]:
        """Run all available discovery methods and return unique subdomains."""
        results: set[str] = set()

        # 1. crt.sh (Certificate Transparency)
        ct_subs = self._crtsh(domain)
        self._vprint(f"    [crt.sh] {domain}: {len(ct_subs)} subdomain(s)")
        results.update(ct_subs)

        # 2. Subfinder (if installed)
        sf_subs = self._subfinder(domain)
        if sf_subs is not None:
            self._vprint(
                f"    [subfinder] {domain}: {len(sf_subs)} subdomain(s)"
            )
            results.update(sf_subs)

        # 3. DNS brute-force
        if brute_wordlist and os.path.isfile(brute_wordlist):
            bf_subs = self._brute_force(domain, brute_wordlist)
            self._vprint(
                f"    [brute-force] {domain}: {len(bf_subs)} subdomain(s)"
            )
            results.update(bf_subs)

        # Normalize
        results = {self._normalize(s) for s in results if self._normalize(s)}
        # Filter to in-scope (must end with .domain)
        base = domain.lower()
        results = {
            s for s in results
            if s == base or s.endswith("." + base)
        }
        return results

    # ── crt.sh ──────────────────────────────────────────────

    def _crtsh(self, domain: str) -> set[str]:
        """Query crt.sh Certificate Transparency log aggregator."""
        if not _HAS_REQUESTS:
            self._vprint("    [crt.sh] skipped — requests not installed")
            return set()

        subs: set[str] = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                self._vprint(
                    f"    [crt.sh] HTTP {resp.status_code} for {domain}"
                )
                return subs
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and "*" not in line:
                        subs.add(line)
        except Exception as exc:
            self._vprint(f"    [crt.sh] error: {exc}")
        return subs

    # ── Subfinder ───────────────────────────────────────────

    def _subfinder(self, domain: str) -> Optional[set[str]]:
        """Run subfinder if it is installed on the system."""
        binary = shutil.which("subfinder")
        if not binary:
            self._vprint("    [subfinder] not installed — skipping")
            return None

        subs: set[str] = set()
        try:
            proc = subprocess.run(
                [binary, "-d", domain, "-silent", "-all"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            for line in proc.stdout.strip().splitlines():
                line = line.strip().lower()
                if line:
                    subs.add(line)
        except subprocess.TimeoutExpired:
            self._vprint("    [subfinder] timed out")
        except Exception as exc:
            self._vprint(f"    [subfinder] error: {exc}")
        return subs

    # ── DNS Brute-Force ─────────────────────────────────────

    def _brute_force(self, domain: str, wordlist: str) -> set[str]:
        """Brute-force subdomains by resolving prefix.domain for each word."""
        subs: set[str] = set()
        words: list[str] = []

        with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip().lower()
                if w and not w.startswith("#"):
                    words.append(w)

        if not words:
            return subs

        # Wildcard detection — if *.domain resolves, brute-force is unreliable
        wildcard_ips = self._resolve_quick(f"unlikely-random-xyz123.{domain}")
        if wildcard_ips:
            self._vprint(
                f"    [brute-force] wildcard DNS detected for {domain} "
                f"({wildcard_ips}) — results filtered"
            )

        def _check(word: str) -> Optional[str]:
            fqdn = f"{word}.{domain}"
            ips = self._resolve_quick(fqdn)
            if ips and ips != wildcard_ips:
                return fqdn
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(_check, w): w for w in words}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    subs.add(result)

        return subs

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _resolve_quick(hostname: str) -> Optional[frozenset[str]]:
        """Quick A-record resolution using stdlib socket."""
        try:
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET, socket.SOCK_STREAM
            )
            ips = frozenset(r[4][0] for r in results)
            return ips if ips else None
        except (socket.gaierror, OSError):
            return None

    @staticmethod
    def _normalize(subdomain: str) -> str:
        s = subdomain.strip().lower().rstrip(".")
        s = re.sub(r"^\*\.", "", s)
        return s

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
