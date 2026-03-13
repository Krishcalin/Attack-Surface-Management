#!/usr/bin/env python3
"""
EASM -- External Attack Surface Management Scanner
Version 4.0.0

Discovers, maps and analyses an organisation's internet-facing
attack surface from seed domains, IPs, ASNs or an org name.

Pipeline:  Seeds -> Subdomain Discovery -> DNS Resolution
           -> Port Scanning -> HTTP Probing -> CT Log Analysis
           -> ASN Mapping -> Enrichment -> Vulnerability Assessment
           -> Risk Scoring -> Report

Phase 4:   REST API, Dashboard, Alerting, SIEM Export, Jira, Scheduling

Requires:  pip install requests dnspython
Optional:  subfinder, httpx, dnsx, naabu, asnmap, nuclei (Go binaries)
           fastapi, uvicorn (for --serve mode)
"""

from __future__ import annotations

__version__ = "4.0.0"

import argparse
import html as html_mod
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ── Path setup ──────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.asset import Asset, AssetType
from models.finding import Finding, SEVERITY_ORDER
from modules.asset_store import AssetStore
from modules.seed_manager import SeedManager
from modules.subdomain_discovery import SubdomainDiscovery
from modules.dns_resolver import DNSResolver
from modules.port_scanner import PortScanner, PORT_SERVICES
from modules.http_prober import HTTPProber
from modules.asn_mapper import ASNMapper
from modules.ct_monitor import CTMonitor
from modules.whois_enrichment import WHOISEnrichment
from modules.tech_fingerprint import TechFingerprinter
from modules.tls_analyzer import TLSAnalyzer
from modules.geoip_enrichment import GeoIPEnrichment
from modules.screenshot_capture import ScreenshotCapture
from modules.attribution_engine import AttributionEngine
from modules.asset_graph import AssetGraph

# Phase 3 modules
from modules.subdomain_takeover import SubdomainTakeoverDetector
from modules.vuln_detector import VulnDetector
from modules.misconfig_detector import MisconfigDetector
from modules.default_creds import DefaultCredentialTester
from modules.dns_security import DNSSecurityChecker
from modules.cloud_enum import CloudStorageEnumerator
from modules.nuclei_scanner import NucleiScanner
from modules.risk_scorer import RiskScorer


# ── ANSI colours ────────────────────────────────────────────────────
BOLD = "\033[1m"
RESET = "\033[0m"
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "INFO": "\033[37m",
}

# ── Exposure / security rules (Phase-1 surface-level checks) ───────
EXPOSURE_RULES: list[dict[str, str]] = [
    {
        "id": "EASM-PORT-001",
        "category": "Exposed Service",
        "name": "Database Port Exposed to Internet",
        "severity": "CRITICAL",
        "ports": "3306,5432,1433,1521,6379,9200,27017",
        "description": (
            "A database service port is directly reachable from the "
            "internet.  Attackers commonly scan for exposed databases "
            "to steal data or deploy ransomware."
        ),
        "recommendation": (
            "Restrict database access to internal networks or VPN. "
            "Use firewall rules to deny public access to DB ports."
        ),
        "cwe": "CWE-200",
    },
    {
        "id": "EASM-PORT-002",
        "category": "Exposed Service",
        "name": "RDP Exposed to Internet",
        "severity": "HIGH",
        "ports": "3389",
        "description": (
            "Remote Desktop Protocol (RDP) is exposed to the internet. "
            "RDP is a top attack vector for ransomware and brute-force."
        ),
        "recommendation": (
            "Disable public RDP.  Use a VPN or Zero-Trust gateway. "
            "Enable NLA and strong MFA if RDP must be exposed."
        ),
        "cwe": "CWE-284",
    },
    {
        "id": "EASM-PORT-003",
        "category": "Exposed Service",
        "name": "Telnet Exposed to Internet",
        "severity": "HIGH",
        "ports": "23",
        "description": (
            "Telnet transmits credentials in cleartext and is exposed."
        ),
        "recommendation": "Replace Telnet with SSH. Block port 23.",
        "cwe": "CWE-319",
    },
    {
        "id": "EASM-PORT-004",
        "category": "Exposed Service",
        "name": "FTP Exposed to Internet",
        "severity": "MEDIUM",
        "ports": "21",
        "description": "FTP transmits credentials in cleartext.",
        "recommendation": "Replace FTP with SFTP/SCP. Block port 21.",
        "cwe": "CWE-319",
    },
    {
        "id": "EASM-PORT-005",
        "category": "Exposed Service",
        "name": "VNC Exposed to Internet",
        "severity": "HIGH",
        "ports": "5900",
        "description": "VNC is exposed; many VNC servers have weak auth.",
        "recommendation": "Restrict VNC behind VPN. Enable strong auth.",
        "cwe": "CWE-284",
    },
    {
        "id": "EASM-PORT-006",
        "category": "Exposed Service",
        "name": "SMB Exposed to Internet",
        "severity": "CRITICAL",
        "ports": "445",
        "description": (
            "SMB (port 445) is exposed. EternalBlue and similar exploits "
            "target SMB for wormable remote code execution."
        ),
        "recommendation": "Block SMB at the perimeter firewall.",
        "cwe": "CWE-284",
    },
    {
        "id": "EASM-HTTP-001",
        "category": "Security Header",
        "name": "Missing Strict-Transport-Security Header",
        "severity": "MEDIUM",
        "description": (
            "The HTTP response lacks the HSTS header, allowing potential "
            "SSL-stripping attacks."
        ),
        "recommendation": (
            "Add Strict-Transport-Security header with max-age >= 31536000."
        ),
        "cwe": "CWE-319",
    },
    {
        "id": "EASM-HTTP-002",
        "category": "Security Header",
        "name": "Missing Content-Security-Policy Header",
        "severity": "LOW",
        "description": "No CSP header; increases XSS attack surface.",
        "recommendation": "Implement a strict Content-Security-Policy.",
        "cwe": "CWE-79",
    },
    {
        "id": "EASM-HTTP-003",
        "category": "Security Header",
        "name": "Missing X-Content-Type-Options Header",
        "severity": "LOW",
        "description": "Missing nosniff header; MIME-type confusion risk.",
        "recommendation": "Add X-Content-Type-Options: nosniff.",
        "cwe": "CWE-16",
    },
    {
        "id": "EASM-HTTP-004",
        "category": "Information Disclosure",
        "name": "Server Version Disclosed",
        "severity": "INFO",
        "description": (
            "The Server header discloses software version information."
        ),
        "recommendation": "Suppress version info in the Server header.",
        "cwe": "CWE-200",
    },
    {
        "id": "EASM-HTTP-005",
        "category": "Security Header",
        "name": "Missing X-Frame-Options Header",
        "severity": "LOW",
        "description": "No X-Frame-Options; clickjacking risk.",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN.",
        "cwe": "CWE-1021",
    },
    {
        "id": "EASM-TLS-001",
        "category": "TLS/SSL",
        "name": "HTTP Service Without TLS",
        "severity": "MEDIUM",
        "description": (
            "A web service is running over plain HTTP without TLS "
            "encryption, exposing data in transit."
        ),
        "recommendation": "Enable HTTPS and redirect HTTP to HTTPS.",
        "cwe": "CWE-319",
    },
    # ── Phase 2: TLS / Certificate rules ────
    {
        "id": "EASM-TLS-002",
        "category": "TLS/SSL",
        "name": "Self-Signed Certificate",
        "severity": "HIGH",
        "description": (
            "The TLS certificate is self-signed, meaning it was not "
            "issued by a trusted CA.  Browsers will show warnings."
        ),
        "recommendation": "Replace with a CA-signed certificate (e.g., Let's Encrypt).",
        "cwe": "CWE-295",
    },
    {
        "id": "EASM-TLS-003",
        "category": "TLS/SSL",
        "name": "Expired TLS Certificate",
        "severity": "CRITICAL",
        "description": "The TLS certificate has expired.",
        "recommendation": "Renew the certificate immediately.",
        "cwe": "CWE-298",
    },
    {
        "id": "EASM-TLS-004",
        "category": "TLS/SSL",
        "name": "TLS Certificate Expiring Soon",
        "severity": "MEDIUM",
        "description": "The TLS certificate expires within 30 days.",
        "recommendation": "Renew the certificate before expiry.",
        "cwe": "CWE-298",
    },
    {
        "id": "EASM-TLS-005",
        "category": "TLS/SSL",
        "name": "Weak RSA Key (< 2048 bits)",
        "severity": "HIGH",
        "description": "The TLS certificate uses an RSA key smaller than 2048 bits.",
        "recommendation": "Generate a new certificate with at least 2048-bit RSA or ECDSA key.",
        "cwe": "CWE-326",
    },
    {
        "id": "EASM-WHOIS-001",
        "category": "Domain",
        "name": "Domain Expiring Soon",
        "severity": "MEDIUM",
        "description": "The domain registration expires within 30 days.",
        "recommendation": "Renew the domain registration immediately.",
        "cwe": "",
    },
    {
        "id": "EASM-WHOIS-002",
        "category": "Domain",
        "name": "DNSSEC Not Enabled",
        "severity": "LOW",
        "description": "DNSSEC is not enabled for this domain.",
        "recommendation": "Enable DNSSEC to prevent DNS spoofing attacks.",
        "cwe": "CWE-350",
    },
    # ── Phase 3: Vulnerability Assessment rules ────
    {
        "id": "EASM-TAKEOVER-001",
        "category": "Subdomain Takeover",
        "name": "Subdomain Takeover Vulnerability",
        "severity": "HIGH",
        "description": (
            "A subdomain has a dangling DNS record pointing to an "
            "unclaimed cloud resource, allowing takeover."
        ),
        "recommendation": (
            "Remove the dangling DNS record or reclaim the "
            "cloud resource."
        ),
        "cwe": "CWE-284",
    },
    {
        "id": "EASM-CVE-001",
        "category": "CVE",
        "name": "Known CVE Detected",
        "severity": "HIGH",
        "description": (
            "A known CVE was detected via version fingerprinting "
            "of an exposed service or application."
        ),
        "recommendation": (
            "Patch or upgrade the affected software to a "
            "non-vulnerable version."
        ),
        "cwe": "CWE-1035",
    },
    {
        "id": "EASM-CRED-001",
        "category": "Default Credential",
        "name": "Default Credentials Accepted",
        "severity": "CRITICAL",
        "description": (
            "An exposed service accepts factory-default credentials."
        ),
        "recommendation": (
            "Change the default password immediately and restrict "
            "service access to authorised networks."
        ),
        "cwe": "CWE-798",
    },
    {
        "id": "EASM-CLOUD-001",
        "category": "Cloud Storage",
        "name": "Public Cloud Storage Bucket",
        "severity": "CRITICAL",
        "description": (
            "A cloud storage bucket (S3/Azure/GCS) is publicly "
            "accessible and may contain sensitive data."
        ),
        "recommendation": (
            "Restrict bucket access to authorised principals only. "
            "Review and remove public ACLs."
        ),
        "cwe": "CWE-284",
    },
]


# ════════════════════════════════════════════════════════════════════
#  EASMScanner — main orchestrator
# ════════════════════════════════════════════════════════════════════

class EASMScanner:
    """External Attack Surface Management scanner — Phase 1 + 2 + 3 + 4 pipeline."""

    TOTAL_STEPS = 14

    def __init__(
        self,
        verbose: bool = False,
        threads: int = 50,
        db_path: str = ":memory:",
        screenshot_dir: str = "screenshots",
    ) -> None:
        self.verbose = verbose
        self.threads = threads
        self.store = AssetStore(db_path)
        self.findings: list[Finding] = []
        self.start_time: float = 0.0
        self.end_time: float = 0.0

        # Phase 1 modules
        self.seed_mgr = SeedManager(verbose=verbose)
        self.subdomain = SubdomainDiscovery(
            threads=threads, verbose=verbose,
        )
        self.dns = DNSResolver(threads=threads, verbose=verbose)
        self.port_scanner = PortScanner(threads=threads, verbose=verbose)
        self.http_prober = HTTPProber(threads=threads, verbose=verbose)
        self.asn_mapper = ASNMapper(verbose=verbose)
        self.ct_monitor = CTMonitor(verbose=verbose)

        # Phase 2 modules
        self.whois = WHOISEnrichment(verbose=verbose)
        self.tech_fp = TechFingerprinter(verbose=verbose)
        self.tls_analyzer = TLSAnalyzer(verbose=verbose)
        self.geoip = GeoIPEnrichment(verbose=verbose)
        self.screenshot = ScreenshotCapture(
            output_dir=screenshot_dir, verbose=verbose,
        )
        self.attrib_engine: Optional[AttributionEngine] = None
        self.graph = AssetGraph()

        # Phase 2 result caches
        self.whois_records: dict = {}
        self.tls_results: list = []
        self.geoip_results: dict = {}
        self.tech_profiles: dict = {}
        self.attribution_results: list = []

        # Phase 3 modules
        self.takeover_detector = SubdomainTakeoverDetector(verbose=verbose)
        self.vuln_detector = VulnDetector(verbose=verbose)
        self.misconfig_detector = MisconfigDetector(verbose=verbose)
        self.cred_tester = DefaultCredentialTester(
            timeout=5, verbose=verbose,
        )
        self.dns_security = DNSSecurityChecker(verbose=verbose)
        self.cloud_enum = CloudStorageEnumerator(verbose=verbose)
        self.nuclei = NucleiScanner(verbose=verbose)
        self.risk_scorer = RiskScorer(verbose=verbose)

        # Phase 3 result caches
        self.takeover_results: list = []
        self.vuln_results: list = []
        self.misconfig_results: list = []
        self.cred_results: list = []
        self.dns_sec_results: dict = {}
        self.cloud_results: list = []
        self.nuclei_results: list = []
        self.risk_scores: list = []

    # ── Pipeline ────────────────────────────────────────────

    def run(
        self,
        domains: Optional[list[str]] = None,
        ips: Optional[list[str]] = None,
        asns: Optional[list[str]] = None,
        cidrs: Optional[list[str]] = None,
        org_name: str = "",
        seed_file: Optional[str] = None,
        brute_wordlist: Optional[str] = None,
        skip_ports: bool = False,
        skip_http: bool = False,
        skip_enrichment: bool = False,
        skip_vuln_assessment: bool = False,
        skip_nuclei: bool = False,
        skip_cred_test: bool = False,
        nuclei_templates: Optional[str] = None,
    ) -> None:
        """Execute the full Phase 1 + 2 + 3 pipeline."""

        N = self.TOTAL_STEPS
        self.start_time = time.time()
        self._banner()

        # ── Step 1: Seed ingestion ─────────────────────────
        self._phase(f"Step 1/{N}", "Seed Ingestion")
        if org_name:
            self.seed_mgr.set_org(org_name)
        if domains:
            for d in domains:
                self.seed_mgr.add_domain(d)
        if ips:
            for ip in ips:
                self.seed_mgr.add_ip(ip)
        if asns:
            for a in asns:
                self.seed_mgr.add_asn(a)
        if cidrs:
            for c in cidrs:
                self.seed_mgr.add_cidr(c)
        if seed_file:
            self.seed_mgr.load_from_file(seed_file)

        seeds = self.seed_mgr.seeds
        if seeds.is_empty:
            print(f"  {SEVERITY_COLOR['HIGH']}[ERROR]{RESET} "
                  f"No valid seeds provided.  Nothing to scan.")
            return

        print(f"  Seeds: {seeds.summary}")
        for d in seeds.domains:
            self.store.upsert_asset(Asset(
                asset_type=AssetType.DOMAIN, value=d, sources=["seed"],
            ))

        # Initialize attribution engine
        self.attrib_engine = AttributionEngine(
            org_name=org_name,
            seed_domains=list(seeds.domains),
            verbose=self.verbose,
        )

        # ── Step 2: ASN expansion ──────────────────────────
        if seeds.asns:
            self._phase(f"Step 2/{N}", "ASN Prefix Expansion")
            for asn in seeds.asns:
                info = self.asn_mapper.get_prefixes(asn)
                self.store.upsert_asset(Asset(
                    asset_type=AssetType.ASN, value=asn,
                    sources=["seed"],
                    attributes={"name": info.name, "country": info.country},
                ))
                for prefix in info.prefixes:
                    self.store.upsert_asset(Asset(
                        asset_type=AssetType.CIDR, value=prefix,
                        sources=["asn-expansion"], parent=asn,
                    ))
                    seeds.cidrs.append(prefix)
                print(f"  {asn}: {len(info.prefixes)} prefix(es) "
                      f"({info.name})")
        else:
            self._phase(f"Step 2/{N}", "ASN Prefix Expansion (skipped)")

        # ── Step 3: Subdomain discovery ────────────────────
        self._phase(f"Step 3/{N}", "Subdomain Discovery")
        all_subdomains: set[str] = set()
        for domain in list(seeds.domains):
            subs = self.subdomain.discover(domain, brute_wordlist)
            all_subdomains.update(subs)
            ct_domains = self.ct_monitor.extract_domains(domain)
            all_subdomains.update(ct_domains)
            print(f"  {domain}: {len(subs)} from enum, "
                  f"{len(ct_domains)} from CT = "
                  f"{len(subs | ct_domains)} unique")

        for sub in sorted(all_subdomains):
            self.store.upsert_asset(Asset(
                asset_type=AssetType.DOMAIN, value=sub,
                sources=["subdomain-discovery"],
            ))
        print(f"  Total unique subdomains: {len(all_subdomains)}")

        # ── Step 4: DNS resolution ─────────────────────────
        self._phase(f"Step 4/{N}", "DNS Resolution")
        all_domains = self.store.all_domains()
        dns_results = self.dns.resolve_bulk(all_domains)
        ip_set: set[str] = set()
        for host, records in dns_results.items():
            for rec in records:
                if rec.record_type in ("A", "AAAA"):
                    ip_set.add(rec.value)
                    self.store.upsert_asset(Asset(
                        asset_type=AssetType.IP, value=rec.value,
                        sources=["dns-resolution"], parent=host,
                    ))
        for ip in seeds.ips:
            ip_set.add(ip)
            self.store.upsert_asset(Asset(
                asset_type=AssetType.IP, value=ip, sources=["seed"],
            ))
        cidr_ips = self.seed_mgr.expand_cidrs()
        for ip in cidr_ips:
            ip_set.add(ip)
        print(f"  Resolved {len(dns_results)}/{len(all_domains)} "
              f"domains -> {len(ip_set)} unique IP(s)")

        # Build graph from DNS
        self.graph.add_dns_edges(dns_results)

        # ── Step 5: Port scanning ──────────────────────────
        port_results = []
        if not skip_ports and ip_set:
            self._phase(f"Step 5/{N}", "Port Scanning")
            targets = sorted(ip_set)
            if len(targets) > 1024:
                print(f"  Limiting scan to first 1024 of "
                      f"{len(targets)} IPs")
                targets = targets[:1024]

            port_results = self.port_scanner.scan(targets)
            for pr in port_results:
                self.store.upsert_asset(Asset(
                    asset_type=AssetType.PORT,
                    value=str(pr.port),
                    parent=pr.ip,
                    sources=["port-scan"],
                    attributes={
                        "service": pr.service,
                        "banner": pr.banner[:256] if pr.banner else "",
                        "tls": pr.tls,
                        "tls_subject": pr.tls_subject,
                    },
                ))
            print(f"  Found {len(port_results)} open port(s) across "
                  f"{len(targets)} host(s)")
            self._check_port_exposure(port_results)
        else:
            self._phase(f"Step 5/{N}", "Port Scanning (skipped)")

        # ── Step 6: HTTP probing ───────────────────────────
        http_results = []
        if not skip_http:
            self._phase(f"Step 6/{N}", "HTTP Probing")
            probe_targets = sorted(
                set(self.store.all_domains()) | ip_set
            )
            if len(probe_targets) > 2048:
                print(f"  Limiting probes to first 2048 of "
                      f"{len(probe_targets)} targets")
                probe_targets = probe_targets[:2048]

            http_results = self.http_prober.probe(probe_targets)
            for hr in http_results:
                self.store.upsert_asset(Asset(
                    asset_type=AssetType.URL,
                    value=hr.url,
                    sources=["http-probe"],
                    attributes={
                        "status_code": hr.status_code,
                        "title": hr.title,
                        "server": hr.server,
                        "content_type": hr.content_type,
                        "technologies": hr.technologies,
                        "favicon_hash": hr.favicon_hash,
                        "tls": hr.tls,
                        "redirect_url": hr.redirect_url,
                        "headers": hr.headers,
                    },
                ))
            print(f"  Found {len(http_results)} live HTTP service(s)")
            self._check_http_security(http_results)
        else:
            self._phase(f"Step 6/{N}", "HTTP Probing (skipped)")

        # ================================================================
        #  PHASE 2 — Enrichment & Attribution
        # ================================================================

        if skip_enrichment:
            for step_num in range(7, N + 1):
                self._phase(
                    f"Step {step_num}/{N}",
                    f"{'WHOIS,TLS,GeoIP,Tech,Attribution'.split(',')[step_num-7] if step_num <= 10 else 'N/A'} (skipped)",
                )
            self.end_time = time.time()
            self._phase_done()
            return

        # ── Step 7: WHOIS enrichment ───────────────────────
        self._phase(f"Step 7/{N}", "WHOIS Enrichment")
        all_domains = self.store.all_domains()
        self.whois_records = self.whois.bulk_lookup(all_domains)
        whois_count = sum(
            1 for r in self.whois_records.values()
            if r.registrar or r.registrant_org
        )
        print(f"  WHOIS data for {whois_count}/{len(self.whois_records)} "
              f"root domain(s)")

        # Check domain expiry + DNSSEC
        for domain, rec in self.whois_records.items():
            dte = rec.days_to_expiry
            if dte is not None and 0 <= dte <= 30:
                self._add_finding(Finding(
                    rule_id="EASM-WHOIS-001",
                    name="Domain Expiring Soon",
                    category="Domain",
                    severity="MEDIUM",
                    asset_value=domain,
                    asset_type="domain",
                    description=f"Domain expires in {dte} day(s).",
                    recommendation="Renew the domain registration immediately.",
                    evidence=f"Expiry: {rec.expiry_date}",
                ))
            if rec.dnssec and rec.dnssec.lower() in ("unsigned", "no"):
                self._add_finding(Finding(
                    rule_id="EASM-WHOIS-002",
                    name="DNSSEC Not Enabled",
                    category="Domain",
                    severity="LOW",
                    asset_value=domain,
                    asset_type="domain",
                    description="DNSSEC is not enabled for this domain.",
                    recommendation="Enable DNSSEC to prevent DNS spoofing.",
                    evidence=f"DNSSEC: {rec.dnssec}",
                ))
            # Add to graph
            self.graph.add_whois_edges(domain, rec)

        # ── Step 8: TLS analysis ───────────────────────────
        self._phase(f"Step 8/{N}", "TLS Certificate Analysis")
        # Build TLS targets from HTTPS URLs + known TLS ports
        tls_targets: list[tuple[str, int]] = []
        seen_tls: set[str] = set()
        for hr in http_results:
            if hr.tls and hr.url:
                from urllib.parse import urlparse as _urlparse
                parsed = _urlparse(hr.url)
                host = parsed.hostname or ""
                port = parsed.port or 443
                key = f"{host}:{port}"
                if host and key not in seen_tls:
                    seen_tls.add(key)
                    tls_targets.append((host, port))
        # Also check TLS ports from port scan
        for pr in port_results:
            if pr.port in self.tls_analyzer.TLS_PORTS:
                key = f"{pr.ip}:{pr.port}"
                if key not in seen_tls:
                    seen_tls.add(key)
                    tls_targets.append((pr.ip, pr.port))

        if tls_targets:
            self.tls_results = self.tls_analyzer.bulk_analyze(tls_targets)
            print(f"  Analyzed {len(self.tls_results)} TLS endpoint(s)")

            for tls_info in self.tls_results:
                # Store cert as asset attribute on the host
                host_asset = self.store.get_asset("ip", tls_info.host)
                if not host_asset:
                    host_asset = self.store.get_asset("domain", tls_info.host)
                if host_asset:
                    host_asset.set_attr("tls", tls_info.to_dict())
                    self.store.upsert_asset(host_asset)

                # Add to graph
                self.graph.add_tls_edges(tls_info.host, tls_info)

                # Security findings
                if tls_info.is_self_signed:
                    self._add_finding(Finding(
                        rule_id="EASM-TLS-002",
                        name="Self-Signed Certificate",
                        category="TLS/SSL",
                        severity="HIGH",
                        asset_value=f"{tls_info.host}:{tls_info.port}",
                        asset_type="url",
                        description="TLS certificate is self-signed.",
                        recommendation="Replace with a CA-signed certificate.",
                        cwe="CWE-295",
                        evidence=f"CN={tls_info.subject_cn}, Issuer={tls_info.issuer_cn}",
                    ))
                if tls_info.is_expired:
                    self._add_finding(Finding(
                        rule_id="EASM-TLS-003",
                        name="Expired TLS Certificate",
                        category="TLS/SSL",
                        severity="CRITICAL",
                        asset_value=f"{tls_info.host}:{tls_info.port}",
                        asset_type="url",
                        description="TLS certificate has expired.",
                        recommendation="Renew the certificate immediately.",
                        cwe="CWE-298",
                        evidence=f"Expired {abs(tls_info.days_to_expiry)} day(s) ago",
                    ))
                elif tls_info.is_expiring_soon:
                    self._add_finding(Finding(
                        rule_id="EASM-TLS-004",
                        name="TLS Certificate Expiring Soon",
                        category="TLS/SSL",
                        severity="MEDIUM",
                        asset_value=f"{tls_info.host}:{tls_info.port}",
                        asset_type="url",
                        description=f"Certificate expires in {tls_info.days_to_expiry} day(s).",
                        recommendation="Renew the certificate before expiry.",
                        cwe="CWE-298",
                        evidence=f"Expiry: {tls_info.not_after}",
                    ))
                if tls_info.is_weak_key:
                    self._add_finding(Finding(
                        rule_id="EASM-TLS-005",
                        name="Weak RSA Key (< 2048 bits)",
                        category="TLS/SSL",
                        severity="HIGH",
                        asset_value=f"{tls_info.host}:{tls_info.port}",
                        asset_type="url",
                        description=f"RSA key is only {tls_info.key_bits} bits.",
                        recommendation="Use at least 2048-bit RSA or ECDSA.",
                        cwe="CWE-326",
                        evidence=f"Key: {tls_info.key_type} {tls_info.key_bits}-bit",
                    ))
        else:
            print("  No TLS endpoints to analyze")

        # ── Step 9: GeoIP + Tech fingerprinting ────────────
        self._phase(f"Step 9/{N}", "GeoIP & Technology Fingerprinting")
        # GeoIP
        all_ips = self.store.all_ips()
        if all_ips:
            self.geoip_results = self.geoip.bulk_lookup(all_ips)
            for ip, geo in self.geoip_results.items():
                ip_asset = self.store.get_asset("ip", ip)
                if ip_asset:
                    ip_asset.set_attr("geoip", geo.to_dict())
                    self.store.upsert_asset(ip_asset)
            print(f"  GeoIP: {len(self.geoip_results)} IP(s) geolocated")

        # Tech fingerprinting (on live URLs)
        live_urls = [
            a.value for a in self.store.get_assets(asset_type="url")
            if a.get_attr("status_code", 0) and a.get_attr("status_code", 0) < 400
        ]
        if live_urls:
            # Limit to 50 URLs for performance
            fp_urls = live_urls[:50]
            self.tech_profiles = self.tech_fp.bulk_fingerprint(fp_urls)
            for url, profile in self.tech_profiles.items():
                url_asset = self.store.get_asset("url", url)
                if url_asset:
                    url_asset.set_attr("tech_profile", profile.to_dict())
                    url_asset.set_attr("technologies", profile.technologies)
                    if profile.waf:
                        url_asset.set_attr("waf", profile.waf)
                    if profile.cdn:
                        url_asset.set_attr("cdn", profile.cdn)
                    self.store.upsert_asset(url_asset)
            print(f"  Tech: {len(self.tech_profiles)} URL(s) fingerprinted")
        else:
            print("  No live URLs for tech fingerprinting")

        # ── Step 10: Attribution & Graph ───────────────────
        self._phase(f"Step 10/{N}", "Attribution & Relationship Graph")
        # Build graph from all assets
        all_assets = self.store.get_assets()
        self.graph.build_from_assets(all_assets, dns_results)

        # Learn org patterns from seed enrichment
        self.attrib_engine.learn_from_seeds(
            whois_records=self.whois_records,
            http_results=http_results,
        )

        # Run attribution on all domains
        domain_assets = self.store.get_assets(asset_type="domain")
        attrib_count = {"attributed": 0, "review": 0, "unattributed": 0}
        for asset in domain_assets:
            root = self.whois._extract_root(asset.value)
            whois_rec = self.whois_records.get(root)
            result = self.attrib_engine.attribute(
                asset_value=asset.value,
                asset_type="domain",
                whois_record=whois_rec,
            )
            self.attribution_results.append(result)
            attrib_count[result.verdict] = attrib_count.get(result.verdict, 0) + 1

            # Update asset with attribution
            asset.org_attribution = result.org_name
            asset.confidence = result.confidence
            self.store.upsert_asset(asset)

        graph_stats = self.graph.stats()
        print(f"  Graph: {graph_stats['total_nodes']} nodes, "
              f"{graph_stats['total_edges']} edges")
        print(f"  Attribution: {attrib_count['attributed']} attributed, "
              f"{attrib_count['review']} review, "
              f"{attrib_count['unattributed']} unattributed")

        # ================================================================
        #  PHASE 3 -- Vulnerability Assessment
        # ================================================================

        if skip_vuln_assessment:
            for step_num in range(11, N + 1):
                self._phase(f"Step {step_num}/{N}", "Vuln Assessment (skipped)")
            self.end_time = time.time()
            self._phase_done()
            return

        # Set nuclei templates dir if provided
        if nuclei_templates:
            self.nuclei.templates_dir = nuclei_templates

        # ── Step 11: Vulnerability Detection ─────────────────
        self._phase(f"Step 11/{N}", "Vulnerability Detection (CVE + Nuclei)")

        # 11a: CVE detection from HTTP headers
        for hr in http_results:
            if hr.status_code == 0:
                continue
            vulns = self.vuln_detector.detect_from_headers(
                hr.url, hr.headers,
            )
            self.vuln_results.extend(vulns)

        # 11b: CVE detection from port banners
        for pr in port_results:
            if pr.banner:
                vulns = self.vuln_detector.detect_from_banner(
                    pr.ip, pr.port, pr.banner,
                )
                self.vuln_results.extend(vulns)

        # 11c: CVE detection from tech fingerprints
        for url, profile in self.tech_profiles.items():
            techs = getattr(profile, "technologies", [])
            if techs:
                vulns = self.vuln_detector.detect_from_tech(url, techs)
                self.vuln_results.extend(vulns)

        # Enrich with EPSS scores
        if self.vuln_results:
            self.vuln_detector.enrich_with_epss(self.vuln_results)

        # Generate CVE findings
        for v in self.vuln_results:
            sev = v.severity
            if v.is_kev:
                sev = "CRITICAL"  # escalate KEV entries
            self._add_finding(Finding(
                rule_id="EASM-CVE-001",
                name=f"Known CVE: {v.cve}",
                category="CVE",
                severity=sev,
                asset_value=v.asset_value,
                asset_type=v.asset_type,
                description=v.description,
                recommendation=(
                    f"Upgrade {v.product} from {v.version} to a "
                    f"patched version."
                ),
                cve=v.cve,
                cwe="CWE-1035",
                evidence=v.evidence,
                attributes={
                    "epss_score": v.epss_score,
                    "is_kev": v.is_kev,
                },
            ))

        # 11d: Nuclei scan
        if not skip_nuclei:
            nuclei_targets = [
                hr.url for hr in http_results
                if hr.status_code and hr.status_code < 400
            ][:100]  # cap at 100 URLs
            if nuclei_targets:
                self.nuclei_results = self.nuclei.scan(nuclei_targets)
                for nr in self.nuclei_results:
                    self._add_finding(Finding(
                        rule_id=f"EASM-NUCLEI-{nr.template_id[:20]}",
                        name=nr.name,
                        category="Nuclei",
                        severity=nr.severity.upper(),
                        asset_value=nr.matched_at,
                        asset_type="url",
                        description=nr.description or nr.name,
                        evidence=nr.evidence,
                    ))

        vuln_count = len(self.vuln_results)
        nuclei_count = len(self.nuclei_results)
        print(f"  CVEs detected: {vuln_count}")
        print(f"  Nuclei findings: {nuclei_count}")

        # ── Step 12: Misconfig & Takeover Detection ──────────
        self._phase(
            f"Step 12/{N}",
            "Misconfiguration & Takeover Detection",
        )

        # 12a: Subdomain takeover
        all_domains = self.store.all_domains()
        self.takeover_results = self.takeover_detector.bulk_check(
            all_domains,
        )
        for tr in self.takeover_results:
            if tr.vulnerable:
                self._add_finding(Finding(
                    rule_id="EASM-TAKEOVER-001",
                    name=f"Subdomain Takeover ({tr.provider})",
                    category="Subdomain Takeover",
                    severity=tr.severity,
                    asset_value=tr.domain,
                    asset_type="domain",
                    description=(
                        f"Subdomain {tr.domain} is vulnerable to "
                        f"takeover via {tr.provider}."
                    ),
                    recommendation=(
                        "Remove the dangling DNS record or reclaim "
                        f"the {tr.provider} resource."
                    ),
                    cwe="CWE-284",
                    evidence=tr.evidence,
                ))

        # 12b: Web misconfigurations
        live_urls = [
            hr.url for hr in http_results
            if hr.status_code and hr.status_code < 400
        ]
        if live_urls:
            self.misconfig_results = self.misconfig_detector.bulk_scan(
                live_urls, max_urls=50,
            )
            for mr in self.misconfig_results:
                self._add_finding(Finding(
                    rule_id=mr.rule_id,
                    name=mr.name,
                    category="Misconfiguration",
                    severity=mr.severity,
                    asset_value=mr.url,
                    asset_type="url",
                    description=mr.name,
                    cwe=mr.cwe,
                    evidence=mr.evidence,
                ))

        # 12c: Cloud storage enumeration
        seed_domains = list(seeds.domains)
        self.cloud_results = self.cloud_enum.enumerate_from_domains(
            seed_domains, org_name=org_name,
        )
        for cr in self.cloud_results:
            if cr.publicly_listable or cr.publicly_readable:
                self._add_finding(Finding(
                    rule_id="EASM-CLOUD-001",
                    name=f"Public {cr.provider.upper()} Bucket",
                    category="Cloud Storage",
                    severity=cr.severity,
                    asset_value=cr.bucket_name,
                    asset_type="url",
                    description=(
                        f"Cloud storage bucket '{cr.bucket_name}' "
                        f"({cr.provider}) is publicly accessible."
                    ),
                    recommendation=(
                        "Restrict bucket access to authorised "
                        "principals only."
                    ),
                    cwe="CWE-284",
                    evidence=cr.evidence,
                ))

        takeover_vuln = sum(1 for t in self.takeover_results if t.vulnerable)
        print(f"  Takeover vulnerable: {takeover_vuln}")
        print(f"  Misconfigurations: {len(self.misconfig_results)}")
        print(f"  Public buckets: {len(self.cloud_results)}")

        # ── Step 13: Credential & DNS Security ───────────────
        self._phase(
            f"Step 13/{N}", "Credential & DNS Security Testing",
        )

        # 13a: Default credential testing
        if not skip_cred_test:
            cred_targets: list[dict] = []
            for pr in port_results:
                if pr.port in (22, 21, 161, 3306, 5432, 6379,
                               27017, 80, 443, 8080, 8443):
                    cred_targets.append({
                        "ip": pr.ip, "port": pr.port,
                    })
            if cred_targets:
                # Cap at 50 targets
                self.cred_results = self.cred_tester.bulk_test(
                    cred_targets[:50],
                )
                for cr in self.cred_results:
                    if cr.success:
                        self._add_finding(Finding(
                            rule_id="EASM-CRED-001",
                            name=(
                                f"Default Credentials ({cr.service})"
                            ),
                            category="Default Credential",
                            severity=cr.severity,
                            asset_value=f"{cr.ip}:{cr.port}",
                            asset_type="port",
                            description=(
                                f"Service {cr.service} at "
                                f"{cr.ip}:{cr.port} accepts "
                                f"default credentials."
                            ),
                            recommendation=(
                                "Change the default password "
                                "immediately."
                            ),
                            cwe="CWE-798",
                            evidence=cr.evidence,
                        ))
        else:
            print("  Credential testing: skipped")

        # 13b: DNS security (SPF/DKIM/DMARC/AXFR)
        root_domains = list(seeds.domains)
        self.dns_sec_results = self.dns_security.bulk_check(
            root_domains,
        )
        for domain, dns_res in self.dns_sec_results.items():
            for finding_data in dns_res.findings:
                self._add_finding(Finding(
                    rule_id=finding_data["rule_id"],
                    name=finding_data["name"],
                    category="DNS Security",
                    severity=finding_data["severity"],
                    asset_value=domain,
                    asset_type="domain",
                    description=finding_data.get("description", ""),
                    recommendation=finding_data.get(
                        "recommendation", ""
                    ),
                    cwe=finding_data.get("cwe", ""),
                    evidence=finding_data.get("evidence", ""),
                ))

        cred_found = sum(1 for c in self.cred_results if c.success)
        dns_findings = sum(
            len(r.findings) for r in self.dns_sec_results.values()
        )
        print(f"  Default creds found: {cred_found}")
        print(f"  DNS security findings: {dns_findings}")

        # ── Step 14: Risk Scoring ────────────────────────────
        self._phase(f"Step 14/{N}", "Risk Scoring & Prioritisation")

        finding_dicts: list[dict] = []
        for f in self.findings:
            fd: dict = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "asset_value": f.asset_value,
                "asset_type": f.asset_type,
                "category": f.category,
                "cve": f.cve,
            }
            # Add EPSS/KEV data if available
            attrs = f.attributes or {}
            fd["epss_score"] = attrs.get("epss_score", 0.0)
            fd["is_kev"] = attrs.get("is_kev", False)
            finding_dicts.append(fd)

        self.risk_scores = self.risk_scorer.score_findings(finding_dicts)

        if self.risk_scores:
            from modules.risk_scorer import RiskScorer as _RS
            stats = _RS.aggregate_stats(self.risk_scores)
            print(f"  Risk scores computed: {stats['count']}")
            print(f"  Avg risk: {stats['avg_score']}, "
                  f"Max: {stats['max_score']}")
            by_level = stats.get("by_level", {})
            for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                cnt = by_level.get(lvl, 0)
                if cnt:
                    print(f"    {lvl}: {cnt}")
            if stats.get("auto_escalated"):
                print(f"  Auto-escalated: {stats['auto_escalated']}")

        self.end_time = time.time()
        self._phase_done()

    # ── Security checks ─────────────────────────────────────

    def _check_port_exposure(self, port_results: list) -> None:
        """Check open ports against exposure rules."""
        for rule in EXPOSURE_RULES:
            if "ports" not in rule:
                continue
            danger_ports = {int(p) for p in rule["ports"].split(",")}
            for pr in port_results:
                if pr.port in danger_ports:
                    self._add_finding(Finding(
                        rule_id=rule["id"],
                        name=rule["name"],
                        category=rule["category"],
                        severity=rule["severity"],
                        asset_value=f"{pr.ip}:{pr.port}",
                        asset_type="port",
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe", ""),
                        evidence=(
                            f"Open port {pr.port} "
                            f"({pr.service or 'unknown service'})"
                            + (f" — banner: {pr.banner[:120]}"
                               if pr.banner else "")
                        ),
                    ))

    def _check_http_security(self, http_results: list) -> None:
        """Check HTTP responses for missing security headers & TLS."""
        for hr in http_results:
            if hr.status_code == 0:
                continue

            # Missing HSTS
            if hr.tls and not hr.headers.get("Strict-Transport-Security"):
                self._add_finding(Finding(
                    rule_id="EASM-HTTP-001",
                    name="Missing Strict-Transport-Security Header",
                    category="Security Header",
                    severity="MEDIUM",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[6]["description"],
                    recommendation=EXPOSURE_RULES[6]["recommendation"],
                    cwe="CWE-319",
                ))

            # Missing CSP
            if not hr.headers.get("Content-Security-Policy"):
                self._add_finding(Finding(
                    rule_id="EASM-HTTP-002",
                    name="Missing Content-Security-Policy Header",
                    category="Security Header",
                    severity="LOW",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[7]["description"],
                    recommendation=EXPOSURE_RULES[7]["recommendation"],
                    cwe="CWE-79",
                ))

            # Missing X-Content-Type-Options
            if not hr.headers.get("X-Content-Type-Options"):
                self._add_finding(Finding(
                    rule_id="EASM-HTTP-003",
                    name="Missing X-Content-Type-Options Header",
                    category="Security Header",
                    severity="LOW",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[8]["description"],
                    recommendation=EXPOSURE_RULES[8]["recommendation"],
                    cwe="CWE-16",
                ))

            # Server version disclosure
            server = hr.headers.get("Server", hr.server)
            if server and any(c.isdigit() for c in server):
                self._add_finding(Finding(
                    rule_id="EASM-HTTP-004",
                    name="Server Version Disclosed",
                    category="Information Disclosure",
                    severity="INFO",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[9]["description"],
                    recommendation=EXPOSURE_RULES[9]["recommendation"],
                    cwe="CWE-200",
                    evidence=f"Server: {server}",
                ))

            # Missing X-Frame-Options
            if not hr.headers.get("X-Frame-Options"):
                self._add_finding(Finding(
                    rule_id="EASM-HTTP-005",
                    name="Missing X-Frame-Options Header",
                    category="Security Header",
                    severity="LOW",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[10]["description"],
                    recommendation=EXPOSURE_RULES[10]["recommendation"],
                    cwe="CWE-1021",
                ))

            # HTTP without TLS
            if hr.url.startswith("http://") and hr.status_code < 400:
                self._add_finding(Finding(
                    rule_id="EASM-TLS-001",
                    name="HTTP Service Without TLS",
                    category="TLS/SSL",
                    severity="MEDIUM",
                    asset_value=hr.url,
                    asset_type="url",
                    description=EXPOSURE_RULES[11]["description"],
                    recommendation=EXPOSURE_RULES[11]["recommendation"],
                    cwe="CWE-319",
                ))

    def _add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.store.add_finding(finding)

    # ── Reporting ───────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a summary dict of the scan."""
        elapsed = self.end_time - self.start_time if self.end_time else 0
        sev_counts = Counter(f.severity for f in self.findings)
        asset_counts = {
            t: self.store.count_assets(t)
            for t in ("domain", "ip", "port", "url", "asn", "cidr")
        }
        # Phase 2 enrichment stats
        enrichment = {
            "whois_records": len(self.whois_records),
            "tls_analyzed": len(self.tls_results),
            "geoip_resolved": len(self.geoip_results),
            "tech_fingerprinted": len(self.tech_profiles),
            "attributed": sum(
                1 for r in self.attribution_results
                if r.verdict == "attributed"
            ),
            "review": sum(
                1 for r in self.attribution_results
                if r.verdict == "review"
            ),
        }
        # Phase 3 vuln assessment stats
        vuln_assessment = {
            "cves_detected": len(self.vuln_results),
            "nuclei_findings": len(self.nuclei_results),
            "takeover_vulnerable": sum(
                1 for t in self.takeover_results if t.vulnerable
            ),
            "misconfigurations": len(self.misconfig_results),
            "default_creds_found": sum(
                1 for c in self.cred_results if c.success
            ),
            "dns_security_findings": sum(
                len(r.findings) for r in self.dns_sec_results.values()
            ),
            "public_buckets": len(self.cloud_results),
            "risk_scores_computed": len(self.risk_scores),
        }
        graph_stats = self.graph.stats()
        return {
            "version": __version__,
            "scan_time": f"{elapsed:.1f}s",
            "seeds": self.seed_mgr.seeds.summary,
            "assets": asset_counts,
            "total_assets": self.store.count_assets(),
            "findings": dict(sev_counts),
            "total_findings": len(self.findings),
            "enrichment": enrichment,
            "vuln_assessment": vuln_assessment,
            "graph": graph_stats,
        }

    def print_report(self, min_severity: str = "INFO") -> None:
        """Print a console report."""
        min_rank = SEVERITY_ORDER.get(min_severity.upper(), 4)

        # ── Summary section ──
        s = self.summary()
        elapsed = self.end_time - self.start_time
        print()
        print(f"{'=' * 70}")
        print(f"{BOLD}  EASM Scan Summary{RESET}")
        print(f"{'=' * 70}")
        print(f"  Scan time     : {elapsed:.1f}s")
        print(f"  Seeds         : {s['seeds']}")
        print()
        print(f"  {BOLD}Assets Discovered:{RESET}")
        for atype, count in s["assets"].items():
            if count > 0:
                print(f"    {atype:<12}: {count}")
        print(f"    {'total':<12}: {s['total_assets']}")
        print()
        print(f"  {BOLD}Security Findings:{RESET}")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = s["findings"].get(sev, 0)
            if cnt > 0:
                color = SEVERITY_COLOR.get(sev, "")
                print(f"    {color}{sev:<12}{RESET}: {cnt}")
        print(f"    {'total':<12}: {s['total_findings']}")

        # ── Enrichment stats ──
        enr = s.get("enrichment", {})
        if any(enr.values()):
            print()
            print(f"  {BOLD}Enrichment:{RESET}")
            if enr.get("whois_records"):
                print(f"    WHOIS       : {enr['whois_records']} domain(s)")
            if enr.get("tls_analyzed"):
                print(f"    TLS         : {enr['tls_analyzed']} endpoint(s)")
            if enr.get("geoip_resolved"):
                print(f"    GeoIP       : {enr['geoip_resolved']} IP(s)")
            if enr.get("tech_fingerprinted"):
                print(f"    Tech FP     : {enr['tech_fingerprinted']} URL(s)")
            if enr.get("attributed") or enr.get("review"):
                print(f"    Attributed  : {enr.get('attributed', 0)} "
                      f"(+{enr.get('review', 0)} review)")

        # ── Vuln assessment stats ──
        va = s.get("vuln_assessment", {})
        if any(va.values()):
            print()
            print(f"  {BOLD}Vulnerability Assessment:{RESET}")
            if va.get("cves_detected"):
                print(f"    CVEs        : {va['cves_detected']}")
            if va.get("nuclei_findings"):
                print(f"    Nuclei      : {va['nuclei_findings']}")
            if va.get("takeover_vulnerable"):
                print(f"    Takeover    : {va['takeover_vulnerable']}")
            if va.get("misconfigurations"):
                print(f"    Misconfigs  : {va['misconfigurations']}")
            if va.get("default_creds_found"):
                print(f"    Def. Creds  : {va['default_creds_found']}")
            if va.get("dns_security_findings"):
                print(f"    DNS Issues  : {va['dns_security_findings']}")
            if va.get("public_buckets"):
                print(f"    Pub Buckets : {va['public_buckets']}")
            if va.get("risk_scores_computed"):
                print(f"    Risk Scored : {va['risk_scores_computed']}")

        grph = s.get("graph", {})
        if grph.get("total_nodes"):
            print()
            print(f"  {BOLD}Asset Graph:{RESET}")
            print(f"    Nodes       : {grph['total_nodes']}")
            print(f"    Edges       : {grph['total_edges']}")

        print(f"{'=' * 70}")

        # ── Findings detail ──
        filtered = [
            f for f in self.findings
            if f.severity_rank <= min_rank
        ]
        filtered.sort(key=lambda f: f.severity_rank)

        if not filtered:
            print(f"\n  No findings at severity >= {min_severity}.\n")
            return

        print(f"\n{BOLD}  Findings (>= {min_severity}):{RESET}\n")
        for i, f in enumerate(filtered, 1):
            color = SEVERITY_COLOR.get(f.severity, "")
            print(f"  {BOLD}[{i}]{RESET} {color}[{f.severity}]{RESET} "
                  f"{f.rule_id} — {f.name}")
            print(f"      Asset   : {f.asset_value}")
            if f.evidence:
                print(f"      Evidence: {f.evidence[:120]}")
            if f.description:
                print(f"      Desc    : {f.description[:120]}")
            if f.recommendation:
                print(f"      Fix     : {f.recommendation[:120]}")
            print()

    def save_json(self, filepath: str) -> None:
        """Save scan results as JSON."""
        data = {
            "easm_scanner_version": __version__,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": self.summary(),
            "assets": [
                a.to_dict()
                for a in self.store.get_assets()
            ],
            "findings": [f.to_dict() for f in self.findings],
            "whois": {
                d: r.to_dict()
                for d, r in self.whois_records.items()
            },
            "tls": [t.to_dict() for t in self.tls_results],
            "geoip": {
                ip: g.to_dict()
                for ip, g in self.geoip_results.items()
            },
            "attribution": [
                r.to_dict() for r in self.attribution_results
            ],
            "graph": self.graph.to_dict(),
            # Phase 3 data
            "vulnerabilities": [
                v.to_dict() for v in self.vuln_results
            ],
            "nuclei": [
                n.to_dict() for n in self.nuclei_results
            ],
            "takeover": [
                t.to_dict() for t in self.takeover_results
                if t.vulnerable or t.cname_target
            ],
            "misconfigurations": [
                m.to_dict() for m in self.misconfig_results
            ],
            "default_credentials": [
                c.to_dict() for c in self.cred_results if c.success
            ],
            "dns_security": {
                d: r.to_dict()
                for d, r in self.dns_sec_results.items()
            },
            "cloud_storage": [
                c.to_dict() for c in self.cloud_results
            ],
            "risk_scores": [
                r.to_dict() for r in self.risk_scores
            ],
        }
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        print(f"  JSON report saved -> {filepath}")

    def save_html(self, filepath: str) -> None:
        """Save scan results as an HTML report."""
        s = self.summary()
        elapsed = self.end_time - self.start_time
        findings_sorted = sorted(
            self.findings, key=lambda f: f.severity_rank
        )

        # Collect assets by type for the asset inventory
        asset_sections: list[str] = []
        for atype in ("domain", "ip", "port", "url", "asn", "cidr"):
            assets = self.store.get_assets(asset_type=atype)
            if not assets:
                continue
            rows = ""
            for a in assets[:500]:  # cap per section
                attrs_str = html_mod.escape(
                    json.dumps(a.attributes, default=str)[:200]
                )
                rows += (
                    f"<tr>"
                    f"<td>{html_mod.escape(a.value)}</td>"
                    f"<td>{html_mod.escape(a.parent)}</td>"
                    f"<td>{', '.join(a.sources)}</td>"
                    f"<td class='attrs'>{attrs_str}</td>"
                    f"<td>{a.first_seen[:19]}</td>"
                    f"</tr>\n"
                )
            asset_sections.append(f"""
            <div class="section">
              <h2>{atype.upper()} ({len(assets)})</h2>
              <table>
                <tr><th>Value</th><th>Parent</th><th>Sources</th>
                    <th>Attributes</th><th>First Seen</th></tr>
                {rows}
              </table>
            </div>""")

        # Build findings table
        finding_rows = ""
        for f in findings_sorted:
            sev_class = f.severity.lower()
            finding_rows += (
                f"<tr class='{sev_class}'>"
                f"<td><span class='sev {sev_class}'>{f.severity}</span></td>"
                f"<td>{html_mod.escape(f.rule_id)}</td>"
                f"<td>{html_mod.escape(f.name)}</td>"
                f"<td>{html_mod.escape(f.asset_value)}</td>"
                f"<td>{html_mod.escape(f.evidence[:150])}</td>"
                f"<td>{html_mod.escape(f.recommendation[:150])}</td>"
                f"</tr>\n"
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EASM Scan Report</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d;
           --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
           --red: #f85149; --orange: #d29922; --cyan: #39d2c0; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
          Helvetica, Arial, sans-serif; font-size: 14px; padding: 24px; }}
  .header {{ background: linear-gradient(135deg, #1a73e8, #0d47a1);
             border-radius: 12px; padding: 32px; margin-bottom: 24px;
             text-align: center; }}
  .header h1 {{ color: #fff; font-size: 28px; margin-bottom: 8px; }}
  .header p {{ color: rgba(255,255,255,0.8); font-size: 14px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit,
            minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 8px; padding: 20px; text-align: center; }}
  .card .num {{ font-size: 32px; font-weight: 700; color: var(--accent); }}
  .card .label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
  .card.critical .num {{ color: var(--red); }}
  .card.high .num {{ color: #f85149; }}
  .card.medium .num {{ color: var(--orange); }}
  .section {{ background: var(--card); border: 1px solid var(--border);
              border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 18px; margin-bottom: 12px; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom:
            1px solid var(--border); font-size: 13px; }}
  th {{ color: #8b949e; font-weight: 600; background: rgba(0,0,0,0.2); }}
  td.attrs {{ max-width: 250px; overflow: hidden; text-overflow: ellipsis;
              white-space: nowrap; font-size: 11px; color: #8b949e; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-weight: 600;
          font-size: 11px; text-transform: uppercase; }}
  .sev.critical {{ background: rgba(248,81,73,0.2); color: #f85149; }}
  .sev.high {{ background: rgba(248,81,73,0.15); color: #f85149; }}
  .sev.medium {{ background: rgba(210,153,34,0.2); color: #d29922; }}
  .sev.low {{ background: rgba(57,210,192,0.2); color: #39d2c0; }}
  .sev.info {{ background: rgba(139,148,158,0.2); color: #8b949e; }}
  .filters {{ margin-bottom: 16px; }}
  .filters button {{ background: var(--card); border: 1px solid var(--border);
                     color: var(--text); padding: 6px 14px; border-radius: 6px;
                     cursor: pointer; margin-right: 6px; font-size: 12px; }}
  .filters button:hover, .filters button.active
    {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
  footer {{ text-align: center; color: #484f58; margin-top: 32px;
            font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <h1>EASM — External Attack Surface Report</h1>
  <p>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
     &nbsp;|&nbsp; Scan time: {elapsed:.1f}s
     &nbsp;|&nbsp; Seeds: {html_mod.escape(s['seeds'])}</p>
</div>

<div class="cards">
  <div class="card"><div class="num">{s['total_assets']}</div>
    <div class="label">Total Assets</div></div>
  <div class="card"><div class="num">{s['assets'].get('domain',0)}</div>
    <div class="label">Domains</div></div>
  <div class="card"><div class="num">{s['assets'].get('ip',0)}</div>
    <div class="label">IPs</div></div>
  <div class="card"><div class="num">{s['assets'].get('port',0)}</div>
    <div class="label">Open Ports</div></div>
  <div class="card"><div class="num">{s['assets'].get('url',0)}</div>
    <div class="label">Live URLs</div></div>
  <div class="card critical"><div class="num">{s['findings'].get('CRITICAL',0)}</div>
    <div class="label">Critical</div></div>
  <div class="card high"><div class="num">{s['findings'].get('HIGH',0)}</div>
    <div class="label">High</div></div>
  <div class="card medium"><div class="num">{s['findings'].get('MEDIUM',0)}</div>
    <div class="label">Medium</div></div>
</div>

<div class="section">
  <h2>Security Findings ({s['total_findings']})</h2>
  <div class="filters">
    <button class="active" onclick="filterSev('all')">All</button>
    <button onclick="filterSev('critical')">Critical</button>
    <button onclick="filterSev('high')">High</button>
    <button onclick="filterSev('medium')">Medium</button>
    <button onclick="filterSev('low')">Low</button>
    <button onclick="filterSev('info')">Info</button>
  </div>
  <table id="findings-table">
    <tr><th>Severity</th><th>Rule</th><th>Name</th><th>Asset</th>
        <th>Evidence</th><th>Recommendation</th></tr>
    {finding_rows}
  </table>
</div>

{''.join(asset_sections)}

<footer>
  EASM Scanner v{__version__} &mdash; External Attack Surface Management
</footer>

<script>
function filterSev(sev) {{
  const rows = document.querySelectorAll('#findings-table tr');
  rows.forEach((r, i) => {{
    if (i === 0) return;
    r.style.display = (sev === 'all' || r.classList.contains(sev))
                       ? '' : 'none';
  }});
  document.querySelectorAll('.filters button').forEach(b => {{
    b.classList.toggle('active',
      b.textContent.toLowerCase() === sev ||
      (sev === 'all' && b.textContent === 'All'));
  }});
}}
</script>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"  HTML report saved -> {filepath}")

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _banner() -> None:
        print(f"""
{BOLD}+==============================================================+
|     EASM -- External Attack Surface Management Scanner       |
|                      v{__version__}                               |
+==============================================================+{RESET}
""")

    @staticmethod
    def _phase(step: str, title: str) -> None:
        print(f"\n{BOLD}  [{step}] {title}{RESET}")
        print(f"  {'-' * 56}")

    @staticmethod
    def _phase_done() -> None:
        print(f"\n{BOLD}  Pipeline complete.{RESET}\n")


# ════════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="easm_scanner",
        description=(
            "EASM — External Attack Surface Management Scanner v"
            + __version__
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python easm_scanner.py -d example.com
  python easm_scanner.py -d example.com acme.org --html report.html
  python easm_scanner.py -d example.com --asn AS15169 --json scan.json
  python easm_scanner.py --seed-file targets.txt --severity HIGH
  python easm_scanner.py -d example.com --skip-ports --verbose
""",
    )
    parser.add_argument(
        "-d", "--domains", nargs="+", metavar="DOMAIN",
        help="Root domain(s) to scan",
    )
    parser.add_argument(
        "-i", "--ips", nargs="+", metavar="IP",
        help="IP address(es) to scan",
    )
    parser.add_argument(
        "--asn", nargs="+", metavar="ASN",
        help="ASN(s) to expand (e.g. AS15169)",
    )
    parser.add_argument(
        "--cidr", nargs="+", metavar="CIDR",
        help="CIDR range(s) to scan (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "--org", metavar="NAME",
        help="Organisation name (for attribution context)",
    )
    parser.add_argument(
        "--seed-file", metavar="FILE",
        help="File containing seeds (one per line: domains, IPs, CIDRs, ASNs)",
    )
    parser.add_argument(
        "--brute-wordlist", metavar="FILE",
        help="Wordlist for subdomain brute-force",
    )
    parser.add_argument(
        "--json", metavar="FILE", dest="json_file",
        help="Save results as JSON",
    )
    parser.add_argument(
        "--html", metavar="FILE", dest="html_file",
        help="Save results as HTML report",
    )
    parser.add_argument(
        "--severity", metavar="LEVEL", default="INFO",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Minimum severity to display (default: INFO)",
    )
    parser.add_argument(
        "--db", metavar="FILE", default=":memory:",
        help="SQLite database path for persistent storage",
    )
    parser.add_argument(
        "--threads", type=int, default=50,
        help="Concurrent threads (default: 50)",
    )
    parser.add_argument(
        "--skip-ports", action="store_true",
        help="Skip port scanning phase",
    )
    parser.add_argument(
        "--skip-http", action="store_true",
        help="Skip HTTP probing phase",
    )
    parser.add_argument(
        "--skip-enrichment", action="store_true",
        help="Skip Phase 2 enrichment (WHOIS, TLS, GeoIP, Tech, Attribution)",
    )
    parser.add_argument(
        "--screenshot-dir", metavar="DIR", default="screenshots",
        help="Directory for screenshots (default: screenshots)",
    )
    # Phase 3 options
    parser.add_argument(
        "--skip-vuln-assessment", action="store_true",
        help="Skip Phase 3 vulnerability assessment",
    )
    parser.add_argument(
        "--skip-nuclei", action="store_true",
        help="Skip Nuclei template scanning",
    )
    parser.add_argument(
        "--skip-cred-test", action="store_true",
        help="Skip default credential testing",
    )
    parser.add_argument(
        "--nuclei-templates", metavar="DIR",
        help="Custom Nuclei templates directory",
    )
    # Phase 4 options
    parser.add_argument(
        "--serve", action="store_true",
        help="Start REST API server after scan (requires fastapi, uvicorn)",
    )
    parser.add_argument(
        "--port", type=int, default=8888,
        help="API server port (default: 8888)",
    )
    parser.add_argument(
        "--schedule", type=int, metavar="MINUTES", default=0,
        help="Run scans on a schedule (interval in minutes)",
    )
    parser.add_argument(
        "--alert-slack", metavar="URL",
        help="Slack webhook URL for alerts",
    )
    parser.add_argument(
        "--alert-teams", metavar="URL",
        help="Microsoft Teams webhook URL for alerts",
    )
    parser.add_argument(
        "--alert-webhook", metavar="URL",
        help="Generic webhook URL for alerts",
    )
    parser.add_argument(
        "--alert-email-to", nargs="+", metavar="EMAIL",
        help="Email recipient(s) for alerts",
    )
    parser.add_argument(
        "--siem-splunk-url", metavar="URL",
        help="Splunk HEC URL for SIEM export",
    )
    parser.add_argument(
        "--siem-splunk-token", metavar="TOKEN",
        help="Splunk HEC token",
    )
    parser.add_argument(
        "--siem-elastic-url", metavar="URL",
        help="Elasticsearch URL for SIEM export",
    )
    parser.add_argument(
        "--siem-csv", metavar="FILE",
        help="Export findings to CSV file",
    )
    parser.add_argument(
        "--siem-jsonl", metavar="FILE",
        help="Export findings to JSON Lines file",
    )
    parser.add_argument(
        "--jira-url", metavar="URL",
        help="Jira server URL for ticket creation",
    )
    parser.add_argument(
        "--jira-project", metavar="KEY",
        help="Jira project key (e.g. SEC)",
    )
    parser.add_argument(
        "--jira-token", metavar="TOKEN",
        help="Jira API token or password",
    )
    parser.add_argument(
        "--jira-user", metavar="EMAIL",
        help="Jira username or email",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Validate: at least one seed source (unless --serve alone)
    if not args.serve and not any([args.domains, args.ips, args.asn,
                                   args.cidr, args.seed_file]):
        parser.error(
            "Provide at least one seed: -d DOMAIN, -i IP, --asn, "
            "--cidr, or --seed-file"
        )

    scanner = EASMScanner(
        verbose=args.verbose,
        threads=args.threads,
        db_path=args.db,
        screenshot_dir=args.screenshot_dir,
    )

    # ── Phase 4: Configure alerting ──────────────────
    alert_engine = None
    alert_configs = []
    from modules.alerting import AlertConfig, AlertEngine
    if args.alert_slack:
        alert_configs.append(AlertConfig(
            channel="slack", slack_webhook_url=args.alert_slack,
        ))
    if args.alert_teams:
        alert_configs.append(AlertConfig(
            channel="teams", teams_webhook_url=args.alert_teams,
        ))
    if args.alert_webhook:
        alert_configs.append(AlertConfig(
            channel="webhook", webhook_url=args.alert_webhook,
        ))
    if args.alert_email_to:
        alert_configs.append(AlertConfig(
            channel="email",
            email_to=args.alert_email_to,
            smtp_host=os.environ.get("SMTP_HOST", ""),
            smtp_port=int(os.environ.get("SMTP_PORT", "587")),
            smtp_user=os.environ.get("SMTP_USER", ""),
            smtp_password=os.environ.get("SMTP_PASSWORD", ""),
            email_from=os.environ.get("SMTP_FROM", ""),
        ))
    if alert_configs:
        alert_engine = AlertEngine(
            configs=alert_configs, verbose=args.verbose,
        )
    else:
        # Console fallback always available
        alert_engine = AlertEngine(
            configs=[AlertConfig(channel="console")],
            verbose=args.verbose,
        )

    # ── Run scan (if seeds provided) ─────────────────
    if any([args.domains, args.ips, args.asn, args.cidr, args.seed_file]):
        scanner.run(
            domains=args.domains,
            ips=args.ips,
            asns=args.asn,
            cidrs=args.cidr,
            org_name=args.org or "",
            seed_file=args.seed_file,
            brute_wordlist=args.brute_wordlist,
            skip_ports=args.skip_ports,
            skip_http=args.skip_http,
            skip_enrichment=args.skip_enrichment,
            skip_vuln_assessment=args.skip_vuln_assessment,
            skip_nuclei=args.skip_nuclei,
            skip_cred_test=args.skip_cred_test,
            nuclei_templates=args.nuclei_templates,
        )

        scanner.print_report(min_severity=args.severity)

        if args.json_file:
            scanner.save_json(args.json_file)
        if args.html_file:
            scanner.save_html(args.html_file)

        # ── Phase 4: Send alerts on findings ─────────
        critical_high = [
            f.to_dict() for f in scanner.findings
            if f.severity in ("CRITICAL", "HIGH")
        ]
        if critical_high and alert_engine:
            print(f"\n  {BOLD}Sending alerts...{RESET}")
            alert_results = alert_engine.send_alerts(
                critical_high, scanner.summary(),
            )
            for ar in alert_results:
                status = "sent" if ar.success else f"FAILED: {ar.error}"
                print(f"    [{ar.channel}] {status} "
                      f"({ar.findings_count} findings)")

        # ── Phase 4: SIEM export ─────────────────────
        from modules.siem_export import SIEMExporter, SIEMConfig
        finding_dicts = [f.to_dict() for f in scanner.findings]
        siem_exporter = SIEMExporter(verbose=args.verbose)

        if args.siem_splunk_url:
            siem_exporter.export(
                SIEMConfig(
                    target="splunk_hec",
                    splunk_url=args.siem_splunk_url,
                    splunk_token=args.siem_splunk_token or "",
                ),
                finding_dicts,
                scan_summary=scanner.summary(),
            )

        if args.siem_elastic_url:
            siem_exporter.export(
                SIEMConfig(
                    target="elasticsearch",
                    es_url=args.siem_elastic_url,
                ),
                finding_dicts,
                scan_summary=scanner.summary(),
            )

        if args.siem_csv:
            siem_exporter.export(
                SIEMConfig(target="csv", output_path=args.siem_csv),
                finding_dicts,
                scan_summary=scanner.summary(),
            )

        if args.siem_jsonl:
            siem_exporter.export(
                SIEMConfig(target="jsonl", output_path=args.siem_jsonl),
                finding_dicts,
                scan_summary=scanner.summary(),
            )

        # ── Phase 4: Jira integration ────────────────
        if args.jira_url and args.jira_project:
            from modules.jira_integration import (
                JiraIntegration, JiraConfig,
            )
            jira = JiraIntegration(JiraConfig(
                url=args.jira_url,
                project_key=args.jira_project,
                username=args.jira_user or "",
                api_token=args.jira_token or "",
            ), verbose=args.verbose)
            jira_findings = [
                f.to_dict() for f in scanner.findings
                if f.severity in ("CRITICAL", "HIGH")
            ]
            if jira_findings:
                print(f"\n  {BOLD}Creating Jira tickets...{RESET}")
                tickets = jira.create_tickets(jira_findings)
                created = sum(1 for t in tickets if t.success)
                print(f"    Created {created}/{len(tickets)} ticket(s)")

    # ── Phase 4: Start API server ────────────────────
    if args.serve:
        from api.server import create_app, run_server
        run_server(scanner=scanner, port=args.port)
        return 0

    # ── Phase 4: Scheduled scanning ──────────────────
    if args.schedule > 0:
        from modules.scheduler import ScanScheduler, ScanProfile
        scheduler = ScanScheduler(
            db_path=args.db if args.db != ":memory:" else "easm_scheduler.db",
            verbose=args.verbose,
        )
        profile = ScanProfile(
            name="cli-schedule",
            domains=args.domains or [],
            ips=args.ips or [],
            asns=args.asn or [],
            cidrs=args.cidr or [],
            org_name=args.org or "",
            interval_minutes=args.schedule,
            skip_ports=args.skip_ports,
            skip_http=args.skip_http,
            skip_enrichment=args.skip_enrichment,
            skip_vuln_assessment=args.skip_vuln_assessment,
            skip_nuclei=args.skip_nuclei,
            skip_cred_test=args.skip_cred_test,
        )

        def scan_callback(prof):
            s = EASMScanner(
                verbose=args.verbose, threads=args.threads,
                db_path=args.db,
            )
            s.run(
                domains=prof.domains or None,
                ips=prof.ips or None,
                asns=prof.asns or None,
                cidrs=prof.cidrs or None,
                org_name=prof.org_name,
                skip_ports=prof.skip_ports,
                skip_http=prof.skip_http,
                skip_enrichment=prof.skip_enrichment,
                skip_vuln_assessment=prof.skip_vuln_assessment,
                skip_nuclei=prof.skip_nuclei,
                skip_cred_test=prof.skip_cred_test,
            )
            return {
                "findings": [f.to_dict() for f in s.findings],
                "assets": [a.to_dict() for a in s.store.get_assets()],
                "summary": s.summary(),
            }

        def on_new_findings(findings, summary):
            if alert_engine:
                alert_engine.send_alerts(findings, summary)

        print(f"\n  {BOLD}Starting scheduled scans "
              f"(every {args.schedule} min)...{RESET}")
        try:
            scheduler.run_scheduled(
                profile, scan_callback,
                on_new_findings=on_new_findings,
            )
        except KeyboardInterrupt:
            print("\n  Scheduled scanning stopped.")
        return 0

    # Exit code: 1 if CRITICAL or HIGH findings
    has_critical = any(
        f.severity in ("CRITICAL", "HIGH") for f in scanner.findings
    )
    return 1 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
