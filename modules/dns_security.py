"""
EASM Scanner -- DNS Security Module
Checks email authentication and DNS security posture:
  - SPF record validation
  - DKIM selector probing
  - DMARC policy analysis
  - DNS zone transfer (AXFR) detection
  - CAA record checks
  - Dangling MX records
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ── Common DKIM selectors to probe ────────────────────────────────

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "s1", "s2", "mail", "dkim", "smtp",
    "mandrill", "everlytickey1", "mxvault",
    "protonmail", "protonmail2", "protonmail3",
    "cm", "sig1", "zendesk1", "zendesk2",
]


@dataclass
class DNSSecurityResult:
    """DNS security check result for a domain."""
    domain: str
    spf_record: str = ""
    spf_issues: list[str] = field(default_factory=list)
    dmarc_record: str = ""
    dmarc_policy: str = ""
    dmarc_issues: list[str] = field(default_factory=list)
    dkim_found: bool = False
    dkim_selectors: list[str] = field(default_factory=list)
    zone_transfer: bool = False
    zone_transfer_ns: str = ""
    caa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    mx_issues: list[str] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "spf_record": self.spf_record,
            "spf_issues": self.spf_issues,
            "dmarc_record": self.dmarc_record,
            "dmarc_policy": self.dmarc_policy,
            "dmarc_issues": self.dmarc_issues,
            "dkim_found": self.dkim_found,
            "dkim_selectors": self.dkim_selectors,
            "zone_transfer": self.zone_transfer,
            "caa_records": self.caa_records,
            "mx_records": self.mx_records,
            "mx_issues": self.mx_issues,
            "findings_count": len(self.findings),
        }


class DNSSecurityChecker:
    """Check DNS security posture for email auth and zone hardening."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def check(self, domain: str) -> DNSSecurityResult:
        """Run all DNS security checks for a domain."""
        result = DNSSecurityResult(domain=domain)

        # 1. SPF check
        self._check_spf(result)

        # 2. DMARC check
        self._check_dmarc(result)

        # 3. DKIM check
        self._check_dkim(result)

        # 4. Zone transfer check
        self._check_zone_transfer(result)

        # 5. CAA check
        self._check_caa(result)

        # 6. MX check
        self._check_mx(result)

        return result

    def bulk_check(
        self, domains: list[str],
    ) -> dict[str, DNSSecurityResult]:
        """Check multiple domains."""
        results: dict[str, DNSSecurityResult] = {}

        for domain in domains:
            results[domain] = self.check(domain)

        total_findings = sum(
            len(r.findings) for r in results.values()
        )
        self._vprint(
            f"    [dns-sec] checked {len(domains)} domain(s), "
            f"{total_findings} finding(s)"
        )
        return results

    # ── SPF ──────────────────────────────────────────────────

    def _check_spf(self, result: DNSSecurityResult) -> None:
        """Check SPF record."""
        txt_records = self._query_txt(result.domain)
        spf_records = [
            r for r in txt_records
            if r.lower().startswith("v=spf1")
        ]

        if not spf_records:
            result.spf_issues.append("No SPF record found")
            result.findings.append({
                "rule_id": "EASM-DNS-001",
                "name": "Missing SPF Record",
                "severity": "MEDIUM",
                "evidence": "No v=spf1 TXT record found",
                "description": (
                    "No SPF record exists, allowing anyone to spoof "
                    "emails from this domain."
                ),
                "recommendation": (
                    "Add an SPF TXT record (e.g., "
                    "'v=spf1 include:_spf.google.com ~all')."
                ),
                "cwe": "CWE-290",
            })
            return

        if len(spf_records) > 1:
            result.spf_issues.append(
                f"Multiple SPF records ({len(spf_records)})"
            )
            result.findings.append({
                "rule_id": "EASM-DNS-001",
                "name": "Multiple SPF Records",
                "severity": "MEDIUM",
                "evidence": f"{len(spf_records)} SPF records found",
                "description": (
                    "Multiple SPF records cause undefined behavior "
                    "per RFC 7208."
                ),
                "recommendation": "Merge into a single SPF record.",
                "cwe": "CWE-290",
            })

        spf = spf_records[0]
        result.spf_record = spf

        # Check for overly permissive SPF
        if "+all" in spf.lower():
            result.spf_issues.append("SPF uses +all (pass all)")
            result.findings.append({
                "rule_id": "EASM-DNS-002",
                "name": "Permissive SPF Record (+all)",
                "severity": "HIGH",
                "evidence": f"SPF: {spf}",
                "description": (
                    "SPF record uses +all which allows any server "
                    "to send email for this domain."
                ),
                "recommendation": "Change +all to ~all or -all.",
                "cwe": "CWE-290",
            })

        # Check for missing enforcement
        if spf.lower().endswith("?all"):
            result.spf_issues.append("SPF uses ?all (neutral)")
            result.findings.append({
                "rule_id": "EASM-DNS-002",
                "name": "Weak SPF Record (?all)",
                "severity": "MEDIUM",
                "evidence": f"SPF: {spf}",
                "description": (
                    "SPF record uses ?all (neutral) which provides "
                    "no protection against spoofing."
                ),
                "recommendation": "Change ?all to ~all or -all.",
                "cwe": "CWE-290",
            })

        # Count DNS lookups (max 10 per RFC)
        lookups = len(re.findall(
            r"\b(include:|a:|mx:|ptr:|redirect=|exists:)", spf, re.I
        ))
        if lookups > 10:
            result.spf_issues.append(
                f"SPF exceeds 10 DNS lookups ({lookups})"
            )
            result.findings.append({
                "rule_id": "EASM-DNS-002",
                "name": "SPF Record Exceeds DNS Lookup Limit",
                "severity": "MEDIUM",
                "evidence": f"SPF has {lookups} DNS lookups (max 10)",
                "description": (
                    "SPF records exceeding 10 DNS lookups will fail "
                    "validation (RFC 7208)."
                ),
                "recommendation": "Flatten SPF record using IP ranges.",
                "cwe": "",
            })

    # ── DMARC ────────────────────────────────────────────────

    def _check_dmarc(self, result: DNSSecurityResult) -> None:
        """Check DMARC record."""
        dmarc_domain = f"_dmarc.{result.domain}"
        txt_records = self._query_txt(dmarc_domain)

        dmarc_records = [
            r for r in txt_records
            if r.lower().startswith("v=dmarc1")
        ]

        if not dmarc_records:
            result.dmarc_issues.append("No DMARC record found")
            result.findings.append({
                "rule_id": "EASM-DNS-003",
                "name": "Missing DMARC Record",
                "severity": "MEDIUM",
                "evidence": f"No DMARC TXT record at {dmarc_domain}",
                "description": (
                    "No DMARC record exists. Email receiving servers "
                    "cannot verify email alignment."
                ),
                "recommendation": (
                    "Add a DMARC TXT record at _dmarc.domain.com "
                    "(start with p=none for monitoring)."
                ),
                "cwe": "CWE-290",
            })
            return

        dmarc = dmarc_records[0]
        result.dmarc_record = dmarc

        # Parse policy
        policy_match = re.search(r"p\s*=\s*(\w+)", dmarc, re.I)
        if policy_match:
            result.dmarc_policy = policy_match.group(1).lower()

        # Check policy strength
        if result.dmarc_policy == "none":
            result.dmarc_issues.append("DMARC policy is 'none' (monitoring only)")
            result.findings.append({
                "rule_id": "EASM-DNS-004",
                "name": "DMARC Policy Set to None",
                "severity": "LOW",
                "evidence": f"DMARC: {dmarc}",
                "description": (
                    "DMARC policy is 'none' which only monitors but "
                    "does not reject spoofed emails."
                ),
                "recommendation": (
                    "Upgrade to p=quarantine or p=reject after "
                    "verifying legitimate email sources."
                ),
                "cwe": "CWE-290",
            })

        # Check for missing rua (aggregate reports)
        if "rua=" not in dmarc.lower():
            result.dmarc_issues.append("No DMARC aggregate report URI")

        # Check subdomain policy
        sp_match = re.search(r"sp\s*=\s*(\w+)", dmarc, re.I)
        if not sp_match and result.dmarc_policy in ("quarantine", "reject"):
            result.dmarc_issues.append(
                "No subdomain policy (sp=); inherits parent"
            )

        # Check percentage
        pct_match = re.search(r"pct\s*=\s*(\d+)", dmarc, re.I)
        if pct_match and int(pct_match.group(1)) < 100:
            pct = pct_match.group(1)
            result.dmarc_issues.append(
                f"DMARC pct={pct} (not 100%)"
            )

    # ── DKIM ─────────────────────────────────────────────────

    def _check_dkim(self, result: DNSSecurityResult) -> None:
        """Probe for DKIM selectors."""
        for selector in COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{result.domain}"
            txt = self._query_txt(dkim_domain)
            dkim_records = [
                r for r in txt
                if "v=dkim1" in r.lower() or "p=" in r.lower()
            ]
            if dkim_records:
                result.dkim_found = True
                result.dkim_selectors.append(selector)

        if not result.dkim_found:
            result.findings.append({
                "rule_id": "EASM-DNS-005",
                "name": "No DKIM Records Found",
                "severity": "LOW",
                "evidence": (
                    f"Probed {len(COMMON_DKIM_SELECTORS)} common selectors"
                ),
                "description": (
                    "No DKIM records detected for common selectors. "
                    "DKIM provides email authentication via "
                    "cryptographic signatures."
                ),
                "recommendation": (
                    "Configure DKIM signing for outbound email."
                ),
                "cwe": "CWE-290",
            })

    # ── Zone transfer ────────────────────────────────────────

    def _check_zone_transfer(self, result: DNSSecurityResult) -> None:
        """Check if DNS zone transfer (AXFR) is allowed."""
        if not HAS_DNS:
            return

        # Get NS records
        try:
            ns_answers = dns.resolver.resolve(result.domain, "NS")
        except Exception:
            return

        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata.target).rstrip(".")
            try:
                # Resolve NS hostname to IP
                ns_ips = dns.resolver.resolve(ns_host, "A")
                for ns_ip in ns_ips:
                    try:
                        zone = dns.zone.from_xfr(
                            dns.query.xfr(
                                str(ns_ip), result.domain,
                                timeout=self.timeout,
                            )
                        )
                        if zone:
                            result.zone_transfer = True
                            result.zone_transfer_ns = ns_host
                            result.findings.append({
                                "rule_id": "EASM-DNS-006",
                                "name": "DNS Zone Transfer Allowed",
                                "severity": "HIGH",
                                "evidence": (
                                    f"AXFR succeeded on {ns_host} "
                                    f"({ns_ip}), "
                                    f"{len(zone.nodes)} record(s)"
                                ),
                                "description": (
                                    "DNS zone transfer is allowed, "
                                    "exposing all DNS records to anyone."
                                ),
                                "recommendation": (
                                    "Restrict AXFR to authorized "
                                    "secondary DNS servers only."
                                ),
                                "cwe": "CWE-200",
                            })
                            self._vprint(
                                f"    [dns-sec] {result.domain}: "
                                f"AXFR allowed on {ns_host}"
                            )
                            return  # One is enough

                    except Exception:
                        continue

            except Exception:
                continue

    # ── CAA ───────────────────────────────────────────────────

    def _check_caa(self, result: DNSSecurityResult) -> None:
        """Check CAA records."""
        if not HAS_DNS:
            return

        try:
            answers = dns.resolver.resolve(result.domain, "CAA")
            for rdata in answers:
                result.caa_records.append(str(rdata))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, Exception):
            pass

    # ── MX ───────────────────────────────────────────────────

    def _check_mx(self, result: DNSSecurityResult) -> None:
        """Check MX records for issues."""
        if not HAS_DNS:
            return

        try:
            answers = dns.resolver.resolve(result.domain, "MX")
            for rdata in answers:
                mx_host = str(rdata.exchange).rstrip(".")
                result.mx_records.append(
                    f"{rdata.preference} {mx_host}"
                )

                # Check if MX resolves
                try:
                    dns.resolver.resolve(mx_host, "A")
                except dns.resolver.NXDOMAIN:
                    result.mx_issues.append(
                        f"MX {mx_host} does not resolve (dangling)"
                    )
                    result.findings.append({
                        "rule_id": "EASM-DNS-005",
                        "name": "Dangling MX Record",
                        "severity": "MEDIUM",
                        "evidence": f"MX {mx_host} returns NXDOMAIN",
                        "description": (
                            "MX record points to a host that does not "
                            "resolve, potentially allowing email "
                            "interception."
                        ),
                        "recommendation": (
                            "Remove or update the MX record."
                        ),
                        "cwe": "CWE-200",
                    })
                except Exception:
                    pass

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, Exception):
            pass

    # ── DNS query helper ─────────────────────────────────────

    def _query_txt(self, domain: str) -> list[str]:
        """Query TXT records for a domain."""
        if HAS_DNS:
            try:
                answers = dns.resolver.resolve(domain, "TXT")
                records = []
                for rdata in answers:
                    # Concatenate multi-string TXT records
                    txt = "".join(
                        s.decode() if isinstance(s, bytes) else s
                        for s in rdata.strings
                    )
                    records.append(txt)
                return records
            except Exception:
                return []
        else:
            # Fallback: use nslookup or dig via subprocess
            return self._txt_fallback(domain)

    @staticmethod
    def _txt_fallback(domain: str) -> list[str]:
        """Fallback TXT lookup via socket (limited)."""
        # Cannot query TXT via socket; return empty
        return []

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
