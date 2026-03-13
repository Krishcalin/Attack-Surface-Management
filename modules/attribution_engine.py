"""
EASM Scanner -- Attribution Engine
Multi-signal organizational attribution: determines whether a discovered
asset belongs to the target organization.

Signals and confidence weights:
  - WHOIS registrant match       0.90
  - ASN ownership                0.95
  - Name server match            0.70
  - Certificate SAN correlation  0.85
  - Certificate org field        0.80
  - Favicon hash match           0.60
  - Web content / brand keywords 0.50
  - Shared IP / infrastructure   0.40
  - DNS CNAME chain              0.65
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from models.asset import Asset


# ── Signal weights ──────────────────────────────────────────────────

SIGNAL_WEIGHTS: dict[str, float] = {
    "whois_registrant_org": 0.90,
    "whois_registrant_email": 0.85,
    "whois_registrant_name": 0.80,
    "asn_ownership": 0.95,
    "nameserver_match": 0.70,
    "cert_san_correlation": 0.85,
    "cert_org_field": 0.80,
    "favicon_hash_match": 0.60,
    "brand_keyword_match": 0.50,
    "shared_infrastructure": 0.40,
    "cname_chain": 0.65,
    "mx_match": 0.55,
    "seed_domain": 1.00,
}

# Confidence thresholds
THRESHOLD_AUTO = 0.70       # auto-attribute
THRESHOLD_REVIEW = 0.40     # flag for human review


@dataclass
class AttributionSignal:
    """A single attribution evidence signal."""
    signal_type: str
    description: str
    weight: float
    source_asset: str = ""
    target_asset: str = ""


@dataclass
class AttributionResult:
    """Attribution verdict for a single asset."""
    asset_value: str
    asset_type: str
    org_name: str = ""
    confidence: float = 0.0
    signals: list[AttributionSignal] = field(default_factory=list)
    verdict: str = ""          # "attributed", "review", "unattributed"

    def to_dict(self) -> dict:
        return {
            "asset": self.asset_value,
            "type": self.asset_type,
            "org": self.org_name,
            "confidence": round(self.confidence, 3),
            "verdict": self.verdict,
            "signals": [
                {
                    "type": s.signal_type,
                    "weight": s.weight,
                    "description": s.description,
                }
                for s in self.signals
            ],
        }


class AttributionEngine:
    """Multi-signal organizational attribution engine."""

    def __init__(
        self,
        org_name: str = "",
        seed_domains: Optional[list[str]] = None,
        verbose: bool = False,
    ) -> None:
        self.org_name = org_name.lower().strip()
        self.seed_domains = [d.lower() for d in (seed_domains or [])]
        self.verbose = verbose

        # Build org keywords from name
        self.org_keywords: list[str] = []
        if self.org_name:
            # Split on spaces, hyphens, dots
            words = re.split(r"[\s\-\.]+", self.org_name)
            self.org_keywords = [w for w in words if len(w) >= 3]

        # Known infrastructure (populated during enrichment)
        self.known_nameservers: set[str] = set()
        self.known_asns: set[str] = set()
        self.known_favicon_hashes: set[str] = set()
        self.known_registrant_orgs: set[str] = set()
        self.known_registrant_emails: set[str] = set()
        self.known_ips: set[str] = set()

    # ── Public API ──────────────────────────────────────────

    def learn_from_seeds(
        self,
        whois_records: Optional[dict] = None,
        asn_info: Optional[dict] = None,
        dns_records: Optional[dict] = None,
        http_results: Optional[list] = None,
    ) -> None:
        """Learn organizational patterns from seed domain enrichment data."""

        if whois_records:
            for domain, rec in whois_records.items():
                if hasattr(rec, "registrant_org") and rec.registrant_org:
                    self.known_registrant_orgs.add(
                        rec.registrant_org.lower()
                    )
                if hasattr(rec, "registrant_email") and rec.registrant_email:
                    self.known_registrant_emails.add(
                        rec.registrant_email.lower()
                    )
                if hasattr(rec, "name_servers"):
                    for ns in rec.name_servers:
                        self.known_nameservers.add(ns.lower())

        if asn_info:
            for asn, info in asn_info.items():
                self.known_asns.add(asn.upper())

        if http_results:
            for hr in http_results:
                fav = getattr(hr, "favicon_hash", "") or ""
                if isinstance(fav, str):
                    fav_val = fav
                else:
                    fav_val = hr.get("favicon_hash", "") if isinstance(hr, dict) else ""
                if fav_val:
                    self.known_favicon_hashes.add(fav_val)

        self._vprint(
            f"    [attrib] learned: "
            f"{len(self.known_registrant_orgs)} org(s), "
            f"{len(self.known_nameservers)} NS, "
            f"{len(self.known_asns)} ASN(s), "
            f"{len(self.known_favicon_hashes)} favicon(s)"
        )

    def attribute(
        self,
        asset_value: str,
        asset_type: str,
        whois_record: Optional[Any] = None,
        asn_info: Optional[Any] = None,
        tls_info: Optional[Any] = None,
        geoip_info: Optional[Any] = None,
        http_result: Optional[Any] = None,
        parent_domain: str = "",
    ) -> AttributionResult:
        """Evaluate attribution for a single asset using all available signals."""

        result = AttributionResult(
            asset_value=asset_value,
            asset_type=asset_type,
            org_name=self.org_name,
        )

        # Signal 1: Seed domain match
        if asset_type == "domain":
            for seed in self.seed_domains:
                if asset_value == seed or asset_value.endswith("." + seed):
                    result.signals.append(AttributionSignal(
                        signal_type="seed_domain",
                        weight=SIGNAL_WEIGHTS["seed_domain"],
                        description=f"Subdomain of seed {seed}",
                        source_asset=seed,
                        target_asset=asset_value,
                    ))
                    break

        # Signal 2: WHOIS registrant match
        if whois_record:
            self._check_whois(result, whois_record)

        # Signal 3: ASN ownership match
        if asn_info:
            self._check_asn(result, asn_info)

        # Signal 4: Certificate org / SAN correlation
        if tls_info:
            self._check_tls(result, tls_info)

        # Signal 5: Favicon hash match
        if http_result:
            self._check_http(result, http_result)

        # Signal 6: Brand keyword in content/title
        if http_result and self.org_keywords:
            self._check_brand(result, http_result)

        # Signal 7: Name server match
        if whois_record and hasattr(whois_record, "name_servers"):
            self._check_nameservers(result, whois_record)

        # Compute confidence (max signal -- not additive to avoid >1.0)
        if result.signals:
            # Use weighted combination: max + 0.1 * sum(others)
            weights = sorted(
                [s.weight for s in result.signals], reverse=True
            )
            result.confidence = weights[0]
            for w in weights[1:]:
                result.confidence = min(
                    1.0, result.confidence + 0.1 * w
                )

        # Verdict
        if result.confidence >= THRESHOLD_AUTO:
            result.verdict = "attributed"
        elif result.confidence >= THRESHOLD_REVIEW:
            result.verdict = "review"
        else:
            result.verdict = "unattributed"

        return result

    def bulk_attribute(
        self,
        assets: list[dict[str, Any]],
    ) -> list[AttributionResult]:
        """Attribute multiple assets. Each dict should have at least
        'value', 'type' and optionally enrichment data."""
        results = []
        for a in assets:
            results.append(self.attribute(
                asset_value=a.get("value", ""),
                asset_type=a.get("type", ""),
                whois_record=a.get("whois"),
                asn_info=a.get("asn"),
                tls_info=a.get("tls"),
                geoip_info=a.get("geoip"),
                http_result=a.get("http"),
                parent_domain=a.get("parent", ""),
            ))

        counts = {"attributed": 0, "review": 0, "unattributed": 0}
        for r in results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
        self._vprint(
            f"    [attrib] {counts['attributed']} attributed, "
            f"{counts['review']} for review, "
            f"{counts['unattributed']} unattributed"
        )
        return results

    # ── Signal checkers ─────────────────────────────────────

    def _check_whois(
        self, result: AttributionResult, rec: Any,
    ) -> None:
        org = getattr(rec, "registrant_org", "") or ""
        if org and self._fuzzy_match(org, self.known_registrant_orgs):
            result.signals.append(AttributionSignal(
                signal_type="whois_registrant_org",
                weight=SIGNAL_WEIGHTS["whois_registrant_org"],
                description=f"WHOIS org '{org}' matches known registrant",
            ))

        email = getattr(rec, "registrant_email", "") or ""
        if email and self._fuzzy_match(
            email, self.known_registrant_emails
        ):
            result.signals.append(AttributionSignal(
                signal_type="whois_registrant_email",
                weight=SIGNAL_WEIGHTS["whois_registrant_email"],
                description=f"WHOIS email '{email}' matches known registrant",
            ))

    def _check_asn(
        self, result: AttributionResult, asn_info: Any,
    ) -> None:
        asn = ""
        if hasattr(asn_info, "asn"):
            asn = asn_info.asn
        elif isinstance(asn_info, dict):
            asn = asn_info.get("asn", "")
        if asn and asn.upper() in self.known_asns:
            result.signals.append(AttributionSignal(
                signal_type="asn_ownership",
                weight=SIGNAL_WEIGHTS["asn_ownership"],
                description=f"IP in known ASN {asn}",
            ))

    def _check_tls(
        self, result: AttributionResult, tls_info: Any,
    ) -> None:
        issuer_org = getattr(tls_info, "issuer_org", "") or ""
        sans = getattr(tls_info, "sans", []) or []

        # Certificate org field
        if issuer_org and self.org_keywords:
            if any(kw in issuer_org.lower() for kw in self.org_keywords):
                result.signals.append(AttributionSignal(
                    signal_type="cert_org_field",
                    weight=SIGNAL_WEIGHTS["cert_org_field"],
                    description=f"Cert issuer org '{issuer_org}' matches keywords",
                ))

        # SAN correlation with seed domains
        for san in sans:
            san_lower = san.lower()
            for seed in self.seed_domains:
                if san_lower == seed or san_lower.endswith("." + seed):
                    result.signals.append(AttributionSignal(
                        signal_type="cert_san_correlation",
                        weight=SIGNAL_WEIGHTS["cert_san_correlation"],
                        description=f"Cert SAN '{san}' matches seed {seed}",
                    ))
                    return  # one match is enough

    def _check_http(
        self, result: AttributionResult, http_result: Any,
    ) -> None:
        fav = ""
        if hasattr(http_result, "favicon_hash"):
            fav = http_result.favicon_hash or ""
        elif isinstance(http_result, dict):
            fav = http_result.get("favicon_hash", "")

        if fav and fav in self.known_favicon_hashes:
            result.signals.append(AttributionSignal(
                signal_type="favicon_hash_match",
                weight=SIGNAL_WEIGHTS["favicon_hash_match"],
                description=f"Favicon hash matches known asset",
            ))

    def _check_brand(
        self, result: AttributionResult, http_result: Any,
    ) -> None:
        title = ""
        if hasattr(http_result, "title"):
            title = (http_result.title or "").lower()
        elif isinstance(http_result, dict):
            title = http_result.get("title", "").lower()

        for kw in self.org_keywords:
            if kw in title:
                result.signals.append(AttributionSignal(
                    signal_type="brand_keyword_match",
                    weight=SIGNAL_WEIGHTS["brand_keyword_match"],
                    description=f"Brand keyword '{kw}' found in page title",
                ))
                return  # one match is enough

    def _check_nameservers(
        self, result: AttributionResult, rec: Any,
    ) -> None:
        ns_list = getattr(rec, "name_servers", []) or []
        for ns in ns_list:
            if ns.lower() in self.known_nameservers:
                result.signals.append(AttributionSignal(
                    signal_type="nameserver_match",
                    weight=SIGNAL_WEIGHTS["nameserver_match"],
                    description=f"Name server '{ns}' matches known NS",
                ))
                return

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _fuzzy_match(value: str, known_set: set[str]) -> bool:
        """Case-insensitive substring match against known values."""
        val_lower = value.lower().strip()
        for known in known_set:
            if val_lower == known or known in val_lower or val_lower in known:
                return True
        return False

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
