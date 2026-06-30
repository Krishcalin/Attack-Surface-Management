"""
EASM Scanner -- Attack Surface Intelligence: Unknown-Asset Discovery
====================================================================
Discovers *unknown* organisation-owned assets by pivoting from known seeds --
the capability that turns Attack Surface Management into Attack Surface
Intelligence (cf. Recorded Future ASI).

v1 pivot: **certificate-SAN pivoting**. Domains that appear on the *same* TLS
certificate as a seed domain (via Certificate Transparency / crt.sh) are strong
candidates for sibling, subsidiary, or shadow-IT apex domains the org also owns.
Each candidate is corroborated with WHOIS/RDAP registrant data and brand-token
matching, then assigned a confidence score with human-readable reasons.

Design: all correlation/scoring logic is **pure** (no I/O) so it unit-tests with
synthetic data offline; network access (CT logs, WHOIS) is delegated to the
existing CTMonitor / WHOISEnrichment modules and is fully injectable.

Passive and benign by default -- it only reads public CT and WHOIS data; it does
not scan or touch the candidate hosts.
"""

from __future__ import annotations

import re
import sys
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.asset import Asset, AssetType  # noqa: E402


# ── Reference data ──────────────────────────────────────────────────

# Multi-label public suffixes we must keep whole when deriving the apex.
TWO_PART_TLDS: frozenset = frozenset({
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.hk",
    "org.uk", "net.au", "ac.uk", "gov.uk", "edu.au", "gov.au", "ne.jp",
    "or.jp", "com.tw", "com.ar", "com.co", "com.my", "com.ua", "com.ph",
})

# Apexes belonging to shared CDN / cloud / SaaS / certificate infrastructure.
# These commonly co-occur on certificates or as CNAME targets but are NOT
# org-owned, so they must never be reported as discovered org assets.
SHARED_INFRA_APEXES: frozenset = frozenset({
    "cloudflaressl.com", "cloudflare.com", "cloudflare-dns.com",
    "amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com",
    "elasticbeanstalk.com", "herokuapp.com", "herokudns.com",
    "azurewebsites.net", "azureedge.net", "azure.com", "windows.net",
    "trafficmanager.net", "azurefd.net", "cloudapp.net", "msftedge.net",
    "microsoft.com", "office.com", "outlook.com", "msecnd.net",
    "googleusercontent.com", "googleapis.com", "gstatic.com", "google.com",
    "appspot.com", "withgoogle.com", "firebaseapp.com", "web.app",
    "github.io", "githubusercontent.com", "github.com",
    "netlify.app", "netlify.com", "vercel.app", "vercel.com",
    "fastly.net", "fastlylb.net", "edgekey.net", "edgesuite.net",
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net",
    "wpengine.com", "wpenginepowered.com", "pantheonsite.io",
    "shopify.com", "myshopify.com", "squarespace.com", "wixsite.com",
    "wix.com", "weebly.com", "wordpress.com",
    "sendgrid.net", "salesforce.com", "force.com", "hubspot.com",
    "hs-sites.com", "zendesk.com", "zdassets.com", "freshdesk.com",
    "digicert.com", "letsencrypt.org", "sectigo.com", "godaddy.com",
    "secureserver.net", "gandi.net",
    "readthedocs.io", "ngrok.io", "surge.sh", "render.com", "onrender.com",
    "fly.dev", "pages.dev", "workers.dev", "r2.dev",
    "atlassian.net", "statuspage.io", "cloudfunctions.net",
})

# WHOIS privacy / proxy email domains -- matching on these would wrongly link
# unrelated domains, so they are ignored as a relatedness signal.
PRIVACY_EMAIL_DOMAINS: frozenset = frozenset({
    "whoisguard.com", "domainsbyproxy.com", "privacyprotect.org",
    "contactprivacy.com", "withheldforprivacy.com", "whoisprivacyprotect.com",
    "privacyguardian.org", "data-protected.net", "anonymize.com",
    "identity-protect.org", "whoisprivacy.com", "namecheap.com",
    "gandi.net", "1and1-private-registration.com", "perfectprivacy.com",
})

# Generic corporate / TLD-ish words stripped when deriving brand tokens.
BRAND_STOPWORDS: frozenset = frozenset({
    "inc", "llc", "ltd", "limited", "corp", "corporation", "company", "co",
    "group", "holdings", "holding", "gmbh", "sa", "ag", "plc", "pty", "bv",
    "the", "and", "of", "technologies", "technology", "tech", "solutions",
    "services", "service", "systems", "system", "global", "international",
    "www", "com", "net", "org", "io", "ai", "app", "cloud", "online",
    "group", "labs", "digital", "software", "consulting", "enterprises",
})

_TOKEN_RE = re.compile(r"[a-z0-9]+")


# ── Pure helpers (no I/O) ───────────────────────────────────────────

def registrable_apex(fqdn: str) -> str:
    """Derive the registrable apex from a FQDN.

    >>> registrable_apex("www.foo.example.com")
    'example.com'
    >>> registrable_apex("mail.acme.co.uk")
    'acme.co.uk'
    """
    parts = (fqdn or "").lower().strip().rstrip(".").lstrip("*.").split(".")
    parts = [p for p in parts if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_shared_infra(apex: str) -> bool:
    """True if the apex belongs to shared CDN/cloud/SaaS/cert infrastructure."""
    return apex.lower() in SHARED_INFRA_APEXES


def brand_tokens(text: str) -> set[str]:
    """Significant lowercased tokens from an org name or domain label,
    with generic corporate / TLD words removed.

    >>> sorted(brand_tokens("ACME Corporation Inc."))
    ['acme']
    """
    toks = set()
    for t in _TOKEN_RE.findall((text or "").lower()):
        if len(t) >= 3 and t not in BRAND_STOPWORDS and not t.isdigit():
            toks.add(t)
    return toks


def _label(apex: str) -> str:
    """The registrable label (first part) of an apex: acme-store.net -> acme-store."""
    return apex.split(".")[0] if apex else ""


def brand_match(apex: str, seed_tokens: set[str]) -> bool:
    """True if the apex's label shares a brand token with the seed set.
    Exact label-token match for tokens >=3 chars; substring match for >=4."""
    if not seed_tokens:
        return False
    label = _label(apex)
    label_tokens = set(re.split(r"[-_]", label))
    for st in seed_tokens:
        if st in label_tokens:
            return True
        if len(st) >= 4 and st in label:
            return True
    return False


def email_apex(email: str) -> str:
    """Registrable apex of an email address's domain (or '' if none/privacy)."""
    if not email or "@" not in email:
        return ""
    domain = email.rsplit("@", 1)[1].strip().lower()
    apex = registrable_apex(domain)
    if apex in PRIVACY_EMAIL_DOMAINS or apex in SHARED_INFRA_APEXES:
        return ""
    return apex


def candidate_apexes(associated: set[str], seed_apexes: set[str]) -> set[str]:
    """From domains co-occurring on seed certificates, return NEW apex domains
    that are not already a seed apex and not shared infrastructure."""
    out: set[str] = set()
    seeds = {a.lower() for a in seed_apexes}
    for name in associated:
        apex = registrable_apex(name)
        if not apex or apex in seeds:
            continue
        if is_shared_infra(apex):
            continue
        out.add(apex)
    return out


# Scoring weights for relatedness signals (confidence 0.0-1.0).
W_SHARED_CERT = 0.50
W_ORG_MATCH = 0.40
W_EMAIL_MATCH = 0.30
W_BRAND_MATCH = 0.20


def score_candidate(
    on_shared_cert: bool,
    org_match: bool,
    email_match: bool,
    brand_match_: bool,
) -> tuple[float, list[str]]:
    """Combine relatedness signals into a 0.0-1.0 confidence + reasons."""
    score = 0.0
    reasons: list[str] = []
    if on_shared_cert:
        score += W_SHARED_CERT
        reasons.append("shares a TLS certificate with a seed domain")
    if org_match:
        score += W_ORG_MATCH
        reasons.append("WHOIS registrant organisation matches a seed")
    if email_match:
        score += W_EMAIL_MATCH
        reasons.append("WHOIS registrant email domain matches a seed")
    if brand_match_:
        score += W_BRAND_MATCH
        reasons.append("domain label contains a seed brand token")
    return min(1.0, round(score, 3)), reasons


def confidence_label(score: float) -> str:
    if score >= 0.85:
        return "HIGH"
    if score >= 0.70:
        return "MEDIUM"
    if score >= 0.50:
        return "LOW"
    return "INFO"


# ── Result model ────────────────────────────────────────────────────

@dataclass
class DiscoveredAsset:
    """An unknown apex domain discovered via intelligence pivoting."""
    apex: str
    method: str = "cert-san-pivot"
    confidence: float = 0.0
    confidence_label: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    registrant_org: str = ""
    source_seed: str = ""
    signals: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Engine ──────────────────────────────────────────────────────────

class IntelDiscovery:
    """Discovers unknown org-owned apex domains by pivoting from seeds.

    The CT and WHOIS clients are injectable (any object exposing
    ``get_associated_domains(domain) -> set[str]`` and ``lookup(domain)``
    returning an object with ``registrant_org`` / ``registrant_email``),
    which keeps the engine unit-testable without network access.
    """

    def __init__(
        self,
        verbose: bool = False,
        timeout: int = 30,
        min_confidence: float = 0.50,
        ct_monitor: Optional[Any] = None,
        whois: Optional[Any] = None,
    ) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.min_confidence = min_confidence
        self._ct = ct_monitor
        self._whois = whois

    # ── lazy real clients (only if not injected) ────────────
    @property
    def ct(self) -> Any:
        if self._ct is None:
            from modules.ct_monitor import CTMonitor
            self._ct = CTMonitor(timeout=self.timeout, verbose=self.verbose)
        return self._ct

    @property
    def whois(self) -> Any:
        if self._whois is None:
            from modules.whois_enrichment import WHOISEnrichment
            self._whois = WHOISEnrichment(timeout=self.timeout, verbose=self.verbose)
        return self._whois

    # ── public API ──────────────────────────────────────────

    def discover(
        self,
        seed_domains: list[str],
        org_name: str = "",
    ) -> list[DiscoveredAsset]:
        """Discover unknown apex domains related to the given seeds."""
        seed_apexes = {registrable_apex(d) for d in seed_domains if d}
        seed_apexes.discard("")
        seed_org_tokens, seed_email_apexes = self._seed_signals(
            seed_apexes, org_name
        )
        seed_brand = set(brand_tokens(org_name))
        for apex in seed_apexes:
            seed_brand |= brand_tokens(_label(apex))

        # 1. cert-SAN pivot: collect domains sharing seed certificates
        associated: set[str] = set()
        for d in sorted(seed_apexes):
            try:
                associated |= set(self.ct.get_associated_domains(d))
            except Exception as exc:                       # network/parse issues
                self._vprint(f"    [intel] cert pivot error for {d}: {exc}")

        candidates = candidate_apexes(associated, seed_apexes)
        self._vprint(
            f"    [intel] {len(candidates)} candidate apex(es) from "
            f"{len(associated)} cert-associated name(s)"
        )

        # 2. corroborate + score each candidate
        results: list[DiscoveredAsset] = []
        for apex in sorted(candidates):
            rec = self._safe_whois(apex)
            cand_org = getattr(rec, "registrant_org", "") if rec else ""
            cand_email = getattr(rec, "registrant_email", "") if rec else ""

            org_match = bool(brand_tokens(cand_org) & seed_org_tokens)
            email_match = bool(email_apex(cand_email)) and \
                email_apex(cand_email) in seed_email_apexes
            bmatch = brand_match(apex, seed_brand)

            conf, reasons = score_candidate(True, org_match, email_match, bmatch)
            if conf < self.min_confidence:
                continue
            results.append(DiscoveredAsset(
                apex=apex,
                method="cert-san-pivot",
                confidence=conf,
                confidence_label=confidence_label(conf),
                reasons=reasons,
                registrant_org=cand_org,
                signals={
                    "shared_cert": True,
                    "org_match": org_match,
                    "email_match": email_match,
                    "brand_match": bmatch,
                },
            ))

        results.sort(key=lambda r: r.confidence, reverse=True)
        self._vprint(
            f"    [intel] {len(results)} related apex(es) at confidence "
            f">= {self.min_confidence}"
        )
        return results

    def to_assets(self, discovered: list[DiscoveredAsset]) -> list[Asset]:
        """Convert discovered apexes into domain Assets for the pipeline."""
        assets: list[Asset] = []
        for d in discovered:
            a = Asset(
                asset_type=AssetType.DOMAIN.value,
                value=d.apex,
                sources=[f"intel:{d.method}"],
                org_attribution=d.registrant_org,
                confidence=d.confidence,
            )
            a.set_attr("discovery_method", d.method)
            a.set_attr("discovery_confidence", d.confidence)
            a.set_attr("discovery_reasons", d.reasons)
            assets.append(a)
        return assets

    # ── internals ───────────────────────────────────────────

    def _seed_signals(
        self,
        seed_apexes: set[str],
        org_name: str,
    ) -> tuple[set[str], set[str]]:
        """Gather registrant org tokens and email apexes for the seeds."""
        org_tokens: set[str] = set(brand_tokens(org_name))
        email_apexes: set[str] = set()
        for apex in sorted(seed_apexes):
            rec = self._safe_whois(apex)
            if not rec:
                continue
            org_tokens |= brand_tokens(getattr(rec, "registrant_org", ""))
            ea = email_apex(getattr(rec, "registrant_email", ""))
            if ea:
                email_apexes.add(ea)
        return org_tokens, email_apexes

    def _safe_whois(self, apex: str) -> Any:
        try:
            return self.whois.lookup(apex)
        except Exception as exc:
            self._vprint(f"    [intel] whois error for {apex}: {exc}")
            return None

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# ── standalone runner ───────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="intel_discovery",
        description="Discover unknown org apex domains by pivoting from seeds "
                    "(cert-SAN + WHOIS).",
    )
    p.add_argument("domains", nargs="+", help="Seed domain(s)")
    p.add_argument("--org", default="", help="Organisation name (boosts scoring)")
    p.add_argument("--min-confidence", type=float, default=0.50)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    engine = IntelDiscovery(
        verbose=args.verbose, min_confidence=args.min_confidence
    )
    found = engine.discover(args.domains, org_name=args.org)
    print(f"\n[intel] Discovered {len(found)} related apex domain(s):\n")
    for d in found:
        print(f"  [{d.confidence_label:<6} {d.confidence:.2f}] {d.apex}")
        if d.registrant_org:
            print(f"           registrant: {d.registrant_org}")
        for r in d.reasons:
            print(f"           - {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
