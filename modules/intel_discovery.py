"""
EASM Scanner -- Attack Surface Intelligence: Unknown-Asset Discovery
====================================================================
Discovers *unknown* organisation-owned assets by pivoting from known seeds --
the capability that turns Attack Surface Management into Attack Surface
Intelligence (cf. Recorded Future ASI).

Pivots (each contributes candidates that are merged, corroborated and scored):
  * cert-san-pivot  -- domains sharing a seed's TLS certificate (CT / crt.sh)
  * reverse-whois   -- domains with the same WHOIS registrant (independent source)
  * passive-dns     -- domains that resolved to a seed IP (passive DNS)
  * favicon-hash    -- hosts serving the same site favicon (Shodan)
  * asn-org         -- network prefixes of a seed-owned ASN

Design: all correlation/scoring logic is **pure** (no I/O) so it unit-tests with
synthetic data offline. Every network source is delegated to a small, injectable
client; live clients are best-effort accelerators that are off unless their CT
source / API key is available (mirrors the project's Go-tool-with-fallback
philosophy). Passive and benign -- it reads public CT / WHOIS / passive-DNS /
Shodan data and never scans the candidate hosts.
"""

from __future__ import annotations

import os
import re
import sys
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.asset import Asset  # noqa: E402


# ── Reference data ──────────────────────────────────────────────────

TWO_PART_TLDS: frozenset = frozenset({
    "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.il",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.hk",
    "org.uk", "net.au", "ac.uk", "gov.uk", "edu.au", "gov.au", "ne.jp",
    "or.jp", "com.tw", "com.ar", "com.co", "com.my", "com.ua", "com.ph",
})

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

PRIVACY_EMAIL_DOMAINS: frozenset = frozenset({
    "whoisguard.com", "domainsbyproxy.com", "privacyprotect.org",
    "contactprivacy.com", "withheldforprivacy.com", "whoisprivacyprotect.com",
    "privacyguardian.org", "data-protected.net", "anonymize.com",
    "identity-protect.org", "whoisprivacy.com", "namecheap.com",
    "gandi.net", "1and1-private-registration.com", "perfectprivacy.com",
})

BRAND_STOPWORDS: frozenset = frozenset({
    "inc", "llc", "ltd", "limited", "corp", "corporation", "company", "co",
    "group", "holdings", "holding", "gmbh", "sa", "ag", "plc", "pty", "bv",
    "the", "and", "of", "technologies", "technology", "tech", "solutions",
    "services", "service", "systems", "system", "global", "international",
    "www", "com", "net", "org", "io", "ai", "app", "cloud", "online",
    "labs", "digital", "software", "consulting", "enterprises",
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
    """Significant lowercased tokens from an org name or domain label.

    >>> sorted(brand_tokens("ACME Corporation Inc."))
    ['acme']
    """
    toks = set()
    for t in _TOKEN_RE.findall((text or "").lower()):
        if len(t) >= 3 and t not in BRAND_STOPWORDS and not t.isdigit():
            toks.add(t)
    return toks


def _label(apex: str) -> str:
    return apex.split(".")[0] if apex else ""


def brand_match(apex: str, seed_tokens: set[str]) -> bool:
    """True if the apex's label shares a brand token with the seed set."""
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


# ── Scoring ─────────────────────────────────────────────────────────

# Per-method base confidence (how strong the discovery signal is on its own).
METHOD_BASE_WEIGHT: dict[str, float] = {
    "cert-san-pivot": 0.50,
    "reverse-whois": 0.55,
    "passive-dns": 0.30,
    "favicon-hash": 0.40,
    "asn-org": 0.55,
}
METHOD_REASON: dict[str, str] = {
    "cert-san-pivot": "shares a TLS certificate with a seed domain",
    "reverse-whois": "registered by the same WHOIS registrant as a seed",
    "passive-dns": "resolved to the same IP as a seed (passive DNS)",
    "favicon-hash": "serves the same site favicon as a seed (Shodan)",
    "asn-org": "belongs to a seed-owned ASN / network",
}

# Corroboration weights (added on top of the strongest method base).
W_MULTI_METHOD = 0.15
W_ORG_MATCH = 0.40
W_EMAIL_MATCH = 0.30
W_BRAND_MATCH = 0.20


def score_candidate(
    methods,
    org_match: bool,
    email_match: bool,
    brand_match_: bool,
) -> tuple[float, list[str]]:
    """Combine discovery method(s) + corroboration into a 0.0-1.0 confidence
    with human-readable reasons. The strongest method sets the base; additional
    methods and registrant/brand corroboration add to it."""
    methods = list(dict.fromkeys(methods))  # de-dupe, keep order
    if not methods:
        return 0.0, []
    base = max(METHOD_BASE_WEIGHT.get(m, 0.30) for m in methods)
    score = base
    reasons = [METHOD_REASON.get(m, m) for m in sorted(methods)]
    if len(methods) > 1:
        score += W_MULTI_METHOD
        reasons.append("corroborated by multiple discovery methods")
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
    """An unknown asset discovered via intelligence pivoting."""
    value: str                       # apex domain or CIDR
    asset_type: str = "domain"       # "domain" or "cidr"
    methods: list[str] = field(default_factory=list)
    confidence: float = 0.0
    confidence_label: str = "INFO"
    reasons: list[str] = field(default_factory=list)
    registrant_org: str = ""
    signals: dict[str, Any] = field(default_factory=dict)

    @property
    def method(self) -> str:
        return self.methods[0] if self.methods else ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Engine ──────────────────────────────────────────────────────────

class IntelDiscovery:
    """Discovers unknown org-owned assets by pivoting from seeds.

    Clients are injectable for testing; live ones are built lazily only for
    pivots that are explicitly enabled (``pivots``) and configured:
      * ct_monitor     -- ``.get_associated_domains(domain) -> set[str]``
      * whois          -- ``.lookup(domain)`` -> obj with registrant_org/email
      * reverse_whois  -- ``.search(query) -> list[str]`` (domains)
      * passive_dns    -- ``.hostnames_for_ip(ip) -> list[str]``
      * shodan         -- ``.hosts_by_favicon(domain) -> list[str]``
      * asn_client     -- ``.asn_for_ip(ip)`` -> obj with .org / .prefixes
    """

    DEFAULT_PIVOTS = frozenset({"cert-san-pivot"})

    def __init__(
        self,
        verbose: bool = False,
        timeout: int = 30,
        min_confidence: float = 0.50,
        pivots: Optional[set] = None,
        ct_monitor: Optional[Any] = None,
        whois: Optional[Any] = None,
        reverse_whois: Optional[Any] = None,
        passive_dns: Optional[Any] = None,
        shodan: Optional[Any] = None,
        asn_client: Optional[Any] = None,
    ) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.min_confidence = min_confidence
        self.pivots = set(pivots) if pivots is not None else set(self.DEFAULT_PIVOTS)
        self._ct = ct_monitor
        self._whois = whois
        self._injected = {
            "reverse-whois": reverse_whois,
            "passive-dns": passive_dns,
            "favicon-hash": shodan,
            "asn-org": asn_client,
        }

    # ── lazy CT / WHOIS (always available) ──────────────────
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

    def _client_for(self, method: str) -> Any:
        """Return the client for an optional pivot, or None if unavailable.
        Injected clients always win and auto-enable the pivot; otherwise a live
        client is built only when the pivot is explicitly enabled + configured."""
        injected = self._injected.get(method)
        if injected is not None:
            return injected
        if method not in self.pivots:
            return None
        return self._build_live(method)

    def _build_live(self, method: str) -> Any:
        try:
            if method == "reverse-whois":
                key = os.environ.get("VIEWDNS_API_KEY")
                return _LiveReverseWhois(key, self.timeout, self.verbose) if key else None
            if method == "passive-dns":
                return _LivePassiveDNS(self.timeout, self.verbose)
            if method == "favicon-hash":
                key = os.environ.get("SHODAN_API_KEY")
                return _LiveShodanFavicon(key, self.timeout, self.verbose) if key else None
            if method == "asn-org":
                return _LiveASNClient(self.timeout, self.verbose)
        except Exception as exc:                            # pragma: no cover
            self._vprint(f"    [intel] could not init {method}: {exc}")
        return None

    # ── public API ──────────────────────────────────────────

    def discover(
        self,
        seed_domains: list[str],
        org_name: str = "",
        seed_ips: Optional[list[str]] = None,
    ) -> list[DiscoveredAsset]:
        """Discover unknown assets related to the given seeds across all
        enabled pivots."""
        seed_apexes = {registrable_apex(d) for d in (seed_domains or []) if d}
        seed_apexes.discard("")
        seed_ips = [ip for ip in (seed_ips or []) if ip]
        seed_org_tokens, seed_email_apexes = self._seed_signals(seed_apexes, org_name)
        seed_brand = set(brand_tokens(org_name))
        for apex in seed_apexes:
            seed_brand |= brand_tokens(_label(apex))

        # raw[(asset_type, value)] = {"methods": set, "org_hint": str}
        raw: dict[tuple, dict] = {}

        def add(value: str, asset_type: str, method: str, org_hint: str = "") -> None:
            value = value.lower().strip().rstrip(".")
            if not value:
                return
            key = (asset_type, value)
            e = raw.setdefault(key, {"methods": set(), "org_hint": ""})
            e["methods"].add(method)
            if org_hint and not e["org_hint"]:
                e["org_hint"] = org_hint

        self._pivot_cert_san(seed_apexes, add)
        self._pivot_reverse_whois(org_name, seed_email_apexes, seed_apexes, add)
        self._pivot_passive_dns(seed_ips, seed_apexes, add)
        self._pivot_favicon(seed_apexes, add)
        self._pivot_asn_org(seed_ips, seed_org_tokens, add)

        results = self._score(raw, seed_org_tokens, seed_email_apexes, seed_brand)
        results.sort(key=lambda r: (-r.confidence, r.value))
        self._vprint(
            f"    [intel] {len(results)} related asset(s) at confidence "
            f">= {self.min_confidence}"
        )
        return results

    def to_assets(self, discovered: list[DiscoveredAsset]) -> list[Asset]:
        """Convert discovered assets into Assets for the pipeline."""
        assets: list[Asset] = []
        for d in discovered:
            a = Asset(
                asset_type=d.asset_type,
                value=d.value,
                sources=[f"intel:{m}" for m in d.methods],
                org_attribution=d.registrant_org,
                confidence=d.confidence,
            )
            a.set_attr("discovery_methods", d.methods)
            a.set_attr("discovery_confidence", d.confidence)
            a.set_attr("discovery_reasons", d.reasons)
            assets.append(a)
        return assets

    # ── pivots ──────────────────────────────────────────────

    def _pivot_cert_san(self, seed_apexes: set, add: Callable) -> None:
        if "cert-san-pivot" not in self.pivots:   # uses the always-on CT client
            return
        associated: set[str] = set()
        for d in sorted(seed_apexes):
            associated |= self._safe(
                lambda d=d: set(self.ct.get_associated_domains(d)),
                set(), f"cert pivot {d}",
            )
        for apex in candidate_apexes(associated, seed_apexes):
            add(apex, "domain", "cert-san-pivot")

    def _pivot_reverse_whois(self, org_name: str, seed_email_apexes: set,
                             seed_apexes: set, add: Callable) -> None:
        client = self._client_for("reverse-whois")
        if not client:
            return
        queries = [q for q in ([org_name] if org_name else []) + sorted(seed_email_apexes) if q]
        for q in queries:
            for dom in self._safe(lambda q=q: client.search(q), [], f"reverse-whois {q}"):
                apex = registrable_apex(dom)
                if apex and apex not in seed_apexes and not is_shared_infra(apex):
                    add(apex, "domain", "reverse-whois")

    def _pivot_passive_dns(self, seed_ips: list, seed_apexes: set, add: Callable) -> None:
        client = self._client_for("passive-dns")
        if not client or not seed_ips:
            return
        for ip in seed_ips:
            for host in self._safe(lambda ip=ip: client.hostnames_for_ip(ip), [], f"pdns {ip}"):
                apex = registrable_apex(host)
                if apex and apex not in seed_apexes and not is_shared_infra(apex):
                    add(apex, "domain", "passive-dns")

    def _pivot_favicon(self, seed_apexes: set, add: Callable) -> None:
        client = self._client_for("favicon-hash")
        if not client:
            return
        for d in sorted(seed_apexes):
            for host in self._safe(lambda d=d: client.hosts_by_favicon(d), [], f"favicon {d}"):
                apex = registrable_apex(host)
                if apex and apex not in seed_apexes and not is_shared_infra(apex):
                    add(apex, "domain", "favicon-hash")

    def _pivot_asn_org(self, seed_ips: list, seed_org_tokens: set, add: Callable) -> None:
        client = self._client_for("asn-org")
        if not client or not seed_ips:
            return
        seen_asn: set = set()
        for ip in seed_ips:
            info = self._safe(lambda ip=ip: client.asn_for_ip(ip), None, f"asn {ip}")
            if not info:
                continue
            org = getattr(info, "org", "") or getattr(info, "name", "")
            asn = getattr(info, "asn", "")
            if asn in seen_asn:
                continue
            seen_asn.add(asn)
            # Only claim a network's prefixes when the ASN org matches a seed.
            if not (brand_tokens(org) & seed_org_tokens):
                continue
            for prefix in getattr(info, "prefixes", []) or []:
                add(prefix, "cidr", "asn-org", org_hint=org)

    # ── scoring / correlation ───────────────────────────────

    def _score(self, raw: dict, seed_org_tokens: set, seed_email_apexes: set,
               seed_brand: set) -> list[DiscoveredAsset]:
        results: list[DiscoveredAsset] = []
        for (atype, value), e in raw.items():
            methods = e["methods"]
            reg_org = e["org_hint"]
            org_match = email_match = bmatch = False

            if atype == "domain":
                rec = self._safe_whois(value)
                cand_org = getattr(rec, "registrant_org", "") if rec else ""
                cand_email = getattr(rec, "registrant_email", "") if rec else ""
                reg_org = cand_org or reg_org
                org_match = bool(brand_tokens(cand_org) & seed_org_tokens)
                # reverse-whois links by registrant by construction
                if "reverse-whois" in methods:
                    org_match = True
                ea = email_apex(cand_email)
                email_match = bool(ea) and ea in seed_email_apexes
                bmatch = brand_match(value, seed_brand)
            else:  # cidr from asn-org -- org already matched in the pivot
                org_match = "asn-org" in methods

            conf, reasons = score_candidate(methods, org_match, email_match, bmatch)
            if conf < self.min_confidence:
                continue
            results.append(DiscoveredAsset(
                value=value,
                asset_type=atype,
                methods=sorted(methods),
                confidence=conf,
                confidence_label=confidence_label(conf),
                reasons=reasons,
                registrant_org=reg_org,
                signals={
                    "methods": sorted(methods),
                    "org_match": org_match,
                    "email_match": email_match,
                    "brand_match": bmatch,
                },
            ))
        return results

    # ── internals ───────────────────────────────────────────

    def _seed_signals(self, seed_apexes: set, org_name: str) -> tuple[set, set]:
        org_tokens: set = set(brand_tokens(org_name))
        email_apexes: set = set()
        for apex in sorted(seed_apexes):
            rec = self._safe_whois(apex)
            if not rec:
                continue
            org_tokens |= brand_tokens(getattr(rec, "registrant_org", ""))
            ea = email_apex(getattr(rec, "registrant_email", ""))
            if ea:
                email_apexes.add(ea)
        return org_tokens, email_apexes

    def _safe_whois(self, domain: str) -> Any:
        return self._safe(lambda: self.whois.lookup(domain), None, f"whois {domain}")

    def _safe(self, fn: Callable, default: Any, label: str) -> Any:
        try:
            return fn()
        except Exception as exc:
            self._vprint(f"    [intel] {label} error: {exc}")
            return default

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# ── Live clients (best-effort; off unless enabled + configured) ──────

class _LiveReverseWhois:
    """ViewDNS reverse-WHOIS (requires VIEWDNS_API_KEY)."""
    def __init__(self, api_key: str, timeout: int, verbose: bool) -> None:
        self.api_key, self.timeout, self.verbose = api_key, timeout, verbose

    def search(self, query: str) -> list[str]:
        import requests
        url = "https://api.viewdns.info/reversewhois/"
        resp = requests.get(url, params={"q": query, "apikey": self.api_key,
                                         "output": "json"}, timeout=self.timeout)
        if resp.status_code != 200:
            return []
        data = resp.json().get("response", {})
        return [d.get("domain", "") for d in data.get("matches", []) if d.get("domain")]


class _LivePassiveDNS:
    """Mnemonic passive DNS (no key, rate-limited)."""
    def __init__(self, timeout: int, verbose: bool) -> None:
        self.timeout, self.verbose = timeout, verbose

    def hostnames_for_ip(self, ip: str) -> list[str]:
        import requests
        url = f"https://api.mnemonic.no/pdns/v3/{ip}"
        resp = requests.get(url, params={"limit": 200}, timeout=self.timeout)
        if resp.status_code != 200:
            return []
        out: list[str] = []
        for rec in resp.json().get("data", []):
            q = rec.get("query", "")
            if q and rec.get("rrtype", "").lower() in ("a", "aaaa"):
                out.append(q)
        return out


class _LiveShodanFavicon:
    """Shodan favicon-hash pivot (requires SHODAN_API_KEY and mmh3)."""
    def __init__(self, api_key: str, timeout: int, verbose: bool) -> None:
        self.api_key, self.timeout, self.verbose = api_key, timeout, verbose

    def hosts_by_favicon(self, domain: str) -> list[str]:
        import base64
        import requests
        try:
            import mmh3
        except ImportError:
            return []
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{domain}/favicon.ico",
                                 timeout=self.timeout)
                if r.status_code == 200 and r.content:
                    fav_hash = mmh3.hash(base64.encodebytes(r.content))
                    break
            except Exception:
                continue
        else:
            return []
        sr = requests.get("https://api.shodan.io/shodan/host/search",
                          params={"key": self.api_key,
                                  "query": f"http.favicon.hash:{fav_hash}"},
                          timeout=self.timeout)
        if sr.status_code != 200:
            return []
        out: list[str] = []
        for m in sr.json().get("matches", []):
            out.extend(m.get("hostnames", []) or [])
        return out


class _LiveASNClient:
    """BGPView IP->ASN->prefixes (no key)."""
    class _Info:
        def __init__(self, asn: str, org: str, prefixes: list[str]) -> None:
            self.asn, self.org, self.prefixes = asn, org, prefixes

    def __init__(self, timeout: int, verbose: bool) -> None:
        self.timeout, self.verbose = timeout, verbose

    def asn_for_ip(self, ip: str):
        import requests
        r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=self.timeout)
        if r.status_code != 200:
            return None
        prefixes_data = r.json().get("data", {}).get("prefixes", [])
        if not prefixes_data:
            return None
        asn_obj = prefixes_data[0].get("asn", {})
        asn = str(asn_obj.get("asn", ""))
        org = asn_obj.get("name", "") or asn_obj.get("description", "")
        pr = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes",
                          timeout=self.timeout)
        prefixes: list[str] = []
        if pr.status_code == 200:
            for p in pr.json().get("data", {}).get("ipv4_prefixes", []):
                if p.get("prefix"):
                    prefixes.append(p["prefix"])
        return self._Info(asn, org, prefixes)


# ── standalone runner ───────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="intel_discovery",
        description="Discover unknown org assets by pivoting from seeds.",
    )
    p.add_argument("domains", nargs="+", help="Seed domain(s)")
    p.add_argument("--org", default="", help="Organisation name (boosts scoring)")
    p.add_argument("--ip", nargs="*", default=[], help="Seed IP(s) for passive-dns / asn-org")
    p.add_argument("--pivots", default="cert-san-pivot",
                   help="Comma-separated pivots: cert-san-pivot,reverse-whois,"
                        "passive-dns,favicon-hash,asn-org")
    p.add_argument("--min-confidence", type=float, default=0.50)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    engine = IntelDiscovery(
        verbose=args.verbose, min_confidence=args.min_confidence,
        pivots={s.strip() for s in args.pivots.split(",") if s.strip()},
    )
    found = engine.discover(args.domains, org_name=args.org, seed_ips=args.ip)
    print(f"\n[intel] Discovered {len(found)} related asset(s):\n")
    for d in found:
        print(f"  [{d.confidence_label:<6} {d.confidence:.2f}] "
              f"{d.value} ({d.asset_type})")
        if d.registrant_org:
            print(f"           registrant: {d.registrant_org}")
        for r in d.reasons:
            print(f"           - {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
