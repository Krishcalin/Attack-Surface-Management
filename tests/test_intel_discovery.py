"""Tests for the Attack Surface Intelligence multi-pivot discovery engine.
Pure-logic tests + integration tests with injected fake clients (no network)."""
from modules.intel_discovery import (
    IntelDiscovery,
    registrable_apex,
    is_shared_infra,
    brand_tokens,
    brand_match,
    email_apex,
    candidate_apexes,
    score_candidate,
    confidence_label,
)


# ── pure helpers ────────────────────────────────────────────────────

def test_registrable_apex():
    assert registrable_apex("www.foo.example.com") == "example.com"
    assert registrable_apex("mail.acme.co.uk") == "acme.co.uk"
    assert registrable_apex("example.com") == "example.com"
    assert registrable_apex("*.wild.example.com") == "example.com"
    assert registrable_apex("EXAMPLE.COM.") == "example.com"


def test_is_shared_infra():
    assert is_shared_infra("cloudflaressl.com")
    assert is_shared_infra("herokuapp.com")
    assert not is_shared_infra("acme.com")


def test_brand_tokens_strips_generic_words():
    assert brand_tokens("ACME Corporation Inc.") == {"acme"}
    assert brand_tokens("Globex Technologies LLC") == {"globex"}
    assert "com" not in brand_tokens("acme.com")
    assert brand_tokens("") == set()


def test_brand_match():
    assert brand_match("acme-store.net", {"acme"})
    assert brand_match("acmestore.net", {"acme"})
    assert not brand_match("example.net", {"acme"})
    assert not brand_match("anything.net", set())


def test_email_apex_filters_privacy_and_infra():
    assert email_apex("admin@acme.com") == "acme.com"
    assert email_apex("x@whoisguard.com") == ""
    assert email_apex("x@amazonaws.com") == ""
    assert email_apex("noemail") == ""


def test_candidate_apexes_filters_seeds_and_cdn():
    associated = {
        "www.acme-store.net", "shop.acme-store.net",
        "mail.acme.com", "cdn.cloudflaressl.com", "unrelated-bank.com",
    }
    cands = candidate_apexes(associated, {"acme.com"})
    assert cands == {"acme-store.net", "unrelated-bank.com"}


# ── scoring ─────────────────────────────────────────────────────────

def test_score_candidate_method_base_and_corroboration():
    # cert-san base 0.50 + org 0.40 + email 0.30 + brand 0.20 -> capped 1.0
    score, reasons = score_candidate({"cert-san-pivot"}, True, True, True)
    assert score == 1.0 and len(reasons) == 4

    # shared cert alone
    assert score_candidate({"cert-san-pivot"}, False, False, False)[0] == 0.50
    # passive-dns alone is weak (0.30)
    assert score_candidate({"passive-dns"}, False, False, False)[0] == 0.30
    # no methods -> zero
    assert score_candidate(set(), False, False, False) == (0.0, [])


def test_score_candidate_multi_method_bonus():
    score, reasons = score_candidate(
        {"cert-san-pivot", "passive-dns"}, False, False, False)
    # base = max(0.50, 0.30) + 0.15 multi-method
    assert score == 0.65
    assert any("multiple" in r for r in reasons)


def test_confidence_label_bands():
    assert confidence_label(0.9) == "HIGH"
    assert confidence_label(0.7) == "MEDIUM"
    assert confidence_label(0.5) == "LOW"
    assert confidence_label(0.2) == "INFO"


# ── fakes ───────────────────────────────────────────────────────────

class _Rec:
    def __init__(self, org="", email=""):
        self.registrant_org = org
        self.registrant_email = email


class _FakeCT:
    def __init__(self, m):
        self.m = m

    def get_associated_domains(self, d):
        return set(self.m.get(d, set()))


class _FakeWHOIS:
    def __init__(self, m):
        self.m = m

    def lookup(self, d):
        return self.m.get(d, _Rec())


class _FakeRW:
    def __init__(self, m):
        self.m = m

    def search(self, q):
        return list(self.m.get(q, []))


class _FakePDNS:
    def __init__(self, m):
        self.m = m

    def hostnames_for_ip(self, ip):
        return list(self.m.get(ip, []))


class _FakeShodan:
    def __init__(self, m):
        self.m = m

    def hosts_by_favicon(self, d):
        return list(self.m.get(d, []))


class _ASNInfo:
    def __init__(self, asn, org, prefixes):
        self.asn, self.org, self.prefixes = asn, org, prefixes


class _FakeASN:
    def __init__(self, m):
        self.m = m

    def asn_for_ip(self, ip):
        return self.m.get(ip)


# ── cert-san only (default pivots) ──────────────────────────────────

def _cert_engine(min_confidence=0.50):
    ct = _FakeCT({"acme.com": {
        "www.acme-store.net", "mail.acme.com",
        "cdn.cloudflaressl.com", "unrelated-bank.com",
    }})
    whois = _FakeWHOIS({
        "acme.com": _Rec(org="ACME Corporation", email="admin@acme.com"),
        "acme-store.net": _Rec(org="ACME Corporation"),
        "unrelated-bank.com": _Rec(org="Big Bank Inc", email="x@bigbank.com"),
    })
    return IntelDiscovery(min_confidence=min_confidence, ct_monitor=ct, whois=whois)


def test_cert_san_discovery_scores():
    found = _cert_engine().discover(["acme.com"], org_name="ACME")
    by = {d.value: d for d in found}
    assert set(by) == {"acme-store.net", "unrelated-bank.com"}
    assert by["acme-store.net"].confidence == 1.0
    assert by["acme-store.net"].confidence_label == "HIGH"
    assert by["acme-store.net"].asset_type == "domain"
    assert by["acme-store.net"].methods == ["cert-san-pivot"]
    assert by["unrelated-bank.com"].confidence == 0.50
    assert [d.value for d in found][0] == "acme-store.net"


def test_min_confidence_threshold_filters():
    found = _cert_engine(min_confidence=0.70).discover(["acme.com"], org_name="ACME")
    assert [d.value for d in found] == ["acme-store.net"]


def test_to_assets_domain_and_cidr():
    found = _cert_engine().discover(["acme.com"], org_name="ACME")
    assets = _cert_engine().to_assets(found)
    store = next(a for a in assets if a.value == "acme-store.net")
    assert store.asset_type == "domain"
    assert store.sources == ["intel:cert-san-pivot"]
    assert store.org_attribution == "ACME Corporation"
    assert store.get_attr("discovery_methods") == ["cert-san-pivot"]


def test_discover_survives_ct_errors():
    class _BoomCT:
        def get_associated_domains(self, domain):
            raise RuntimeError("crt.sh down")

    eng = IntelDiscovery(ct_monitor=_BoomCT(), whois=_FakeWHOIS({}))
    assert eng.discover(["acme.com"], org_name="ACME") == []


# ── multi-pivot integration ─────────────────────────────────────────

def _multi_engine(min_confidence=0.50):
    ct = _FakeCT({"acme.com": {"www.acme-store.net", "cdn.cloudflaressl.com"}})
    whois = _FakeWHOIS({
        "acme.com": _Rec(org="ACME Corporation", email="admin@acme.com"),
        "acme-store.net": _Rec(org="ACME Corporation"),
    })
    rw = _FakeRW({"ACME": ["acme-labs.io"]})
    pdns = _FakePDNS({"203.0.113.10": ["app.acme-cloud.net", "x.cloudflaressl.com"]})
    shodan = _FakeShodan({"acme.com": ["portal.acme-store.net"]})  # same as cert-san
    asn = _FakeASN({"203.0.113.10": _ASNInfo("AS64500", "ACME Corporation",
                                             ["203.0.113.0/24"])})
    return IntelDiscovery(
        min_confidence=min_confidence,
        pivots={"cert-san-pivot", "reverse-whois", "passive-dns",
                "favicon-hash", "asn-org"},
        ct_monitor=ct, whois=whois, reverse_whois=rw,
        passive_dns=pdns, shodan=shodan, asn_client=asn,
    )


def test_all_pivots_contribute():
    found = _multi_engine().discover(
        ["acme.com"], org_name="ACME", seed_ips=["203.0.113.10"])
    by = {d.value: d for d in found}

    # one candidate from each pivot path surfaces
    assert "acme-labs.io" in by                     # reverse-whois
    assert "acme-cloud.net" in by                    # passive-dns (+brand)
    assert "203.0.113.0/24" in by                    # asn-org (cidr)
    assert "acme-store.net" in by                    # cert-san + favicon

    # acme-store.net found by two pivots -> corroborated
    store = by["acme-store.net"]
    assert set(store.methods) == {"cert-san-pivot", "favicon-hash"}
    assert any("multiple" in r for r in store.reasons)

    # reverse-whois implies registrant linkage
    assert by["acme-labs.io"].signals["org_match"] is True

    # the CIDR is a network asset
    cidr = by["203.0.113.0/24"]
    assert cidr.asset_type == "cidr" and "asn-org" in cidr.methods

    to_assets = _multi_engine().to_assets(found)
    assert any(a.asset_type == "cidr" and a.value == "203.0.113.0/24"
               for a in to_assets)


def test_passive_dns_alone_is_filtered_without_corroboration():
    # a passive-dns-only candidate with no brand/registrant match scores 0.30
    pdns = _FakePDNS({"10.0.0.1": ["host.randomvendor.net"]})
    eng = IntelDiscovery(
        pivots={"passive-dns"},
        ct_monitor=_FakeCT({}), whois=_FakeWHOIS({}), passive_dns=pdns,
    )
    found = eng.discover(["acme.com"], org_name="ACME", seed_ips=["10.0.0.1"])
    assert found == []                               # 0.30 < 0.50 threshold
