"""Tests for the Attack Surface Intelligence unknown-asset discovery engine.
Pure-logic tests + an integration test with injected fake CT/WHOIS (no network)."""
from modules.intel_discovery import (
    IntelDiscovery,
    DiscoveredAsset,
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
    assert brand_match("acme-store.net", {"acme"})        # token in label
    assert brand_match("acmestore.net", {"acme"})         # substring (>=4)
    assert not brand_match("example.net", {"acme"})
    assert not brand_match("anything.net", set())


def test_email_apex_filters_privacy_and_infra():
    assert email_apex("admin@acme.com") == "acme.com"
    assert email_apex("x@whoisguard.com") == ""           # privacy proxy
    assert email_apex("x@amazonaws.com") == ""            # shared infra
    assert email_apex("noemail") == ""


def test_candidate_apexes_filters_seeds_and_cdn():
    associated = {
        "www.acme-store.net", "shop.acme-store.net",     # -> acme-store.net
        "mail.acme.com",                                  # seed apex -> drop
        "cdn.cloudflaressl.com",                          # CDN -> drop
        "unrelated-bank.com",
    }
    cands = candidate_apexes(associated, {"acme.com"})
    assert cands == {"acme-store.net", "unrelated-bank.com"}


def test_score_candidate_weights_and_cap():
    score, reasons = score_candidate(True, True, True, True)
    assert score == 1.0 and len(reasons) == 4             # capped
    score2, _ = score_candidate(True, False, False, False)
    assert score2 == 0.5                                  # shared cert only
    assert score_candidate(False, False, False, False)[0] == 0.0


def test_confidence_label_bands():
    assert confidence_label(0.9) == "HIGH"
    assert confidence_label(0.7) == "MEDIUM"
    assert confidence_label(0.5) == "LOW"
    assert confidence_label(0.2) == "INFO"


# ── injected-I/O integration ────────────────────────────────────────

class _Rec:
    def __init__(self, org="", email=""):
        self.registrant_org = org
        self.registrant_email = email


class _FakeCT:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_associated_domains(self, domain):
        return set(self.mapping.get(domain, set()))


class _FakeWHOIS:
    def __init__(self, mapping):
        self.mapping = mapping

    def lookup(self, domain):
        return self.mapping.get(domain, _Rec())


def _engine(min_confidence=0.50):
    ct = _FakeCT({
        "acme.com": {
            "www.acme-store.net", "shop.acme-store.net",
            "mail.acme.com",                 # seed apex -> filtered
            "cdn.cloudflaressl.com",         # CDN -> filtered
            "unrelated-bank.com",            # shared cert, otherwise unrelated
        },
    })
    whois = _FakeWHOIS({
        "acme.com": _Rec(org="ACME Corporation", email="admin@acme.com"),
        "acme-store.net": _Rec(org="ACME Corporation"),
        "unrelated-bank.com": _Rec(org="Big Bank Inc", email="x@bigbank.com"),
    })
    return IntelDiscovery(min_confidence=min_confidence, ct_monitor=ct, whois=whois)


def test_discover_finds_related_apexes_with_scores():
    found = _engine().discover(["acme.com"], org_name="ACME")
    by_apex = {d.apex: d for d in found}

    # seed apex and CDN never reported; both genuine candidates surface
    assert set(by_apex) == {"acme-store.net", "unrelated-bank.com"}

    store = by_apex["acme-store.net"]
    assert store.confidence == 1.0 and store.confidence_label == "HIGH"
    assert store.signals["org_match"] and store.signals["brand_match"]
    assert store.registrant_org == "ACME Corporation"
    assert any("certificate" in r for r in store.reasons)

    bank = by_apex["unrelated-bank.com"]
    assert bank.confidence == 0.5 and bank.confidence_label == "LOW"
    assert bank.signals == {
        "shared_cert": True, "org_match": False,
        "email_match": False, "brand_match": False,
    }

    # results sorted by confidence descending
    assert [d.apex for d in found][0] == "acme-store.net"


def test_min_confidence_threshold_filters():
    found = _engine(min_confidence=0.70).discover(["acme.com"], org_name="ACME")
    assert [d.apex for d in found] == ["acme-store.net"]   # 0.5 bank dropped


def test_to_assets_conversion():
    found = _engine().discover(["acme.com"], org_name="ACME")
    assets = _engine().to_assets(found)
    assert all(a.asset_type == "domain" for a in assets)
    store = next(a for a in assets if a.value == "acme-store.net")
    assert store.sources == ["intel:cert-san-pivot"]
    assert store.confidence == 1.0
    assert store.org_attribution == "ACME Corporation"
    assert store.get_attr("discovery_method") == "cert-san-pivot"
    assert store.get_attr("discovery_reasons")


def test_discover_survives_ct_errors():
    class _BoomCT:
        def get_associated_domains(self, domain):
            raise RuntimeError("crt.sh down")

    eng = IntelDiscovery(ct_monitor=_BoomCT(), whois=_FakeWHOIS({}))
    assert eng.discover(["acme.com"], org_name="ACME") == []
