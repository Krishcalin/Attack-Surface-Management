"""Tests for threat-intelligence IOC enrichment. No network (parsers are pure;
the loader is exercised via an injected fetch)."""
import json

from modules.threat_intel import (
    ThreatIntel,
    ThreatFeeds,
    FEED_URLS,
    parse_feodo,
    parse_threatfox,
    parse_urlhaus,
    parse_ip_netset,
    parse_spamhaus_drop,
    parse_tor,
    _host_from_url,
    _is_ip,
)


# ── pure parsers ────────────────────────────────────────────────────

def test_parse_feodo():
    data = [{"ip_address": "203.0.113.10", "malware": "Emotet"},
            {"ip_address": "203.0.113.11"}]
    assert parse_feodo(data) == [("203.0.113.10", "Emotet"), ("203.0.113.11", "")]
    assert parse_feodo("bad") == []


def test_parse_threatfox_splits_ips_domains_urls():
    data = {
        "1": [{"ioc_value": "203.0.113.20:443", "ioc_type": "ip:port",
               "malware_printable": "Cobalt Strike"}],
        "2": [{"ioc_value": "bad.example.net", "ioc_type": "domain",
               "malware_printable": "Qakbot"}],
        "3": [{"ioc_value": "http://1.2.3.4/x", "ioc_type": "url"}],
    }
    ips, doms = parse_threatfox(data)
    assert ("203.0.113.20", "Cobalt Strike") in ips
    assert ("1.2.3.4", "") in ips            # url host that is an IP
    assert ("bad.example.net", "Qakbot") in doms


def test_parse_urlhaus_extracts_hosts():
    text = "http://evil.example.org/payload\n# comment\nhttps://1.2.3.4/p\n"
    hosts = parse_urlhaus(text)
    assert hosts == {"evil.example.org", "1.2.3.4"}


def test_parse_ip_netset():
    ips, nets = parse_ip_netset("# c\n198.51.100.0/24\n203.0.113.40\nbad\n")
    assert "203.0.113.40" in ips
    assert any(str(n) == "198.51.100.0/24" for n in nets)


def test_parse_spamhaus_drop():
    nets = parse_spamhaus_drop("; header\n192.0.2.0/24 ; SBL123\nbad line\n")
    assert any(str(n) == "192.0.2.0/24" for n in nets)


def test_parse_tor():
    assert parse_tor("# Tor\n203.0.113.50\nnotanip\n") == {"203.0.113.50"}


def test_helpers():
    assert _is_ip("1.2.3.4") and not _is_ip("example.com")
    assert _host_from_url("http://u:p@evil.com:8080/x") == "evil.com"
    assert _host_from_url("evil.com") == "evil.com"


# ── ThreatFeeds matching ────────────────────────────────────────────

def test_feeds_match_ip_direct_and_cidr():
    import ipaddress
    f = ThreatFeeds()
    f.add_ip("203.0.113.10", "feodo", "Emotet")
    f.add_network(ipaddress.ip_network("198.51.100.0/24"), "firehol")
    assert f.match_ip("203.0.113.10")[0]["source"] == "feodo"
    assert any(h["source"] == "firehol" for h in f.match_ip("198.51.100.7"))
    assert f.match_ip("8.8.8.8") == []


def test_feeds_match_domain():
    f = ThreatFeeds()
    f.add_domain("Bad.Example.NET", "threatfox", "Qakbot")
    assert f.match_domain("bad.example.net")[0]["malware"] == "Qakbot"
    assert f.match_domain("good.example.com") == []


# ── end-to-end via injected fetch ───────────────────────────────────

def _fake_fetch():
    payload = {
        FEED_URLS["feodo"]: json.dumps(
            [{"ip_address": "203.0.113.10", "malware": "Emotet"}]),
        FEED_URLS["threatfox"]: json.dumps(
            {"1": [{"ioc_value": "203.0.113.20:443", "ioc_type": "ip:port",
                    "malware_printable": "Cobalt Strike"},
                   {"ioc_value": "bad.example.net", "ioc_type": "domain",
                    "malware_printable": "Qakbot"}]}),
        FEED_URLS["urlhaus"]: "http://evil.example.org/x\nhttp://203.0.113.30/p\n",
        FEED_URLS["firehol"]: "198.51.100.0/24\n203.0.113.40\n",
        FEED_URLS["spamhaus"]: "; h\n192.0.2.0/24 ; SBL1\n",
        FEED_URLS["tor"]: "203.0.113.50\n",
    }
    return lambda url: payload.get(url)


def test_check_assets_end_to_end():
    ti = ThreatIntel(fetch=_fake_fetch())
    ips = ["203.0.113.10", "203.0.113.20", "203.0.113.30", "198.51.100.7",
           "192.0.2.9", "203.0.113.40", "203.0.113.50", "8.8.8.8"]
    domains = ["bad.example.net", "evil.example.org", "good.example.com"]
    matches = ti.check_assets(ips, domains)
    by_ioc = {(m.ioc, m.source) for m in matches}

    assert ("203.0.113.10", "feodo") in by_ioc
    assert ("203.0.113.20", "threatfox") in by_ioc
    assert ("203.0.113.30", "urlhaus") in by_ioc
    assert ("198.51.100.7", "firehol") in by_ioc
    assert ("192.0.2.9", "spamhaus") in by_ioc
    assert ("203.0.113.40", "firehol") in by_ioc
    assert ("203.0.113.50", "tor") in by_ioc
    assert ("bad.example.net", "threatfox") in by_ioc
    assert ("evil.example.org", "urlhaus") in by_ioc
    # clean assets produce no match
    assert not any(m.ioc in ("8.8.8.8", "good.example.com") for m in matches)


def test_to_findings_rules_and_severity():
    ti = ThreatIntel(fetch=_fake_fetch())
    matches = ti.check_assets(["203.0.113.10", "203.0.113.50"], [])
    findings = {f.rule_id: f for f in ti.to_findings(matches)}
    assert findings["EASM-TI-001"].severity == "CRITICAL"     # feodo
    assert findings["EASM-TI-001"].asset_value == "203.0.113.10"
    assert "Emotet" in findings["EASM-TI-001"].evidence
    assert findings["EASM-TI-006"].severity == "MEDIUM"       # tor
    assert all(f.category == "Threat Intelligence"
               for f in ti.to_findings(matches))


def test_injected_feeds_skip_loader():
    feeds = ThreatFeeds()
    feeds.add_ip("10.0.0.1", "feodo", "TestBot")
    ti = ThreatIntel(feeds=feeds)          # no fetch -> must not hit network
    matches = ti.check_assets(["10.0.0.1", "10.0.0.2"], [])
    assert len(matches) == 1 and matches[0].source == "feodo"
