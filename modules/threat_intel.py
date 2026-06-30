"""
EASM Scanner -- Threat-Intelligence IOC Enrichment
==================================================
Cross-references the discovered attack surface against free / community threat-
intelligence feeds to answer the SOC question: *is any of my own external asset
already known-bad -- a botnet C2, in a malicious/hijacked netblock, serving
malware, or a Tor exit?*

Feeds (no API key required):
  * feodo     -- abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON)
  * threatfox -- abuse.ch ThreatFox recent IOCs (JSON: IPs + domains + malware)
  * urlhaus   -- abuse.ch URLhaus online malware URL hosts (text)
  * firehol   -- FireHOL level1 aggregated malicious IPs/networks (netset)
  * spamhaus  -- Spamhaus DROP hijacked/criminal netblocks (text)
  * tor       -- Tor Project bulk exit-node list (text)

Design: feed parsing + matching is **pure** (no I/O) so it unit-tests with
synthetic data offline; fetching is delegated to an injectable loader. Passive
and benign -- it only reads public reputation feeds and matches them locally;
it never contacts the flagged hosts.
"""

from __future__ import annotations

import ipaddress
import json
import sys
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.finding import Finding  # noqa: E402


# ── Feed definitions ────────────────────────────────────────────────

NO_KEY_FEEDS: tuple = ("feodo", "threatfox", "urlhaus", "firehol", "spamhaus", "tor")

FEED_URLS: dict[str, str] = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
               "master/firehol_level1.netset",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
    "tor": "https://check.torproject.org/torbulkexitlist",
}

# source -> (rule_id, name, severity, recommendation)
SOURCE_RULES: dict[str, tuple] = {
    "feodo": ("EASM-TI-001", "Asset IP on botnet C2 blocklist (Feodo Tracker)",
              "CRITICAL",
              "An owned IP appears as a known botnet command-and-control server "
              "-- treat the host as compromised, isolate and investigate."),
    "threatfox": ("EASM-TI-002", "Asset is an active malware IOC (ThreatFox)",
                  "CRITICAL",
                  "An owned asset matches a current malware indicator. "
                  "Investigate for compromise and remove malicious content."),
    "urlhaus": ("EASM-TI-003", "Asset hosts a known malware URL (URLhaus)",
                "HIGH",
                "An owned host is distributing malware according to URLhaus. "
                "Take the content down and check for a web compromise."),
    "firehol": ("EASM-TI-004", "Asset IP in a known-malicious network (FireHOL)",
                "HIGH",
                "An owned IP falls in a FireHOL level1 malicious range. "
                "Verify the asset is not abused or mis-attributed."),
    "spamhaus": ("EASM-TI-005", "Asset IP in a hijacked/criminal netblock (Spamhaus DROP)",
                 "HIGH",
                 "An owned IP falls in a Spamhaus DROP netblock. Confirm "
                 "ownership and routing; the range is associated with abuse."),
    "tor": ("EASM-TI-006", "Asset IP is a Tor exit node",
            "MEDIUM",
            "An owned IP is listed as a Tor exit node, which is unusual for "
            "corporate infrastructure -- confirm this is intended."),
}


# ── Pure feed parsers (no I/O) ──────────────────────────────────────

def parse_feodo(data: Any) -> list[tuple[str, str]]:
    """Feodo JSON -> [(ip, malware), ...]."""
    out: list[tuple[str, str]] = []
    if isinstance(data, list):
        for e in data:
            if isinstance(e, dict) and e.get("ip_address"):
                out.append((e["ip_address"].strip(), e.get("malware", "")))
    return out


def parse_threatfox(data: Any) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """ThreatFox recent JSON -> (ip_iocs, domain_iocs), each [(ioc, malware)]."""
    ips: list[tuple[str, str]] = []
    domains: list[tuple[str, str]] = []
    if not isinstance(data, dict):
        return ips, domains
    for entries in data.values():
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict):
                continue
            ioc = str(e.get("ioc_value") or e.get("ioc") or "").strip()
            itype = str(e.get("ioc_type", "")).lower()
            malware = e.get("malware_printable") or e.get("malware") or ""
            if not ioc:
                continue
            if itype.startswith("ip"):                 # ip:port -> strip port
                ips.append((ioc.split(":")[0], malware))
            elif itype == "domain":
                domains.append((ioc.lower(), malware))
            elif itype == "url":
                host = _host_from_url(ioc)
                if host:
                    (ips if _is_ip(host) else domains).append((host, malware))
    return ips, domains


def parse_urlhaus(text: str) -> set[str]:
    """URLhaus text export -> set of malicious hosts (domains/IPs)."""
    hosts: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _host_from_url(line)
        if host:
            hosts.add(host)
    return hosts


def parse_ip_netset(text: str) -> tuple[set[str], list[Any]]:
    """A FireHOL-style netset (IPs and CIDRs, '#' comments) -> (ips, networks)."""
    ips: set[str] = set()
    nets: list[Any] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "/" in line:
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
        elif _is_ip(line):
            ips.add(line)
    return ips, nets


def parse_spamhaus_drop(text: str) -> list[Any]:
    """Spamhaus DROP ('CIDR ; SBLxxxxx', ';' comments) -> networks."""
    nets: list[Any] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        cidr = line.split(";", 1)[0].strip()
        if "/" in cidr:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return nets


def parse_tor(text: str) -> set[str]:
    """Tor bulk exit list -> set of exit IPs."""
    ips: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and _is_ip(line):
            ips.add(line)
    return ips


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host_from_url(url: str) -> str:
    """Extract the host from a URL or bare host:port."""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = s.rsplit("@", 1)[-1]          # strip creds
    if s.startswith("["):            # IPv6 literal
        return s[1:].split("]", 1)[0]
    return s.split(":", 1)[0].lower()


# ── Feeds container (pure matching) ─────────────────────────────────

@dataclass
class ThreatFeeds:
    """Parsed IOC data with fast local matching."""
    ip_iocs: dict[str, list[dict]] = field(default_factory=dict)
    domain_iocs: dict[str, list[dict]] = field(default_factory=dict)
    networks: list[tuple] = field(default_factory=list)   # (ip_network, source)

    def add_ip(self, ip: str, source: str, malware: str = "") -> None:
        self.ip_iocs.setdefault(ip, []).append({"source": source, "malware": malware})

    def add_domain(self, domain: str, source: str, malware: str = "") -> None:
        self.domain_iocs.setdefault(domain.lower(), []).append(
            {"source": source, "malware": malware})

    def add_network(self, net: Any, source: str) -> None:
        self.networks.append((net, source))

    def match_ip(self, ip: str) -> list[dict]:
        out = list(self.ip_iocs.get(ip, []))
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        for net, source in self.networks:
            if addr in net:
                out.append({"source": source, "malware": ""})
        return out

    def match_domain(self, domain: str) -> list[dict]:
        return list(self.domain_iocs.get((domain or "").lower().rstrip("."), []))

    def counts(self) -> dict[str, int]:
        return {
            "ip_iocs": len(self.ip_iocs),
            "domain_iocs": len(self.domain_iocs),
            "networks": len(self.networks),
        }


@dataclass
class ThreatMatch:
    ioc: str
    ioc_type: str           # "ip" | "domain"
    source: str
    malware: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Engine ──────────────────────────────────────────────────────────

class ThreatIntel:
    """Match discovered assets against threat-intel feeds.

    ``feeds`` (a ThreatFeeds) and ``fetch`` (callable url->text|None) are
    injectable for offline testing; otherwise a lazy HTTP loader is used.
    """

    def __init__(
        self,
        verbose: bool = False,
        timeout: int = 30,
        sources: Optional[set] = None,
        feeds: Optional[ThreatFeeds] = None,
        fetch: Optional[Callable] = None,
    ) -> None:
        self.verbose = verbose
        self.timeout = timeout
        self.sources = set(sources) if sources else set(NO_KEY_FEEDS)
        self._feeds = feeds
        self._fetch = fetch

    # ── feed loading ────────────────────────────────────────

    def load_feeds(self) -> ThreatFeeds:
        if self._feeds is not None:
            return self._feeds
        feeds = ThreatFeeds()
        for source in self.sources:
            url = FEED_URLS.get(source)
            if not url:
                continue
            raw = self._http(url)
            if not raw:
                self._vprint(f"    [ti] {source}: feed unavailable")
                continue
            self._ingest(feeds, source, raw)
        self._vprint(f"    [ti] feeds loaded: {feeds.counts()}")
        self._feeds = feeds
        return feeds

    def _ingest(self, feeds: ThreatFeeds, source: str, raw: str) -> None:
        try:
            if source == "feodo":
                for ip, mw in parse_feodo(self._json(raw)):
                    feeds.add_ip(ip, "feodo", mw)
            elif source == "threatfox":
                ips, doms = parse_threatfox(self._json(raw))
                for ip, mw in ips:
                    feeds.add_ip(ip, "threatfox", mw)
                for d, mw in doms:
                    feeds.add_domain(d, "threatfox", mw)
            elif source == "urlhaus":
                for host in parse_urlhaus(raw):
                    (feeds.add_ip if _is_ip(host) else feeds.add_domain)(host, "urlhaus")
            elif source == "firehol":
                ips, nets = parse_ip_netset(raw)
                for ip in ips:
                    feeds.add_ip(ip, "firehol")
                for net in nets:
                    feeds.add_network(net, "firehol")
            elif source == "spamhaus":
                for net in parse_spamhaus_drop(raw):
                    feeds.add_network(net, "spamhaus")
            elif source == "tor":
                for ip in parse_tor(raw):
                    feeds.add_ip(ip, "tor")
        except Exception as exc:
            self._vprint(f"    [ti] {source}: parse error {exc}")

    # ── matching ────────────────────────────────────────────

    def check_assets(
        self,
        ips: list[str],
        domains: list[str],
        feeds: Optional[ThreatFeeds] = None,
    ) -> list[ThreatMatch]:
        feeds = feeds or self.load_feeds()
        matches: list[ThreatMatch] = []
        for ip in ips:
            for hit in feeds.match_ip(ip):
                matches.append(ThreatMatch(ioc=ip, ioc_type="ip",
                                           source=hit["source"],
                                           malware=hit.get("malware", "")))
        for d in domains:
            for hit in feeds.match_domain(d):
                matches.append(ThreatMatch(ioc=d, ioc_type="domain",
                                           source=hit["source"],
                                           malware=hit.get("malware", "")))
        # de-dupe identical (ioc, source)
        seen: set = set()
        unique: list[ThreatMatch] = []
        for m in matches:
            key = (m.ioc, m.source)
            if key not in seen:
                seen.add(key)
                unique.append(m)
        self._vprint(f"    [ti] {len(unique)} threat-intel match(es)")
        return unique

    def to_findings(self, matches: list[ThreatMatch]) -> list[Finding]:
        out: list[Finding] = []
        for m in matches:
            rule = SOURCE_RULES.get(m.source)
            if not rule:
                continue
            rule_id, name, severity, recommendation = rule
            evidence = f"source={m.source}"
            if m.malware:
                evidence += f", malware={m.malware}"
            out.append(Finding(
                rule_id=rule_id,
                name=name,
                category="Threat Intelligence",
                severity=severity,
                asset_value=m.ioc,
                asset_type=m.ioc_type,
                description=(f"Owned {m.ioc_type} {m.ioc} matches a threat-intel "
                             f"feed ({m.source})"
                             + (f" associated with {m.malware}" if m.malware else "")
                             + "."),
                recommendation=recommendation,
                evidence=evidence,
            ))
        return out

    # ── internals ───────────────────────────────────────────

    def _http(self, url: str) -> Optional[str]:
        if self._fetch is not None:
            return self._fetch(url)
        try:
            import requests
            r = requests.get(url, timeout=self.timeout,
                             headers={"User-Agent": "EASM-Scanner/4 (+threat-intel)"})
            return r.text if r.status_code == 200 else None
        except Exception as exc:
            self._vprint(f"    [ti] fetch error {url}: {exc}")
            return None

    @staticmethod
    def _json(raw: str) -> Any:
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return None

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# ── standalone runner ───────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="threat_intel",
        description="Check IPs/domains against free threat-intel feeds.",
    )
    p.add_argument("--ip", nargs="*", default=[], help="IP(s) to check")
    p.add_argument("--domain", nargs="*", default=[], help="Domain(s) to check")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    ti = ThreatIntel(verbose=args.verbose)
    matches = ti.check_assets(args.ip, args.domain)
    print(f"\n[ti] {len(matches)} match(es):\n")
    for m in matches:
        mw = f"  ({m.malware})" if m.malware else ""
        print(f"  [{m.source:<9}] {m.ioc_type} {m.ioc}{mw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
