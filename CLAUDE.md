# EASM Scanner — Development Guide

## Project Overview
External Attack Surface Management (EASM) scanner — a homegrown CyCognito-like solution.
Modular Python orchestrator wrapping Go-based ProjectDiscovery tools with pure-Python fallbacks.

**Version**: 2.0.0 (Phase 1 + Phase 2 complete)

## Quick Start
```bash
pip install -r requirements.txt   # requests, dnspython
python easm_scanner.py -d example.com --org "ACME Corp" --html report.html --json scan.json -v
```

## Architecture

### 10-Step Pipeline
1. Seed Ingestion → 2. ASN Prefix Expansion → 3. Subdomain Discovery → 4. DNS Resolution →
5. Port Scanning → 6. HTTP Probing → 7. WHOIS Enrichment → 8. TLS Analysis →
9. GeoIP + Tech Fingerprinting → 10. Attribution + Relationship Graph

### File Layout
```
easm_scanner.py              # Main orchestrator, CLI, pipeline, reporting (~1340 lines)
models/
  asset.py                   # Asset dataclass (domain, ip, port, url, cert, asn, cidr)
  finding.py                 # Finding dataclass with severity ranking
modules/
  asset_store.py             # SQLite-backed asset + finding storage (upsert/merge)
  seed_manager.py            # Seed parsing (domains, IPs, CIDRs, ASNs, files)
  subdomain_discovery.py     # crt.sh + subfinder + DNS brute-force
  dns_resolver.py            # Bulk DNS resolution + dnsx wrapper
  port_scanner.py            # TCP scanner + naabu + banner grab
  http_prober.py             # HTTP probe + tech fingerprint + httpx wrapper
  asn_mapper.py              # ASN-to-CIDR via BGPView/RIPE/asnmap
  ct_monitor.py              # Certificate Transparency via crt.sh
  whois_enrichment.py        # RDAP + whois CLI, registrant extraction
  tech_fingerprint.py        # 150+ signatures (headers, cookies, body, meta)
  tls_analyzer.py            # Cert chain, cipher suites, expiry, key strength + tlsx
  geoip_enrichment.py        # ip-api.com batch + single lookups
  screenshot_capture.py      # gowitness wrapper
  attribution_engine.py      # Multi-signal org attribution (7 signal types)
  asset_graph.py             # In-memory adjacency-list graph, BFS traversal
config/
  settings.yaml              # Default config (threads, resolvers, ports, timeouts)
wordlists/
  subdomains-top1000.txt     # ~160 common subdomain prefixes
```

## Coding Conventions

### Module Pattern
- Each module is self-contained with its own dataclass results
- Every Go tool wrapper has a pure-Python fallback (scanner works without Go tools)
- Verbose output via `_vprint()` method, gated by `self.verbose`
- All network calls have timeouts and exception handling

### Rule IDs
Format: `EASM-{CATEGORY}-{NNN}`
- `EASM-PORT-001` to `006`: Exposed DB, RDP, Telnet, FTP, VNC, SMB
- `EASM-HTTP-001` to `005`: Missing HSTS, CSP, X-Content-Type-Options, server version, X-Frame-Options
- `EASM-TLS-001` to `005`: No TLS, self-signed, expired, expiring-soon, weak RSA key
- `EASM-WHOIS-001` to `002`: Domain expiring, DNSSEC not enabled

### Finding Class
Uses same pattern as other scanners in the parent repo:
`rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve`

### Severity Levels
`CRITICAL > HIGH > MEDIUM > LOW > INFO` — exit code 1 if CRITICAL or HIGH findings

### Console Output
ASCII-only characters for Windows compatibility (no Unicode box-drawing). Use `+`, `=`, `|`, `-` for borders.

## Safety Caps
- CIDR expansion: max /16 (65,536 hosts)
- Port scan targets: max 1,024 IPs
- HTTP probe targets: max 2,048
- GeoIP rate limit: 1.4s between calls (ip-api.com free tier: 45/min)

## Dependencies
- **Required**: `requests>=2.31.0`, `dnspython>=2.4.0`
- **Optional Go tools** (faster but not required): subfinder, httpx, dnsx, naabu, asnmap, tlsx, gowitness

## Remaining Phases
- **Phase 3**: Vulnerability Assessment (Nuclei integration, subdomain takeover, misconfig detection, credential testing, risk scoring)
- **Phase 4**: Reporting & Integration (FastAPI backend, React dashboard, alerting, SIEM/Jira integration)

## CLI Reference
```bash
# Full scan
python easm_scanner.py -d example.com --org "ACME Corp" --html report.html --json scan.json -v

# Quick discovery only (skip enrichment)
python easm_scanner.py -d example.com --skip-enrichment --skip-ports

# Seed file with custom thread count
python easm_scanner.py --seed-file targets.txt --threads 100

# Filter output by severity
python easm_scanner.py -d example.com --severity HIGH
```
