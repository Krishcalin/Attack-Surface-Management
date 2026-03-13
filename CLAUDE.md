# EASM Scanner — Development Guide

## Project Overview
External Attack Surface Management (EASM) scanner — a homegrown CyCognito-like solution.
Modular Python orchestrator wrapping Go-based ProjectDiscovery tools with pure-Python fallbacks.

**Version**: 4.0.0 (Phase 1 + Phase 2 + Phase 3 + Phase 4 complete)

## Quick Start
```bash
pip install -r requirements.txt   # requests, dnspython, fastapi, uvicorn
python easm_scanner.py -d example.com --org "ACME Corp" --html report.html --json scan.json -v

# Start with REST API dashboard
python easm_scanner.py -d example.com --serve --port 8888
```

## Architecture

### 14-Step Pipeline + Phase 4 Integration
**Phase 1 — Discovery:**
1. Seed Ingestion -> 2. ASN Prefix Expansion -> 3. Subdomain Discovery -> 4. DNS Resolution ->
5. Port Scanning -> 6. HTTP Probing

**Phase 2 — Enrichment:**
7. WHOIS Enrichment -> 8. TLS Analysis -> 9. GeoIP + Tech Fingerprinting -> 10. Attribution + Graph

**Phase 3 — Vulnerability Assessment:**
11. Vulnerability Detection (CVE fingerprint + Nuclei) -> 12. Misconfiguration & Takeover Detection ->
13. Credential & DNS Security Testing -> 14. Risk Scoring & Prioritisation

**Phase 4 — Reporting & Integration:**
- REST API (FastAPI) with interactive dashboard
- Multi-channel alerting (Email, Slack, Teams, Webhook, Console)
- SIEM export (Splunk HEC, Elasticsearch, Syslog CEF, CSV, JSON Lines)
- Jira ticket integration (Cloud/Server, deduplication)
- Scan scheduling with diff detection (SQLite-backed)

### File Layout
```
easm_scanner.py              # Main orchestrator, CLI, 14-step pipeline, reporting
models/
  asset.py                   # Asset dataclass (domain, ip, port, url, cert, asn, cidr)
  finding.py                 # Finding dataclass with severity ranking
modules/
  # Phase 1 — Discovery
  asset_store.py             # SQLite-backed asset + finding storage (upsert/merge)
  seed_manager.py            # Seed parsing (domains, IPs, CIDRs, ASNs, files)
  subdomain_discovery.py     # crt.sh + subfinder + DNS brute-force
  dns_resolver.py            # Bulk DNS resolution + dnsx wrapper
  port_scanner.py            # TCP scanner + naabu + banner grab
  http_prober.py             # HTTP probe + tech fingerprint + httpx wrapper
  asn_mapper.py              # ASN-to-CIDR via BGPView/RIPE/asnmap
  ct_monitor.py              # Certificate Transparency via crt.sh
  # Phase 2 — Enrichment
  whois_enrichment.py        # RDAP + whois CLI, registrant extraction
  tech_fingerprint.py        # 150+ signatures (headers, cookies, body, meta)
  tls_analyzer.py            # Cert chain, cipher suites, expiry, key strength + tlsx
  geoip_enrichment.py        # ip-api.com batch + single lookups
  screenshot_capture.py      # gowitness wrapper
  attribution_engine.py      # Multi-signal org attribution (7 signal types)
  asset_graph.py             # In-memory adjacency-list graph, BFS traversal
  # Phase 3 — Vulnerability Assessment
  vuln_detector.py           # CVE detection via version fingerprinting + NVD/EPSS
  nuclei_scanner.py          # Nuclei Go wrapper + 15 built-in Python templates
  subdomain_takeover.py      # Dangling DNS/CNAME detection (25 cloud providers)
  misconfig_detector.py      # 39 sensitive paths, CORS, open redirect, directory listing
  default_creds.py           # Default credential testing (SSH, FTP, HTTP, SNMP, DB, Redis, MongoDB)
  dns_security.py            # SPF/DKIM/DMARC validation, zone transfer (AXFR), CAA, MX checks
  cloud_enum.py              # S3/Azure Blob/GCS bucket enumeration + permission testing
  risk_scorer.py             # Multi-factor risk scoring (severity x criticality x exploitability x temporal)
  # Phase 4 — Reporting & Integration
  alerting.py                # Multi-channel alerting (Email/Slack/Teams/Webhook/Console)
  siem_export.py             # SIEM export (Splunk HEC/Elasticsearch/Syslog CEF/CSV/JSONL)
  jira_integration.py        # Jira Cloud/Server ticket creation with deduplication
  scheduler.py               # SQLite-backed scan scheduling with diff detection
api/
  server.py                  # FastAPI REST API server (14 endpoints)
  dashboard.py               # Dashboard data renderer
templates/
  dashboard.html             # Interactive single-page dashboard (dark theme, charts, filters)
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
- `EASM-TAKEOVER-001`: Subdomain takeover vulnerability
- `EASM-CVE-001`: Known CVE detected via version fingerprint
- `EASM-CRED-001`: Default credentials accepted
- `EASM-CLOUD-001`: Public cloud storage bucket
- `EASM-MISCONFIG-001` to `010`: Exposed .env/.git, backups, configs, debug, admin, Swagger, CORS, redirect, directory listing
- `EASM-DNS-001` to `006`: Missing SPF, permissive SPF, missing DMARC, weak DMARC, no DKIM, zone transfer
- `EASM-NUCLEI-*`: Dynamic rule IDs from Nuclei template matches

### Finding Class
`rule_id, name, category, severity, asset_value, asset_type, description, recommendation, cwe, cve, evidence, attributes`

### Severity Levels
`CRITICAL > HIGH > MEDIUM > LOW > INFO` — exit code 1 if CRITICAL or HIGH findings

### Console Output
ASCII-only characters for Windows compatibility (no Unicode box-drawing). Use `+`, `=`, `|`, `-` for borders.

## Safety Caps
- CIDR expansion: max /16 (65,536 hosts)
- Port scan targets: max 1,024 IPs
- HTTP probe targets: max 2,048
- GeoIP rate limit: 1.4s between calls (ip-api.com free tier: 45/min)
- Nuclei targets: max 100 URLs
- Misconfig scan: max 50 URLs, 50 paths per URL
- Cloud bucket candidates: max 200
- Credential test targets: max 50

## Risk Scoring
Formula: `Risk = (Severity x 0.40) + (Criticality x 0.35) + (Exploitability x 0.15) + (Temporal x 0.10)`
- Output: 0-100 score, mapped to CRITICAL(>=80)/HIGH(>=60)/MEDIUM(>=40)/LOW(>=20)/INFO
- Auto-escalation: CISA KEV, default creds, confirmed takeover, public buckets, critical CVE+exploit

## Phase 4 — Reporting & Integration

### REST API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Launch new scan |
| GET | `/api/scan/status` | Current scan status |
| GET | `/api/scan/history` | Scan history |
| GET | `/api/summary` | Latest scan summary |
| GET | `/api/assets` | Asset inventory (filterable) |
| GET | `/api/findings` | Security findings (filterable) |
| GET | `/api/risk-scores` | Risk score data |
| GET | `/api/graph` | Asset relationship graph |
| GET | `/api/export/{fmt}` | Export (json/csv/jsonl) |
| POST | `/api/alerts/test` | Send test alert |
| GET | `/` | Interactive dashboard |

### Alerting Channels
- **Email**: SMTP with TLS, HTML + plain text (env: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD)
- **Slack**: Block Kit webhook
- **Teams**: MessageCard webhook
- **Webhook**: Generic POST JSON
- **Console**: stdout fallback

### SIEM Export Targets
- **Splunk HEC**: Batched POST (100 events/request)
- **Elasticsearch**: Bulk API with auth/apikey
- **Syslog CEF**: UDP/TCP with CEF format
- **CSV**: DictWriter export
- **JSON Lines**: Newline-delimited JSON

### Jira Integration
- REST API v2 (Cloud + Server)
- Severity-to-priority mapping (Critical->Highest, High->High, Medium->Medium)
- JQL deduplication (searches existing tickets by label)
- Jira wiki markup description builder

### Scan Scheduler
- SQLite-backed scan history (scan_history, finding_snapshots, asset_snapshots)
- Finding diff detection (new, resolved, unchanged)
- Asset diff (new, removed)
- Interval-based execution with alert triggers on new findings

## Dependencies
- **Required**: `requests>=2.31.0`, `dnspython>=2.4.0`
- **Phase 4 API**: `fastapi>=0.104.0`, `uvicorn>=0.24.0` (optional, for `--serve`)
- **Optional Go tools** (faster but not required): subfinder, httpx, dnsx, naabu, asnmap, tlsx, gowitness, nuclei
- **Optional Python libs**: paramiko (SSH cred test), mysql-connector (MySQL), psycopg2 (PostgreSQL), pymongo (MongoDB)

## CLI Reference
```bash
# Full scan (all 14 steps)
python easm_scanner.py -d example.com --org "ACME Corp" --html report.html --json scan.json -v

# Discovery only (skip enrichment + vuln assessment)
python easm_scanner.py -d example.com --skip-enrichment --skip-ports

# Skip Phase 3 vulnerability assessment
python easm_scanner.py -d example.com --skip-vuln-assessment

# Skip specific Phase 3 checks
python easm_scanner.py -d example.com --skip-nuclei --skip-cred-test

# Custom Nuclei templates
python easm_scanner.py -d example.com --nuclei-templates /path/to/templates

# Seed file with custom thread count
python easm_scanner.py --seed-file targets.txt --threads 100

# Filter output by severity
python easm_scanner.py -d example.com --severity HIGH

# Start REST API + Dashboard after scan
python easm_scanner.py -d example.com --serve --port 8888

# Scheduled scanning (every 60 minutes)
python easm_scanner.py -d example.com --schedule 60

# Alert to Slack on new findings
python easm_scanner.py -d example.com --alert-slack https://hooks.slack.com/services/...

# Alert to Microsoft Teams
python easm_scanner.py -d example.com --alert-teams https://outlook.office.com/webhook/...

# SIEM export to Splunk
python easm_scanner.py -d example.com --siem-splunk-url https://splunk:8088 --siem-splunk-token TOKEN

# SIEM export to CSV/JSONL
python easm_scanner.py -d example.com --siem-csv findings.csv --siem-jsonl findings.jsonl

# Jira ticket creation for CRITICAL/HIGH findings
python easm_scanner.py -d example.com --jira-url https://acme.atlassian.net --jira-project SEC --jira-user admin@acme.com --jira-token TOKEN
```
