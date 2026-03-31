#!/usr/bin/env python3
"""
EASM Scanner -- Demo / Mock Runner
Produces a realistic JSON + HTML report without live DNS/port scanning by
directly instantiating Finding/Asset objects and using the scanner's
save_json / save_html methods.
"""

import datetime
import json
import os
import sys
import time

os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── Add scanner root to path ────────────────────────────────────────
SCANNER_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCANNER_ROOT)

from models.asset import Asset, AssetType
from models.finding import Finding

# ── We need a minimal mock of the AssetStore and graph so the scanner
#    can serialise without hitting a real database ────────────────────

class MockAssetStore:
    """In-memory asset store that mimics the real one."""
    def __init__(self):
        self._assets: list[Asset] = []

    def add(self, asset: Asset) -> None:
        self._assets.append(asset)

    def get_assets(self, asset_type: str = None) -> list[Asset]:
        if asset_type:
            return [a for a in self._assets if a.asset_type == asset_type]
        return list(self._assets)

    def count_assets(self, asset_type: str) -> int:
        return len([a for a in self._assets if a.asset_type == asset_type])


class MockAssetGraph:
    def to_dict(self):
        return {"nodes": [], "edges": []}


# ── Demo Assets ─────────────────────────────────────────────────────

DEMO_DOMAINS = [
    ("example-corp.com", {}),
    ("www.example-corp.com", {"cname": "cdn.example-corp.com"}),
    ("api.example-corp.com", {"cname": "api-gw.example-corp.com"}),
    ("mail.example-corp.com", {"mx": True}),
    ("dev.example-corp.com", {"environment": "development"}),
    ("staging.example-corp.com", {"environment": "staging"}),
    ("admin.example-corp.com", {"admin_panel": True}),
    ("vpn.example-corp.com", {"service": "vpn"}),
    ("legacy.example-corp.com", {"deprecated": True}),
]

DEMO_IPS = [
    ("203.0.113.10", {"ptr": "www.example-corp.com", "asn": "AS13335"}),
    ("203.0.113.11", {"ptr": "api.example-corp.com", "asn": "AS13335"}),
    ("203.0.113.20", {"ptr": "mail.example-corp.com", "asn": "AS16509"}),
    ("198.51.100.5", {"ptr": "dev.example-corp.com", "asn": "AS14618"}),
    ("198.51.100.6", {"ptr": "legacy.example-corp.com", "asn": "AS14618"}),
]

DEMO_PORTS = [
    ("80", "203.0.113.10", {"service": "http", "banner": "nginx/1.24.0"}),
    ("443", "203.0.113.10", {"service": "https", "banner": "nginx/1.24.0"}),
    ("443", "203.0.113.11", {"service": "https", "banner": "envoy"}),
    ("25", "203.0.113.20", {"service": "smtp", "banner": "Postfix"}),
    ("443", "203.0.113.20", {"service": "https", "banner": "Microsoft-IIS/10.0"}),
    ("22", "198.51.100.5", {"service": "ssh", "banner": "OpenSSH_8.9"}),
    ("8080", "198.51.100.5", {"service": "http-alt", "banner": "Jetty/9.4.44"}),
    ("3306", "198.51.100.5", {"service": "mysql", "banner": "MySQL 5.7.38"}),
    ("3389", "198.51.100.6", {"service": "rdp", "banner": "Microsoft Terminal Services"}),
    ("21", "198.51.100.6", {"service": "ftp", "banner": "vsFTPd 3.0.3"}),
    ("5900", "198.51.100.6", {"service": "vnc", "banner": "RFB 003.008"}),
    ("9200", "198.51.100.6", {"service": "elasticsearch", "banner": "Elasticsearch 7.10.2"}),
]

DEMO_URLS = [
    ("https://www.example-corp.com/", {"status": 200, "title": "Example Corp", "tech": ["nginx", "React"]}),
    ("https://api.example-corp.com/v1/docs", {"status": 200, "title": "API Docs", "tech": ["envoy", "FastAPI"]}),
    ("https://admin.example-corp.com/login", {"status": 200, "title": "Admin Login", "tech": ["IIS", "ASP.NET"]}),
    ("http://dev.example-corp.com:8080/", {"status": 200, "title": "Jenkins", "tech": ["Jetty", "Jenkins"]}),
]

# ── Demo Findings ───────────────────────────────────────────────────

DEMO_FINDINGS = [
    # Exposed Services (port scanning)
    Finding(
        rule_id="EASM-PORT-001", name="Database Port Exposed to Internet",
        category="Exposed Service", severity="CRITICAL",
        asset_value="198.51.100.5:3306", asset_type="port",
        description="MySQL port 3306 is directly reachable from the internet on dev.example-corp.com. Attackers commonly scan for exposed databases to steal data or deploy ransomware.",
        recommendation="Restrict database access to internal networks or VPN. Use firewall rules to deny public access to DB ports.",
        cwe="CWE-200", evidence="Banner: MySQL 5.7.38 -- Connection accepted without TLS",
    ),
    Finding(
        rule_id="EASM-PORT-002", name="RDP Exposed to Internet",
        category="Exposed Service", severity="HIGH",
        asset_value="198.51.100.6:3389", asset_type="port",
        description="Remote Desktop Protocol (RDP) is exposed on legacy.example-corp.com. RDP is a top attack vector for ransomware and brute-force attacks.",
        recommendation="Disable public RDP. Use a VPN or Zero-Trust gateway. Enable NLA and strong MFA if RDP must be exposed.",
        cwe="CWE-284", evidence="Banner: Microsoft Terminal Services -- NLA not enforced",
    ),
    Finding(
        rule_id="EASM-PORT-004", name="FTP Exposed to Internet",
        category="Exposed Service", severity="MEDIUM",
        asset_value="198.51.100.6:21", asset_type="port",
        description="FTP on legacy.example-corp.com transmits credentials in cleartext and allows anonymous login.",
        recommendation="Replace FTP with SFTP/SCP. Block port 21. Disable anonymous access.",
        cwe="CWE-319", evidence="Banner: vsFTPd 3.0.3 -- Anonymous login succeeded",
    ),
    Finding(
        rule_id="EASM-PORT-005", name="VNC Exposed to Internet",
        category="Exposed Service", severity="HIGH",
        asset_value="198.51.100.6:5900", asset_type="port",
        description="VNC is exposed on legacy.example-corp.com; many VNC servers have weak authentication.",
        recommendation="Restrict VNC behind VPN. Enable strong authentication and encryption.",
        cwe="CWE-284", evidence="Banner: RFB 003.008 -- No authentication required",
    ),
    Finding(
        rule_id="EASM-PORT-007", name="Elasticsearch Exposed to Internet",
        category="Exposed Service", severity="CRITICAL",
        asset_value="198.51.100.6:9200", asset_type="port",
        description="Elasticsearch is publicly accessible without authentication on legacy.example-corp.com. Contains indexed application logs with user data.",
        recommendation="Place Elasticsearch behind a firewall. Enable X-Pack security with authentication. Never expose port 9200 publicly.",
        cwe="CWE-284", evidence="GET /_cat/indices returned 47 indices including 'users', 'logs-prod'",
    ),

    # TLS Analysis
    Finding(
        rule_id="EASM-TLS-001", name="TLS Certificate Expired",
        category="TLS/SSL", severity="HIGH",
        asset_value="legacy.example-corp.com", asset_type="domain",
        description="The TLS certificate for legacy.example-corp.com expired 45 days ago. Browsers will show security warnings and automated systems may reject connections.",
        recommendation="Renew the TLS certificate immediately. Implement automated certificate management (e.g., Let's Encrypt with certbot auto-renewal).",
        cwe="CWE-295", evidence="Certificate expired: 2026-02-14T00:00:00Z (45 days ago)",
    ),
    Finding(
        rule_id="EASM-TLS-002", name="Weak TLS Protocol (TLSv1.0)",
        category="TLS/SSL", severity="MEDIUM",
        asset_value="mail.example-corp.com", asset_type="domain",
        description="The mail server still supports TLSv1.0, which has known vulnerabilities (BEAST, POODLE). PCI DSS requires TLS 1.2+.",
        recommendation="Disable TLSv1.0 and TLSv1.1. Configure minimum TLS version to 1.2. Prefer TLS 1.3 cipher suites.",
        cwe="CWE-326", evidence="Supported protocols: TLSv1.0, TLSv1.1, TLSv1.2",
    ),
    Finding(
        rule_id="EASM-TLS-003", name="Self-Signed Certificate",
        category="TLS/SSL", severity="MEDIUM",
        asset_value="dev.example-corp.com", asset_type="domain",
        description="The development server uses a self-signed certificate. While acceptable for internal use, public exposure enables MITM attacks.",
        recommendation="Use CA-signed certificates for all internet-facing services. Use Let's Encrypt for free automated certificates.",
        cwe="CWE-295", evidence="Issuer: CN=dev.example-corp.com (self-signed, not in trust store)",
    ),

    # WHOIS / Domain
    Finding(
        rule_id="EASM-WHOIS-001", name="Domain Registration Expiring Soon",
        category="Domain Intelligence", severity="MEDIUM",
        asset_value="example-corp.com", asset_type="domain",
        description="The domain example-corp.com expires in 28 days. If not renewed, an attacker could register it and intercept email/traffic.",
        recommendation="Renew the domain immediately. Enable auto-renewal and domain lock. Set calendar reminders.",
        cwe="CWE-284", evidence="Expiry: 2026-04-28 | Registrar: GoDaddy | Auto-renew: disabled",
    ),

    # Subdomain Takeover
    Finding(
        rule_id="EASM-TAKEOVER-001", name="Subdomain Takeover Risk (Dangling CNAME)",
        category="Subdomain Takeover", severity="HIGH",
        asset_value="staging.example-corp.com", asset_type="domain",
        description="staging.example-corp.com has a CNAME pointing to a deprovisioned Heroku app (staging-app-xyz.herokuapp.com). An attacker can claim this endpoint and serve malicious content.",
        recommendation="Remove the dangling DNS record or re-provision the target service. Monitor for dangling CNAMEs regularly.",
        cwe="CWE-284", evidence="CNAME: staging-app-xyz.herokuapp.com -> NXDOMAIN (Heroku: app not found)",
    ),

    # Vulnerability Assessment
    Finding(
        rule_id="EASM-VULN-001", name="Critical CVE in Exposed Service",
        category="Vulnerability", severity="CRITICAL",
        asset_value="198.51.100.5:8080", asset_type="port",
        description="Jenkins 2.346 on dev.example-corp.com is vulnerable to CVE-2024-23897 (arbitrary file read via CLI). CVSS 9.8. Actively exploited in the wild.",
        recommendation="Update Jenkins to the latest LTS version immediately. Restrict access to the Jenkins UI to internal networks.",
        cwe="CWE-22", cve="CVE-2024-23897",
        evidence="Jenkins version 2.346 detected. Known vulnerable to CVE-2024-23897 (CVSS 9.8, CISA KEV).",
    ),
    Finding(
        rule_id="EASM-VULN-002", name="Outdated Web Server with Known CVEs",
        category="Vulnerability", severity="HIGH",
        asset_value="https://www.example-corp.com", asset_type="url",
        description="nginx/1.24.0 has multiple known vulnerabilities including HTTP/2 rapid reset (CVE-2023-44487).",
        recommendation="Update nginx to the latest stable version. Apply security patches promptly.",
        cwe="CWE-1104", cve="CVE-2023-44487",
        evidence="Server: nginx/1.24.0 -- 3 known CVEs for this version",
    ),

    # Misconfiguration
    Finding(
        rule_id="EASM-MISCONF-001", name="Directory Listing Enabled",
        category="Misconfiguration", severity="MEDIUM",
        asset_value="https://www.example-corp.com/assets/", asset_type="url",
        description="Directory listing is enabled on /assets/, exposing internal file structure and potentially sensitive files.",
        recommendation="Disable directory listing in the web server configuration (autoindex off for nginx).",
        cwe="CWE-548", evidence="HTTP 200 with <title>Index of /assets/</title>",
    ),
    Finding(
        rule_id="EASM-MISCONF-002", name="Admin Panel Exposed Without MFA",
        category="Misconfiguration", severity="HIGH",
        asset_value="https://admin.example-corp.com/login", asset_type="url",
        description="The admin panel is internet-accessible with only password authentication. No MFA or IP restriction detected.",
        recommendation="Restrict admin panel to VPN/internal network. Enforce multi-factor authentication. Implement IP whitelisting.",
        cwe="CWE-308", evidence="Login form at /login with username+password fields only. No TOTP/WebAuthn detected.",
    ),

    # Cloud Exposure
    Finding(
        rule_id="EASM-CLOUD-001", name="Public S3 Bucket Discovered",
        category="Cloud Exposure", severity="HIGH",
        asset_value="s3://example-corp-backups", asset_type="url",
        description="An S3 bucket named 'example-corp-backups' is publicly readable, containing database backup files.",
        recommendation="Set the bucket ACL to private. Enable S3 Block Public Access at the account level. Review all bucket policies.",
        cwe="CWE-284", evidence="Bucket listing returned 156 objects including db-backup-2026-03.sql.gz (4.2 GB)",
    ),

    # DNS Security
    Finding(
        rule_id="EASM-DNS-001", name="SPF Record Missing",
        category="DNS Security", severity="MEDIUM",
        asset_value="example-corp.com", asset_type="domain",
        description="No SPF record found for example-corp.com. Attackers can spoof emails from this domain.",
        recommendation="Add an SPF TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider).",
        cwe="CWE-290", evidence="TXT records: no v=spf1 entry found",
    ),
    Finding(
        rule_id="EASM-DNS-002", name="DMARC Not Enforced",
        category="DNS Security", severity="LOW",
        asset_value="example-corp.com", asset_type="domain",
        description="DMARC policy is set to 'none', providing monitoring only. Spoofed emails will still be delivered.",
        recommendation="Gradually increase DMARC policy: p=none -> p=quarantine -> p=reject. Monitor DMARC reports.",
        cwe="CWE-290", evidence="_dmarc.example-corp.com TXT: v=DMARC1; p=none; rua=mailto:dmarc@example-corp.com",
    ),

    # Default Credentials
    Finding(
        rule_id="EASM-CRED-001", name="Default Credentials on Jenkins",
        category="Default Credentials", severity="CRITICAL",
        asset_value="http://dev.example-corp.com:8080", asset_type="url",
        description="Jenkins is accessible with default credentials admin:admin. Full administrative access to the CI/CD pipeline.",
        recommendation="Change default credentials immediately. Enforce strong passwords. Enable LDAP/SSO integration.",
        cwe="CWE-798", evidence="POST /j_acegi_security_check with j_username=admin&j_password=admin -> HTTP 302 -> /",
    ),

    # Information Disclosure
    Finding(
        rule_id="EASM-INFO-001", name="Sensitive Endpoints Exposed in robots.txt",
        category="Information Disclosure", severity="LOW",
        asset_value="https://www.example-corp.com/robots.txt", asset_type="url",
        description="robots.txt reveals paths to admin interfaces, internal APIs, and backup directories.",
        recommendation="Remove sensitive paths from robots.txt. Use authentication and authorization instead of obscurity.",
        cwe="CWE-200", evidence="Disallow: /admin/\nDisallow: /api/internal/\nDisallow: /backup/",
    ),

    # Tech Fingerprinting
    Finding(
        rule_id="EASM-TECH-001", name="End-of-Life Software Detected",
        category="Technology", severity="MEDIUM",
        asset_value="198.51.100.5", asset_type="ip",
        description="MySQL 5.7.38 on dev.example-corp.com reached end-of-life in October 2023. No security patches are available.",
        recommendation="Upgrade to MySQL 8.0 LTS or migrate to a supported database version.",
        cwe="CWE-1104", evidence="Banner: MySQL 5.7.38 -- EOL since 2023-10-25",
    ),
]


def main():
    print(f"[*] EASM Scanner Demo Runner")
    print(f"[*] Injecting {len(DEMO_FINDINGS)} synthetic findings "
          f"and {len(DEMO_DOMAINS) + len(DEMO_IPS) + len(DEMO_PORTS) + len(DEMO_URLS)} assets...")

    # We cannot easily instantiate the full EASMScanner because it initialises
    # many heavy modules.  Instead, we build the JSON and HTML directly using
    # the Finding/Asset models and the scanner's serialisation format.

    # Build assets
    assets = []
    for domain, attrs in DEMO_DOMAINS:
        a = Asset(asset_type="domain", value=domain, sources=["demo"], attributes=attrs)
        assets.append(a)
    for ip, attrs in DEMO_IPS:
        a = Asset(asset_type="ip", value=ip, sources=["demo"], attributes=attrs)
        assets.append(a)
    for port, parent, attrs in DEMO_PORTS:
        a = Asset(asset_type="port", value=port, sources=["demo"],
                  attributes=attrs, parent=parent)
        assets.append(a)
    for url, attrs in DEMO_URLS:
        a = Asset(asset_type="url", value=url, sources=["demo"], attributes=attrs)
        assets.append(a)

    findings = list(DEMO_FINDINGS)

    # Build severity counts
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    asset_counts = {}
    for a in assets:
        asset_counts[a.asset_type] = asset_counts.get(a.asset_type, 0) + 1

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Build JSON report (matching EASMScanner.save_json format)
    report = {
        "easm_scanner_version": "4.0.0",
        "scan_timestamp": now_iso,
        "summary": {
            "elapsed_seconds": 42.7,
            "total_findings": len(findings),
            "severity_counts": {
                "CRITICAL": sev_counts.get("CRITICAL", 0),
                "HIGH": sev_counts.get("HIGH", 0),
                "MEDIUM": sev_counts.get("MEDIUM", 0),
                "LOW": sev_counts.get("LOW", 0),
                "INFO": sev_counts.get("INFO", 0),
            },
            "asset_counts": asset_counts,
        },
        "assets": [a.to_dict() for a in assets],
        "findings": [f.to_dict() for f in findings],
        "whois": {
            "example-corp.com": {
                "registrar": "GoDaddy",
                "creation_date": "2018-06-15",
                "expiry_date": "2026-04-28",
                "name_servers": ["ns1.example-corp.com", "ns2.example-corp.com"],
                "status": ["clientTransferProhibited"],
            }
        },
        "tls": [
            {
                "host": "www.example-corp.com",
                "port": 443,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "issuer": "Let's Encrypt Authority X3",
                "subject": "*.example-corp.com",
                "not_before": "2026-01-15T00:00:00Z",
                "not_after": "2026-07-15T00:00:00Z",
                "days_remaining": 106,
                "san": ["*.example-corp.com", "example-corp.com"],
            },
            {
                "host": "legacy.example-corp.com",
                "port": 443,
                "protocol": "TLSv1.2",
                "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
                "issuer": "legacy.example-corp.com",
                "subject": "legacy.example-corp.com",
                "not_before": "2025-02-14T00:00:00Z",
                "not_after": "2026-02-14T00:00:00Z",
                "days_remaining": -45,
                "san": ["legacy.example-corp.com"],
                "self_signed": True,
            },
        ],
        "geoip": {
            "203.0.113.10": {"country": "US", "region": "California", "city": "San Francisco", "org": "Cloudflare, Inc."},
            "203.0.113.11": {"country": "US", "region": "California", "city": "San Francisco", "org": "Cloudflare, Inc."},
            "203.0.113.20": {"country": "US", "region": "Virginia", "city": "Ashburn", "org": "Amazon.com, Inc."},
            "198.51.100.5": {"country": "US", "region": "Oregon", "city": "Boardman", "org": "Amazon.com, Inc."},
            "198.51.100.6": {"country": "US", "region": "Oregon", "city": "Boardman", "org": "Amazon.com, Inc."},
        },
        "attribution": [],
        "graph": {"nodes": [], "edges": []},
        "vulnerabilities": [],
        "nuclei": [],
    }

    # Output paths
    out_dir = os.path.join(SCANNER_ROOT, "test_data")
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "easm_report.json")
    html_path = os.path.join(out_dir, "easm_report.html")

    # Save JSON
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"  JSON report saved: {json_path}")

    # Generate HTML report
    sev_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
        "LOW": "#0891b2", "INFO": "#6b7280",
    }

    finding_rows = ""
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.severity, 5)):
        clr = sev_colors.get(f.severity, "#6b7280")
        import html as html_mod
        esc = html_mod.escape
        finding_rows += f"""<tr>
<td><span class="sev" style="background:{clr};color:#fff;padding:2px 8px;border-radius:4px">{f.severity}</span></td>
<td><strong>{esc(f.rule_id)}</strong></td>
<td>{esc(f.name)}</td>
<td>{esc(f.category)}</td>
<td>{esc(f.asset_value)}</td>
<td>{esc(f.description[:150])}...</td>
<td>{esc(f.recommendation[:120])}...</td>
<td>{esc(f.cwe)}{(' / ' + esc(f.cve)) if f.cve else ''}</td>
</tr>\n"""

    asset_rows = ""
    for a in assets:
        asset_rows += f"""<tr>
<td>{html_mod.escape(a.asset_type)}</td>
<td>{html_mod.escape(a.value)}</td>
<td>{html_mod.escape(a.parent)}</td>
<td>{html_mod.escape(', '.join(a.sources))}</td>
<td>{html_mod.escape(str(a.attributes)[:150])}</td>
</tr>\n"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EASM Scanner Report (Demo)</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:0}}
.header{{background:linear-gradient(135deg,#7c3aed,#2563eb,#0891b2);padding:2rem;text-align:center}}
.header h1{{color:#fff;font-size:2rem;margin-bottom:.5rem}}
.header p{{color:#e2e8f0;font-size:1rem}}
.container{{max-width:1400px;margin:2rem auto;padding:0 1rem}}
.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
.card{{background:#1e293b;border-radius:8px;padding:1.2rem;text-align:center}}
.card .num{{font-size:2rem;font-weight:700}}
.card .label{{color:#94a3b8;font-size:.85rem;margin-top:.3rem}}
table{{width:100%;border-collapse:collapse;margin-bottom:2rem;background:#1e293b;border-radius:8px;overflow:hidden}}
th{{background:#334155;padding:.75rem;text-align:left;font-size:.85rem;color:#94a3b8}}
td{{padding:.65rem .75rem;border-bottom:1px solid #334155;font-size:.85rem}}
tr:hover{{background:#334155}}
h2{{margin:1.5rem 0 1rem;color:#f1f5f9;font-size:1.3rem}}
.sev{{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;font-size:.8rem}}
</style>
</head><body>
<div class="header">
<h1>EASM Scanner Report</h1>
<p>External Attack Surface Management &mdash; v4.0.0 (Demo)</p>
<p>Scan Date: {now_iso[:19]} UTC &bull; Target: example-corp.com</p>
</div>
<div class="container">
<div class="summary">
<div class="card"><div class="num" style="color:#dc2626">{sev_counts.get("CRITICAL",0)}</div><div class="label">Critical</div></div>
<div class="card"><div class="num" style="color:#ea580c">{sev_counts.get("HIGH",0)}</div><div class="label">High</div></div>
<div class="card"><div class="num" style="color:#ca8a04">{sev_counts.get("MEDIUM",0)}</div><div class="label">Medium</div></div>
<div class="card"><div class="num" style="color:#0891b2">{sev_counts.get("LOW",0)}</div><div class="label">Low</div></div>
<div class="card"><div class="num">{len(assets)}</div><div class="label">Assets</div></div>
<div class="card"><div class="num">{len(findings)}</div><div class="label">Findings</div></div>
</div>

<h2>Security Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Rule ID</th><th>Name</th><th>Category</th><th>Asset</th><th>Description</th><th>Recommendation</th><th>CWE / CVE</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>

<h2>Discovered Assets</h2>
<table>
<thead><tr><th>Type</th><th>Value</th><th>Parent</th><th>Sources</th><th>Attributes</th></tr></thead>
<tbody>{asset_rows}</tbody>
</table>
</div>
</body></html>"""

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    print(f"  HTML report saved: {html_path}")

    # Summary
    print(f"\n[*] Summary:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"    {sev:10s}: {sev_counts.get(sev, 0)}")
    print(f"    {'TOTAL':10s}: {len(findings)}")
    print(f"    Assets   : {len(assets)}")
    print(f"\n[+] JSON report: {json_path}")
    print(f"[+] HTML report: {html_path}")

    # Verify
    with open(json_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    print(f"[+] Verified: JSON contains {len(data['findings'])} findings and {len(data['assets'])} assets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
