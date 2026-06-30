"""
EASM Scanner -- Detection Pairing (blue-team artifacts)
=======================================================
For every exposure we find, emit the *defensive* counterpart: the MITRE ATT&CK
technique an attacker would use to exploit it, and -- where it makes sense -- a
ready-to-deploy **Sigma rule** plus a plain-language log signature to detect that
exploitation.

This is the differentiator no EASM (or Recorded Future) leads with: we don't
just tell you what's exposed, we hand the SOC the detection to catch its abuse.

Pure and offline: pairing maps a Finding (by rule family + its own fields) to
detection guidance; a tiny built-in YAML emitter renders the Sigma rule (no
PyYAML dependency). Sigma IDs are deterministic (uuid5) so output is stable.
"""

from __future__ import annotations

import re
import sys
import uuid
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.finding import Finding  # noqa: E402

_SIGMA_NS = uuid.UUID("6f3a1d02-2c4e-5b8a-9f10-ea54de791234")  # fixed namespace


# ── MITRE ATT&CK technique catalogue ────────────────────────────────

@dataclass(frozen=True)
class Mitre:
    id: str
    name: str
    tactic: str          # snake_case ATT&CK tactic

    @property
    def url(self) -> str:
        base = self.id.split(".")[0]
        sub = self.id.split(".")[1] if "." in self.id else ""
        return f"https://attack.mitre.org/techniques/{base}/" + (f"{sub}/" if sub else "")

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "tactic": self.tactic,
                "url": self.url}


T1190 = Mitre("T1190", "Exploit Public-Facing Application", "initial_access")
T1133 = Mitre("T1133", "External Remote Services", "initial_access")
T1210 = Mitre("T1210", "Exploitation of Remote Services", "lateral_movement")
T1021_RDP = Mitre("T1021.001", "Remote Services: Remote Desktop Protocol", "lateral_movement")
T1021_SMB = Mitre("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral_movement")
T1021_SSH = Mitre("T1021.004", "Remote Services: SSH", "lateral_movement")
T1021_VNC = Mitre("T1021.005", "Remote Services: VNC", "lateral_movement")
T1078 = Mitre("T1078", "Valid Accounts", "initial_access")
T1110 = Mitre("T1110", "Brute Force", "credential_access")
T1530 = Mitre("T1530", "Data from Cloud Storage", "collection")
T1590_DNS = Mitre("T1590.002", "Gather Victim Network Information: DNS", "reconnaissance")
T1584_DOM = Mitre("T1584.001", "Compromise Infrastructure: Domains", "resource_development")
T1071_WEB = Mitre("T1071.001", "Application Layer Protocol: Web Protocols", "command_and_control")
T1090_TOR = Mitre("T1090.003", "Proxy: Multi-hop Proxy", "command_and_control")
T1557 = Mitre("T1557", "Adversary-in-the-Middle", "credential_access")
T1083 = Mitre("T1083", "File and Directory Discovery", "discovery")
T1595 = Mitre("T1595", "Active Scanning", "reconnaissance")

_SEV_TO_LEVEL = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                 "LOW": "low", "INFO": "informational"}

# Default ports per exposed-service rule (used to scope the Sigma rule).
_PORT_RULES = {
    "EASM-PORT-001": ([3306, 5432, 1433, 1521, 27017, 6379], [T1133, T1210], "database"),
    "EASM-PORT-002": ([3389], [T1133, T1021_RDP], "RDP"),
    "EASM-PORT-003": ([23], [T1133], "Telnet"),
    "EASM-PORT-004": ([21], [T1133], "FTP"),
    "EASM-PORT-005": ([5900], [T1133, T1021_VNC], "VNC"),
    "EASM-PORT-006": ([445], [T1133, T1021_SMB], "SMB"),
}


# ── Result model ────────────────────────────────────────────────────

@dataclass
class DetectionPairing:
    rule_id: str
    asset: str
    mitre: list[dict] = field(default_factory=list)
    log_source: str = ""
    detection: str = ""               # plain-language log signature / guidance
    sigma: Optional[dict] = None      # Sigma rule as a dict (None if N/A)
    references: list[str] = field(default_factory=list)

    @property
    def sigma_yaml(self) -> str:
        return to_sigma_yaml(self.sigma) if self.sigma else ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sigma_yaml"] = self.sigma_yaml
        return d


# ── helpers ─────────────────────────────────────────────────────────

def _family(rule_id: str) -> str:
    return "-".join(rule_id.split("-")[:2])


def _host_of(value: str) -> str:
    s = (value or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].rsplit("@", 1)[-1]
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    return s.split(":", 1)[0]


def _path_of(value: str) -> str:
    s = (value or "").strip()
    if "://" in s:
        rest = s.split("://", 1)[1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return ""


def _sigma_id(rule_id: str, asset: str) -> str:
    return str(uuid.uuid5(_SIGMA_NS, f"{rule_id}|{asset}"))


def _tags(mitres: list[Mitre]) -> list[str]:
    tags: list[str] = []
    for m in mitres:
        tags.append("attack." + m.id.lower())
        t = "attack." + m.tactic
        if t not in tags:
            tags.append(t)
    return tags


def _sigma(rule_id: str, asset: str, title: str, severity: str,
           mitres: list[Mitre], logsource: dict, selection: dict,
           references: list[str], description: str) -> dict:
    return {
        "title": title,
        "id": _sigma_id(rule_id, asset),
        "status": "experimental",
        "description": description,
        "author": "EASM Scanner (detection pairing)",
        "references": references,
        "logsource": logsource,
        "detection": {"selection": selection, "condition": "selection"},
        "level": _SEV_TO_LEVEL.get(severity.upper(), "medium"),
        "tags": _tags(mitres),
    }


# ── pairing ─────────────────────────────────────────────────────────

def pair_finding(finding: Finding) -> Optional[DetectionPairing]:
    """Return the detection pairing for a finding, or None if not applicable."""
    rid = finding.rule_id
    fam = _family(rid)
    asset = finding.asset_value
    sev = finding.severity
    host = _host_of(asset)
    refs: list[str] = []

    # --- Exposed services ---
    if fam == "EASM-PORT":
        ports, mitres, svc = _PORT_RULES.get(
            rid, ([0], [T1133], "service"))
        sel = {"DestinationPort": ports if len(ports) > 1 else ports[0]}
        if host:
            sel["DestinationIp" if re.match(r"^[\d.]+$", host) else
                "DestinationHostname"] = host
        sigma = _sigma(rid, asset, f"Inbound connection to exposed {svc} ({host})",
                       sev, mitres, {"category": "firewall"}, sel, refs,
                       f"Detects external connections to the internet-exposed "
                       f"{svc} on {host}.")
        return DetectionPairing(rid, asset, [m.to_dict() for m in mitres],
                                "firewall / netflow",
                                f"Connection to {host} on port(s) {ports}",
                                sigma, refs)

    # --- Threat-intel IOC matches ---
    if fam == "EASM-TI":
        tor = rid == "EASM-TI-006"
        mitres = [T1090_TOR] if tor else [T1071_WEB]
        if finding.asset_type == "ip" or re.match(r"^[\d.]+$", host):
            sel = {"DestinationIp": host}
        else:
            sel = {"DestinationHostname": host}
        sigma = _sigma(rid, asset, f"Traffic to known-bad IOC {host}", sev,
                       mitres, {"category": "firewall"}, sel, refs,
                       f"Detects any traffic to/from {host}, flagged by threat "
                       f"intelligence ({finding.evidence}).")
        return DetectionPairing(rid, asset, [m.to_dict() for m in mitres],
                                "firewall / proxy / DNS",
                                f"Any session with {host}", sigma, refs)

    # --- Web misconfiguration (sensitive path exposed) ---
    if fam == "EASM-MISCONFIG":
        path = _path_of(asset) or "/.env"
        sel = {"cs-uri-stem|contains": path}
        if host:
            sel["cs-host"] = host
        sigma = _sigma(rid, asset, f"Access to sensitive path {path} on {host}",
                       sev, [T1190, T1083], {"category": "webserver"}, sel, refs,
                       f"Detects requests to the exposed sensitive resource "
                       f"{path} on {host}.")
        return DetectionPairing(rid, asset, [m.to_dict() for m in (T1190, T1083)],
                                "web server / proxy access logs",
                                f"HTTP request to {path} on {host}", sigma, refs)

    # --- Default credentials ---
    if fam == "EASM-CRED":
        sel = {"EventID": 4624}                      # Windows successful logon
        if host:
            sel["WorkstationName"] = host
        sigma = _sigma(rid, asset, f"Successful auth on default-credential host {host}",
                       sev, [T1078, T1110], {"product": "windows", "service": "security"},
                       sel, refs,
                       f"Hunt for logons to {host}, which accepts default "
                       f"credentials -- correlate with the default account.")
        return DetectionPairing(rid, asset, [m.to_dict() for m in (T1078, T1110)],
                                "authentication logs",
                                f"Successful login to {host} using a default account",
                                sigma, refs)

    # --- Public cloud storage ---
    if fam == "EASM-CLOUD":
        sigma = _sigma(rid, asset, f"Anonymous access to cloud bucket {asset}",
                       sev, [T1530], {"product": "aws", "service": "cloudtrail"},
                       {"eventName": "GetObject", "requestParameters.bucketName": host or asset},
                       refs,
                       f"Detects object reads from the publicly accessible bucket "
                       f"{asset}.")
        return DetectionPairing(rid, asset, [T1530.to_dict()],
                                "cloud storage access logs (CloudTrail/S3)",
                                f"GetObject on bucket {asset}", sigma, refs)

    # --- DNS (zone transfer / mail exposure) ---
    if fam == "EASM-DNS":
        sel = {"query_type": "AXFR"}
        if host:
            sel["query|contains"] = host
        sigma = _sigma(rid, asset, f"DNS zone-transfer (AXFR) attempt for {host}",
                       sev, [T1590_DNS], {"category": "dns"}, sel, refs,
                       f"Detects AXFR zone-transfer requests for {host}.")
        return DetectionPairing(rid, asset, [T1590_DNS.to_dict()], "DNS query logs",
                                f"AXFR query for {host}", sigma, refs)

    # --- Subdomain takeover ---
    if fam == "EASM-TAKEOVER":
        sigma = _sigma(rid, asset, f"Resolution/serving change on dangling host {host}",
                       sev, [T1584_DOM], {"category": "dns"},
                       {"query|contains": host}, refs,
                       f"Monitor DNS/HTTP for {host}; a dangling CNAME can be "
                       f"claimed by an attacker (subdomain takeover).")
        return DetectionPairing(rid, asset, [T1584_DOM.to_dict()],
                                "DNS / proxy logs",
                                f"New resolution or content on {host}", sigma, refs)

    # --- Guidance-only families (MITRE context, no auto-Sigma) ---
    guidance = {
        "EASM-CVE": ([T1190], "WAF / IDS / web logs",
                     "Deploy WAF/IDS signatures for the CVE and watch web logs "
                     "for exploit patterns against the affected host."),
        "EASM-NUCLEI": ([T1190], "WAF / IDS / web logs",
                        "Watch for exploitation attempts matching the Nuclei "
                        "template against the affected host."),
        "EASM-TLS": ([T1557], "network / TLS inspection",
                     "Weak/!invalid TLS enables AiTM; monitor for downgrade and "
                     "certificate anomalies, and remediate the TLS config."),
        "EASM-HTTP": ([T1190], "web logs",
                      "Missing security headers ease client-side attacks; add the "
                      "headers and monitor for related abuse."),
        "EASM-INTEL": ([T1595], "asset monitoring",
                       "Newly discovered asset -- bring it under continuous "
                       "monitoring and confirm ownership."),
    }
    if fam in guidance:
        mitres, log_source, detection = guidance[fam]
        return DetectionPairing(rid, asset, [m.to_dict() for m in mitres],
                                log_source, detection, None, refs)
    return None


# ── tiny YAML emitter (Sigma) ───────────────────────────────────────

def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    return "'" + s.replace("'", "''") + "'"      # always single-quote strings


def _yaml(obj: Any, indent: int = 0) -> list[str]:
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                lines.append(f"{pad}{k}:")
                lines.extend(_yaml(v, indent + 1))
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{pad}{k}: []")
                else:
                    lines.append(f"{pad}{k}:")
                    for item in v:
                        lines.append(f"{pad}  - {_scalar(item)}")
            else:
                lines.append(f"{pad}{k}: {_scalar(v)}")
    return lines


def to_sigma_yaml(sigma: dict) -> str:
    return "\n".join(_yaml(sigma)) + "\n"


# ── engine ──────────────────────────────────────────────────────────

class DetectionPairer:
    """Pairs findings with detection guidance + Sigma rules."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def pair_all(self, findings: list[Finding]) -> list[DetectionPairing]:
        out: list[DetectionPairing] = []
        for f in findings:
            p = pair_finding(f)
            if p:
                out.append(p)
        self._vprint(f"    [detect] paired {len(out)}/{len(findings)} finding(s)")
        return out

    def annotate(self, findings: list[Finding]) -> list[DetectionPairing]:
        """Attach detection metadata onto each finding's attributes (so it flows
        into JSON / SIEM / dashboard) and return the pairings."""
        pairings: list[DetectionPairing] = []
        for f in findings:
            p = pair_finding(f)
            if not p:
                continue
            f.attributes = f.attributes or {}
            f.attributes["mitre"] = p.mitre
            f.attributes["detection"] = {
                "log_source": p.log_source,
                "signature": p.detection,
                "has_sigma": p.sigma is not None,
            }
            pairings.append(p)
        return pairings

    @staticmethod
    def mitre_coverage(pairings: list[DetectionPairing]) -> dict[str, Any]:
        techniques: dict[str, str] = {}
        tactics: set = set()
        sigma_count = 0
        for p in pairings:
            if p.sigma:
                sigma_count += 1
            for m in p.mitre:
                techniques[m["id"]] = m["name"]
                tactics.add(m["tactic"])
        return {
            "paired_findings": len(pairings),
            "sigma_rules": sigma_count,
            "techniques": dict(sorted(techniques.items())),
            "tactics": sorted(tactics),
        }

    def write_sigma(self, pairings: list[DetectionPairing], out_dir: str) -> int:
        """Write one Sigma .yml per pairing that has a rule. Returns count."""
        import os
        os.makedirs(out_dir, exist_ok=True)
        n = 0
        for p in pairings:
            if not p.sigma:
                continue
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{p.rule_id}_{p.asset}")[:120]
            with open(os.path.join(out_dir, f"{safe}.yml"), "w",
                      encoding="utf-8") as fh:
                fh.write(p.sigma_yaml)
            n += 1
        self._vprint(f"    [detect] wrote {n} Sigma rule(s) to {out_dir}")
        return n

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# ── standalone demo ─────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    # Demo: pair a couple of synthetic findings and print Sigma.
    samples = [
        Finding("EASM-PORT-002", "RDP Exposed", "Exposed Service", "HIGH",
                "203.0.113.10", "ip", evidence="3389 open"),
        Finding("EASM-TI-001", "Botnet C2", "Threat Intelligence", "CRITICAL",
                "203.0.113.20", "ip", evidence="source=feodo, malware=Emotet"),
        Finding("EASM-MISCONFIG-001", "Exposed .env", "Misconfiguration", "HIGH",
                "https://app.example.com/.env", "url"),
    ]
    pairer = DetectionPairer(verbose=True)
    for p in pairer.pair_all(samples):
        print("\n# " + p.rule_id + "  MITRE: "
              + ", ".join(m["id"] for m in p.mitre))
        print(p.sigma_yaml or f"  (guidance) {p.detection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(argv=sys.argv[1:]))
