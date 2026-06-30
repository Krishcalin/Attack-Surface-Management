"""
EASM Scanner -- STIX 2.1 Export
===============================
Serialises the discovered attack surface -- assets, findings, threat-intel IOC
matches, CVEs and MITRE ATT&CK mappings -- as a **STIX 2.1 bundle** with
relationships, the threat-intel interchange standard. The bundle ingests into
TIPs/SIEMs/SOAR (MISP, OpenCTI, Sentinel, ...).

Object mapping:
  * identity            -- the producer (EASM Scanner)
  * SCOs                -- domain-name / ipv4-addr / ipv6-addr / url (assets)
  * indicator           -- threat-intel IOC matches (with a STIX pattern)
  * x-easm-finding      -- every other finding (custom SDO, full fidelity)
  * vulnerability       -- distinct CVEs
  * attack-pattern      -- distinct MITRE techniques (from detection pairing)
  * relationship        -- finding->asset, finding->vuln, finding->technique,
                           indicator->asset (referential integrity guaranteed)

Pure/offline and deterministic: object IDs are uuid5 over stable keys, and the
timestamp is injectable, so the same scan yields the same bundle.
"""

from __future__ import annotations

import ipaddress
import json
import sys
import uuid
import pathlib
from datetime import datetime, timezone
from typing import Any, Optional

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from models.asset import Asset      # noqa: E402  (typing / convenience)
from models.finding import Finding  # noqa: E402

_NS = uuid.UUID("9b8a7c6d-5e4f-4a3b-2c1d-ea54de517100")   # fixed STIX-ID namespace
_SPEC = "2.1"


def _uid(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_NS, stix_type + ':' + key)}"


def _ts(now: Optional[datetime]) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host(value: str) -> str:
    """Host part of an asset value (strips scheme / path / :port)."""
    s = (value or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].rsplit("@", 1)[-1]
    if s.startswith("["):
        return s[1:].split("]", 1)[0]
    # keep IPv6 (has multiple colons) intact; strip :port only for host:port
    if s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s


# ── object builders (pure) ──────────────────────────────────────────

def _identity(now: Optional[datetime]) -> dict:
    return {
        "type": "identity", "spec_version": _SPEC,
        "id": _uid("identity", "easm-scanner"),
        "created": _ts(now), "modified": _ts(now),
        "name": "EASM Scanner", "identity_class": "system",
    }


def asset_sco(value: str, asset_type: str) -> Optional[dict]:
    """Return the STIX SCO for an asset value, or None (e.g. CIDR)."""
    at = (asset_type or "").lower()
    if at == "url" or "://" in (value or ""):
        return {"type": "url", "spec_version": _SPEC,
                "id": _uid("url", value), "value": value}
    if at == "cidr":
        return None
    host = _host(value)
    if not host:
        return None
    if at == "domain":
        return {"type": "domain-name", "spec_version": _SPEC,
                "id": _uid("domain-name", host), "value": host}
    if _is_ip(host):
        t = "ipv6-addr" if ":" in host else "ipv4-addr"
        return {"type": t, "spec_version": _SPEC, "id": _uid(t, host),
                "value": host}
    # default: treat as a domain name
    return {"type": "domain-name", "spec_version": _SPEC,
            "id": _uid("domain-name", host), "value": host}


def vulnerability_sdo(cve: str, now: Optional[datetime], created_by: str) -> dict:
    return {
        "type": "vulnerability", "spec_version": _SPEC,
        "id": _uid("vulnerability", cve),
        "created": _ts(now), "modified": _ts(now),
        "created_by_ref": created_by, "name": cve,
        "external_references": [{"source_name": "cve", "external_id": cve}],
    }


def attack_pattern_sdo(mitre: dict, now: Optional[datetime], created_by: str) -> dict:
    tid = mitre.get("id", "")
    ext = {"source_name": "mitre-attack", "external_id": tid}
    if mitre.get("url"):
        ext["url"] = mitre["url"]
    return {
        "type": "attack-pattern", "spec_version": _SPEC,
        "id": _uid("attack-pattern", tid),
        "created": _ts(now), "modified": _ts(now),
        "created_by_ref": created_by,
        "name": mitre.get("name", tid),
        "external_references": [ext],
    }


def indicator_for_ti(finding: Finding, now: Optional[datetime],
                     created_by: str) -> Optional[dict]:
    """Build a STIX indicator (with pattern) for a threat-intel IOC finding."""
    host = _host(finding.asset_value)
    if not host:
        return None
    if finding.asset_type == "domain" or not _is_ip(host):
        pattern = f"[domain-name:value = '{host}']"
    else:
        prop = "ipv6-addr" if ":" in host else "ipv4-addr"
        pattern = f"[{prop}:value = '{host}']"
    return {
        "type": "indicator", "spec_version": _SPEC,
        "id": _uid("indicator", finding.rule_id + "|" + host),
        "created": _ts(now), "modified": _ts(now),
        "created_by_ref": created_by,
        "name": finding.name,
        "description": finding.description or finding.name,
        "indicator_types": ["malicious-activity"],
        "pattern_type": "stix", "pattern": pattern,
        "valid_from": _ts(now),
    }


def finding_sdo(finding: Finding, now: Optional[datetime], created_by: str) -> dict:
    """Custom x-easm-finding SDO carrying the full finding (exposures/misconfigs)."""
    obj = {
        "type": "x-easm-finding", "spec_version": _SPEC,
        "id": _uid("x-easm-finding", finding.rule_id + "|" + finding.asset_value),
        "created": _ts(now), "modified": _ts(now),
        "created_by_ref": created_by,
        "name": f"{finding.rule_id}: {finding.name}",
        "description": finding.description or finding.name,
        "x_rule_id": finding.rule_id,
        "x_severity": finding.severity,
        "x_category": finding.category,
        "x_asset_value": finding.asset_value,
        "x_asset_type": finding.asset_type,
    }
    if finding.recommendation:
        obj["x_recommendation"] = finding.recommendation
    if finding.evidence:
        obj["x_evidence"] = finding.evidence
    mitre = (finding.attributes or {}).get("mitre")
    if mitre:
        obj["x_mitre_techniques"] = [m.get("id") for m in mitre]
    return obj


def relationship_sro(src: str, rel: str, tgt: str, now: Optional[datetime],
                     created_by: str) -> dict:
    return {
        "type": "relationship", "spec_version": _SPEC,
        "id": _uid("relationship", f"{src}|{rel}|{tgt}"),
        "created": _ts(now), "modified": _ts(now),
        "created_by_ref": created_by,
        "relationship_type": rel, "source_ref": src, "target_ref": tgt,
    }


# ── exporter ────────────────────────────────────────────────────────

class StixExporter:
    """Builds a STIX 2.1 bundle from assets + findings."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    def build_bundle(
        self,
        assets: list,
        findings: list,
        now: Optional[datetime] = None,
    ) -> dict:
        objects: list[dict] = []
        seen: set = set()

        def add(obj: Optional[dict]) -> Optional[str]:
            if not obj:
                return None
            if obj["id"] not in seen:
                objects.append(obj)
                seen.add(obj["id"])
            return obj["id"]

        identity = _identity(now)
        add(identity)
        cby = identity["id"]

        sco_index: dict[tuple, str] = {}

        def ensure_sco(value: str, asset_type: str) -> Optional[str]:
            sco = asset_sco(value, asset_type)
            if not sco:
                return None
            key = (sco["type"], sco["value"])
            if key not in sco_index:
                add(sco)
                sco_index[key] = sco["id"]
            return sco_index[key]

        # asset observables
        for a in assets:
            av = a.value if hasattr(a, "value") else a.get("value", "")
            at = a.asset_type if hasattr(a, "asset_type") else a.get("asset_type", "")
            ensure_sco(av, at)

        vuln_ids: dict[str, str] = {}
        ap_ids: dict[str, str] = {}

        for f in findings:
            sco_id = ensure_sco(f.asset_value, f.asset_type)

            sdo = None
            rel_to_asset = "related-to"
            if f.rule_id.startswith("EASM-TI"):
                sdo = indicator_for_ti(f, now, cby)   # IOC -> indicator
                if sdo is not None:
                    rel_to_asset = "based-on"
            if sdo is None:                           # everything else (+ TI fallback)
                sdo = finding_sdo(f, now, cby)
            sid = add(sdo)

            if sco_id:
                add(relationship_sro(sid, rel_to_asset, sco_id, now, cby))

            if f.cve:
                if f.cve not in vuln_ids:
                    vuln_ids[f.cve] = add(vulnerability_sdo(f.cve, now, cby))
                add(relationship_sro(sid, "related-to", vuln_ids[f.cve], now, cby))

            for m in (f.attributes or {}).get("mitre", []) or []:
                tid = m.get("id")
                if not tid:
                    continue
                if tid not in ap_ids:
                    ap_ids[tid] = add(attack_pattern_sdo(m, now, cby))
                add(relationship_sro(sid, "related-to", ap_ids[tid], now, cby))

        bundle = {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(_NS, "bundle:" + _ts(now))),
            "objects": objects,
        }
        self._vprint(f"    [stix] bundle: {len(objects)} object(s)")
        return bundle

    def save(self, bundle: dict, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, ensure_ascii=False)
        print(f"[+] STIX 2.1 bundle saved to: {path}")

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# ── standalone demo ─────────────────────────────────────────────────

def _main(argv: list[str]) -> int:
    findings = [
        Finding("EASM-TI-001", "Botnet C2", "Threat Intelligence", "CRITICAL",
                "203.0.113.20", "ip", evidence="source=feodo"),
        Finding("EASM-CVE-001", "Known CVE", "CVE", "HIGH", "app.example.com",
                "domain", cve="CVE-2024-1234"),
    ]
    findings[1].attributes = {"mitre": [{"id": "T1190",
                                         "name": "Exploit Public-Facing Application",
                                         "tactic": "initial_access",
                                         "url": "https://attack.mitre.org/techniques/T1190/"}]}
    assets = [Asset(asset_type="domain", value="app.example.com")]
    bundle = StixExporter(verbose=True).build_bundle(assets, findings)
    print(json.dumps(bundle, indent=2)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
