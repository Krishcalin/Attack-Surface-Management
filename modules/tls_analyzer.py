"""
EASM Scanner -- TLS Analyzer Module
Analyses TLS/SSL configuration of discovered services:
  - Certificate details (subject, issuer, SANs, expiry, key size)
  - Protocol versions (TLS 1.0/1.1/1.2/1.3)
  - Self-signed detection
  - Weak key detection
Wraps tlsx if installed; pure-Python ssl fallback.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class TLSInfo:
    """TLS/SSL analysis result for a host:port."""
    host: str
    port: int = 443
    # Certificate
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    sans: list[str] = field(default_factory=list)
    serial: str = ""
    not_before: str = ""
    not_after: str = ""
    days_to_expiry: int = 0
    key_type: str = ""            # RSA, ECDSA, etc.
    key_bits: int = 0
    sig_algorithm: str = ""
    # Protocol
    protocol: str = ""            # TLSv1.2, TLSv1.3, etc.
    cipher: str = ""
    # Flags
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False   # < 30 days
    is_weak_key: bool = False        # RSA < 2048
    has_tls_1_0: bool = False
    has_tls_1_1: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host, "port": self.port,
            "subject_cn": self.subject_cn, "issuer_cn": self.issuer_cn,
            "issuer_org": self.issuer_org, "sans": self.sans,
            "serial": self.serial, "not_before": self.not_before,
            "not_after": self.not_after, "days_to_expiry": self.days_to_expiry,
            "key_type": self.key_type, "key_bits": self.key_bits,
            "sig_algorithm": self.sig_algorithm,
            "protocol": self.protocol, "cipher": self.cipher,
            "is_self_signed": self.is_self_signed,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon,
            "is_weak_key": self.is_weak_key,
        }


class TLSAnalyzer:
    """Analyse TLS configuration of remote hosts."""

    # Known TLS ports
    TLS_PORTS = [443, 993, 995, 8443, 2083, 2087, 465, 636]

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def analyze(self, host: str, port: int = 443) -> TLSInfo:
        """Analyse TLS for a single host:port.
        Tries tlsx first, falls back to Python ssl."""

        # Try tlsx
        result = self._tlsx_analyze(host, port)
        if result and not result.error:
            return result

        # Python fallback
        return self._ssl_analyze(host, port)

    def bulk_analyze(
        self,
        targets: list[tuple[str, int]],
    ) -> list[TLSInfo]:
        """Analyse TLS for multiple host:port pairs."""

        # Try tlsx bulk
        tlsx_results = self._tlsx_bulk(targets)
        if tlsx_results is not None:
            return tlsx_results

        # Fallback per-target
        results: list[TLSInfo] = []
        for host, port in targets:
            info = self._ssl_analyze(host, port)
            if not info.error:
                results.append(info)
        self._vprint(
            f"    [tls] analyzed {len(results)}/{len(targets)} target(s)"
        )
        return results

    # ── tlsx wrapper ────────────────────────────────────────

    def _tlsx_analyze(
        self, host: str, port: int,
    ) -> Optional[TLSInfo]:
        binary = shutil.which("tlsx")
        if not binary:
            return None

        try:
            proc = subprocess.run(
                [
                    binary, "-host", f"{host}:{port}",
                    "-silent", "-json",
                    "-san", "-cn", "-so", "-cipher",
                    "-expired", "-self-signed",
                    "-tls-version",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            import json
            for line in proc.stdout.strip().splitlines():
                obj = json.loads(line.strip())
                info = TLSInfo(host=host, port=port)
                info.subject_cn = obj.get("subject_cn", "")
                info.issuer_cn = obj.get("issuer_cn", "")
                info.issuer_org = obj.get("issuer_org", "")
                info.sans = obj.get("san", []) or []
                info.serial = obj.get("serial", "")
                info.not_before = obj.get("not_before", "")
                info.not_after = obj.get("not_after", "")
                info.protocol = obj.get("tls_version", "")
                info.cipher = obj.get("cipher", "")
                info.is_self_signed = obj.get("self_signed", False)
                info.is_expired = obj.get("expired", False)
                self._compute_expiry(info)
                self._vprint(
                    f"    [tlsx] {host}:{port}: "
                    f"CN={info.subject_cn}, "
                    f"expiry={info.days_to_expiry}d"
                )
                return info
        except Exception as exc:
            self._vprint(f"    [tlsx] {host}:{port}: error {exc}")

        return None

    def _tlsx_bulk(
        self, targets: list[tuple[str, int]],
    ) -> Optional[list[TLSInfo]]:
        binary = shutil.which("tlsx")
        if not binary:
            return None

        stdin_data = "\n".join(f"{h}:{p}" for h, p in targets)
        results: list[TLSInfo] = []

        try:
            proc = subprocess.run(
                [
                    binary, "-silent", "-json",
                    "-san", "-cn", "-so", "-cipher",
                    "-expired", "-self-signed",
                    "-tls-version",
                ],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=120,
            )
            import json
            for line in proc.stdout.strip().splitlines():
                obj = json.loads(line.strip())
                host_port = obj.get("host", "")
                if ":" in host_port:
                    h, p_str = host_port.rsplit(":", 1)
                    p = int(p_str)
                else:
                    h, p = host_port, 443

                info = TLSInfo(host=h, port=p)
                info.subject_cn = obj.get("subject_cn", "")
                info.issuer_cn = obj.get("issuer_cn", "")
                info.issuer_org = obj.get("issuer_org", "")
                info.sans = obj.get("san", []) or []
                info.serial = obj.get("serial", "")
                info.not_before = obj.get("not_before", "")
                info.not_after = obj.get("not_after", "")
                info.protocol = obj.get("tls_version", "")
                info.cipher = obj.get("cipher", "")
                info.is_self_signed = obj.get("self_signed", False)
                info.is_expired = obj.get("expired", False)
                self._compute_expiry(info)
                results.append(info)

            self._vprint(
                f"    [tlsx] analyzed {len(results)}/{len(targets)} "
                f"target(s)"
            )
            return results

        except Exception as exc:
            self._vprint(f"    [tlsx] bulk error: {exc}")
            return None

    # ── Python ssl fallback ─────────────────────────────────

    def _ssl_analyze(self, host: str, port: int) -> TLSInfo:
        info = TLSInfo(host=host, port=port)

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (host, port), timeout=self.timeout
            ) as raw_sock:
                with ctx.wrap_socket(
                    raw_sock, server_hostname=host
                ) as ssock:
                    # Protocol & cipher
                    info.protocol = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        info.cipher = cipher_info[0]

                    # Certificate
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert(binary_form=False)

                    if cert:
                        # Subject CN
                        subject = dict(
                            x[0] for x in cert.get("subject", ())
                        )
                        info.subject_cn = subject.get("commonName", "")

                        # Issuer
                        issuer = dict(
                            x[0] for x in cert.get("issuer", ())
                        )
                        info.issuer_cn = issuer.get("commonName", "")
                        info.issuer_org = issuer.get(
                            "organizationName", ""
                        )

                        # SANs
                        san_list = cert.get("subjectAltName", ())
                        for san_type, san_val in san_list:
                            if san_type == "DNS":
                                info.sans.append(san_val.lower())

                        # Serial
                        info.serial = str(
                            cert.get("serialNumber", "")
                        )

                        # Dates
                        not_before = cert.get("notBefore", "")
                        not_after = cert.get("notAfter", "")
                        if not_before:
                            info.not_before = self._parse_ssl_date(
                                not_before
                            )
                        if not_after:
                            info.not_after = self._parse_ssl_date(
                                not_after
                            )

                        # Self-signed check
                        info.is_self_signed = (
                            info.subject_cn == info.issuer_cn
                            and info.issuer_org == ""
                        )

                    # Key info from binary cert
                    if cert_bin:
                        self._extract_key_info(info, cert_bin)

            self._compute_expiry(info)

            self._vprint(
                f"    [tls] {host}:{port}: "
                f"{info.protocol}, CN={info.subject_cn}, "
                f"expiry={info.days_to_expiry}d"
                + (" [SELF-SIGNED]" if info.is_self_signed else "")
                + (" [EXPIRED]" if info.is_expired else "")
            )

        except ssl.SSLError as exc:
            info.error = f"SSL error: {exc}"
            self._vprint(f"    [tls] {host}:{port}: SSL error {exc}")
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            info.error = f"Connection error: {exc}"
        except Exception as exc:
            info.error = str(exc)

        return info

    # ── Legacy protocol check ───────────────────────────────

    def check_legacy_tls(self, host: str, port: int = 443) -> TLSInfo:
        """Check if host supports deprecated TLS 1.0 / 1.1."""
        info = self.analyze(host, port)

        for proto_name, proto_const in [
            ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
        ]:
            if proto_const is None:
                continue
            try:
                ctx = ssl.SSLContext(proto_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection(
                    (host, port), timeout=self.timeout
                ) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host):
                        if proto_name == "TLSv1.0":
                            info.has_tls_1_0 = True
                        else:
                            info.has_tls_1_1 = True
            except Exception:
                pass

        return info

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _compute_expiry(info: TLSInfo) -> None:
        if not info.not_after:
            return
        try:
            exp_str = info.not_after
            if "T" in exp_str:
                exp = datetime.fromisoformat(
                    exp_str.replace("Z", "+00:00")
                )
            else:
                exp = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
                exp = exp.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            info.days_to_expiry = (exp - now).days
            info.is_expired = info.days_to_expiry < 0
            info.is_expiring_soon = 0 <= info.days_to_expiry <= 30
        except (ValueError, TypeError):
            pass

    @staticmethod
    def _parse_ssl_date(date_str: str) -> str:
        """Convert ssl date 'Mon DD HH:MM:SS YYYY GMT' to ISO format."""
        try:
            dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, TypeError):
            return date_str

    @staticmethod
    def _extract_key_info(info: TLSInfo, cert_der: bytes) -> None:
        """Extract key type and size from DER-encoded cert.
        Best-effort using basic ASN.1 parsing."""
        # Look for RSA OID (1.2.840.113549.1.1.1)
        rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        ec_oid = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"

        if rsa_oid in cert_der:
            info.key_type = "RSA"
            # Estimate key size from cert length
            cert_len = len(cert_der)
            if cert_len < 900:
                info.key_bits = 1024
            elif cert_len < 1300:
                info.key_bits = 2048
            elif cert_len < 1800:
                info.key_bits = 3072
            else:
                info.key_bits = 4096
            info.is_weak_key = info.key_bits < 2048
        elif ec_oid in cert_der:
            info.key_type = "ECDSA"
            info.key_bits = 256  # most common
        else:
            info.key_type = "unknown"

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
