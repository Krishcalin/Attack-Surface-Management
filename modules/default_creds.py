"""
EASM Scanner -- Default Credential Tester
Tests for known default / factory credentials on exposed services.
NOT brute-force -- single-attempt per credential pair with strict timeouts.

Supported services:
  - SSH (paramiko optional)
  - FTP (stdlib ftplib)
  - HTTP Basic Auth (requests)
  - SNMP community strings (pysnmp optional)
  - MySQL (mysql-connector optional)
  - PostgreSQL (psycopg2 optional)
  - Redis (stdlib socket)
  - MongoDB (pymongo optional)
"""

from __future__ import annotations

import ftplib
import socket
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Optional imports ───────────────────────────────────────────────

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Default credential database ───────────────────────────────────
# Only well-known factory defaults -- NOT a dictionary attack list.

DEFAULT_CREDS: dict[str, list[dict[str, str]]] = {
    "ssh": [
        {"user": "root", "pass": "root"},
        {"user": "root", "pass": "toor"},
        {"user": "admin", "pass": "admin"},
        {"user": "admin", "pass": "password"},
        {"user": "admin", "pass": "1234"},
        {"user": "ubnt", "pass": "ubnt"},
        {"user": "pi", "pass": "raspberry"},
        {"user": "test", "pass": "test"},
    ],
    "ftp": [
        {"user": "anonymous", "pass": "anonymous"},
        {"user": "anonymous", "pass": ""},
        {"user": "ftp", "pass": "ftp"},
        {"user": "admin", "pass": "admin"},
        {"user": "admin", "pass": "password"},
    ],
    "http_basic": [
        {"user": "admin", "pass": "admin"},
        {"user": "admin", "pass": "password"},
        {"user": "admin", "pass": "1234"},
        {"user": "admin", "pass": "12345"},
        {"user": "root", "pass": "root"},
        {"user": "admin", "pass": ""},
        {"user": "user", "pass": "user"},
        {"user": "tomcat", "pass": "tomcat"},
        {"user": "manager", "pass": "manager"},
    ],
    "snmp": [
        {"community": "public"},
        {"community": "private"},
        {"community": "community"},
        {"community": "default"},
        {"community": "snmp"},
    ],
    "mysql": [
        {"user": "root", "pass": ""},
        {"user": "root", "pass": "root"},
        {"user": "root", "pass": "mysql"},
        {"user": "admin", "pass": "admin"},
    ],
    "postgres": [
        {"user": "postgres", "pass": "postgres"},
        {"user": "postgres", "pass": ""},
        {"user": "admin", "pass": "admin"},
    ],
    "redis": [
        {"pass": ""},  # No auth
    ],
    "mongodb": [
        {"user": "", "pass": ""},  # No auth
    ],
}


# Service-to-port mapping
SERVICE_PORTS: dict[str, list[int]] = {
    "ssh": [22, 2222],
    "ftp": [21],
    "http_basic": [80, 443, 8080, 8443, 8888],
    "snmp": [161],
    "mysql": [3306],
    "postgres": [5432],
    "redis": [6379],
    "mongodb": [27017],
}


@dataclass
class CredentialResult:
    """Result of a default credential test."""
    ip: str
    port: int
    service: str
    success: bool = False
    username: str = ""
    password: str = ""
    evidence: str = ""
    severity: str = "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "port": self.port,
            "service": self.service,
            "success": self.success,
            "username": self.username,
            "evidence": self.evidence,
            "severity": self.severity,
        }


class DefaultCredentialTester:
    """Test exposed services for default / factory credentials."""

    def __init__(
        self,
        timeout: int = 5,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def test_service(
        self,
        ip: str,
        port: int,
        service: str = "",
    ) -> list[CredentialResult]:
        """Test a single service for default credentials."""
        if not service:
            service = self._identify_service(port)
        if not service:
            return []

        tester = {
            "ssh": self._test_ssh,
            "ftp": self._test_ftp,
            "http_basic": self._test_http_basic,
            "snmp": self._test_snmp,
            "redis": self._test_redis,
            "mysql": self._test_mysql,
            "postgres": self._test_postgres,
            "mongodb": self._test_mongodb,
        }.get(service)

        if not tester:
            return []

        return tester(ip, port)

    def bulk_test(
        self,
        targets: list[dict[str, Any]],
    ) -> list[CredentialResult]:
        """Test multiple services. Each dict: {ip, port, service?}"""
        all_results: list[CredentialResult] = []

        for target in targets:
            ip = target.get("ip", "")
            port = target.get("port", 0)
            service = target.get("service", "")

            if not ip or not port:
                continue

            results = self.test_service(ip, port, service)
            all_results.extend(results)

        success_count = sum(1 for r in all_results if r.success)
        self._vprint(
            f"    [creds] tested {len(targets)} service(s), "
            f"{success_count} default credential(s) found"
        )
        return all_results

    # ── SSH ──────────────────────────────────────────────────

    def _test_ssh(self, ip: str, port: int) -> list[CredentialResult]:
        """Test SSH for default credentials using paramiko."""
        results: list[CredentialResult] = []
        if not HAS_PARAMIKO:
            self._vprint("    [creds] paramiko not installed, skipping SSH")
            return results

        for cred in DEFAULT_CREDS["ssh"]:
            result = CredentialResult(
                ip=ip, port=port, service="ssh",
                username=cred["user"],
            )
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    ip, port=port,
                    username=cred["user"],
                    password=cred["pass"],
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                )
                client.close()

                result.success = True
                result.evidence = (
                    f"SSH login successful with "
                    f"{cred['user']}:{cred['pass']}"
                )
                results.append(result)
                self._vprint(
                    f"    [creds] {ip}:{port} SSH: "
                    f"DEFAULT CRED {cred['user']}:{cred['pass']}"
                )
                break  # Stop after first success

            except paramiko.AuthenticationException:
                continue
            except Exception:
                break  # Connection error, stop trying

        return results

    # ── FTP ──────────────────────────────────────────────────

    def _test_ftp(self, ip: str, port: int) -> list[CredentialResult]:
        """Test FTP for default/anonymous credentials."""
        results: list[CredentialResult] = []

        for cred in DEFAULT_CREDS["ftp"]:
            result = CredentialResult(
                ip=ip, port=port, service="ftp",
                username=cred["user"],
            )
            try:
                ftp = ftplib.FTP()
                ftp.connect(ip, port, timeout=self.timeout)
                ftp.login(cred["user"], cred["pass"])
                ftp.quit()

                result.success = True
                sev = "HIGH" if cred["user"] == "anonymous" else "CRITICAL"
                result.severity = sev
                result.evidence = (
                    f"FTP login successful with "
                    f"{cred['user']}:{cred['pass'] or '(blank)'}"
                )
                results.append(result)
                self._vprint(
                    f"    [creds] {ip}:{port} FTP: "
                    f"DEFAULT CRED {cred['user']}"
                )
                break

            except ftplib.error_perm:
                continue
            except Exception:
                break

        return results

    # ── HTTP Basic Auth ──────────────────────────────────────

    def _test_http_basic(
        self, ip: str, port: int,
    ) -> list[CredentialResult]:
        """Test HTTP endpoints for default basic auth."""
        results: list[CredentialResult] = []
        if not HAS_REQUESTS:
            return results

        scheme = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{ip}:{port}"

        # First check if the target requires auth
        try:
            resp = _requests.get(
                base_url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "EASM-Scanner/3.0"},
            )
            # Also check common admin paths
            auth_paths = ["/", "/admin", "/manager/html", "/login"]
            needs_auth = False
            auth_url = base_url

            for path in auth_paths:
                try:
                    r = _requests.get(
                        f"{base_url}{path}",
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                        headers={"User-Agent": "EASM-Scanner/3.0"},
                    )
                    if r.status_code == 401:
                        needs_auth = True
                        auth_url = f"{base_url}{path}"
                        break
                except Exception:
                    continue

            if not needs_auth:
                return results

        except Exception:
            return results

        # Test default credentials
        for cred in DEFAULT_CREDS["http_basic"]:
            result = CredentialResult(
                ip=ip, port=port, service="http_basic",
                username=cred["user"],
            )
            try:
                resp = _requests.get(
                    auth_url,
                    auth=(cred["user"], cred["pass"]),
                    timeout=self.timeout,
                    verify=False,
                    headers={"User-Agent": "EASM-Scanner/3.0"},
                )
                if resp.status_code in (200, 301, 302):
                    result.success = True
                    result.evidence = (
                        f"HTTP Basic Auth accepted "
                        f"{cred['user']}:{cred['pass']} "
                        f"at {auth_url}"
                    )
                    results.append(result)
                    self._vprint(
                        f"    [creds] {ip}:{port} HTTP: "
                        f"DEFAULT CRED {cred['user']}"
                    )
                    break

            except Exception:
                break

        return results

    # ── SNMP ──────────────────────────────────────────────────

    def _test_snmp(self, ip: str, port: int) -> list[CredentialResult]:
        """Test SNMP for default community strings."""
        results: list[CredentialResult] = []

        for cred in DEFAULT_CREDS["snmp"]:
            community = cred["community"]
            result = CredentialResult(
                ip=ip, port=port, service="snmp",
                username=community,
                severity="HIGH",
            )

            # Simple SNMP v2c GET request for sysDescr.0
            # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)

                # Build SNMPv2c GET packet for sysDescr.0
                pkt = self._build_snmpv2c_get(community)
                sock.sendto(pkt, (ip, port))

                data, _ = sock.recvfrom(4096)
                sock.close()

                if data and len(data) > 10:
                    result.success = True
                    result.evidence = (
                        f"SNMP community '{community}' accepted"
                    )
                    results.append(result)
                    self._vprint(
                        f"    [creds] {ip}:{port} SNMP: "
                        f"community '{community}' accepted"
                    )
                    break

            except socket.timeout:
                continue
            except Exception:
                break

        return results

    @staticmethod
    def _build_snmpv2c_get(community: str) -> bytes:
        """Build a minimal SNMPv2c GET request for sysDescr.0."""
        # Minimal BER-encoded SNMPv2c GET-request
        comm_bytes = community.encode()
        # OID 1.3.6.1.2.1.1.1.0 (sysDescr)
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
                     0x01, 0x01, 0x00])
        # NULL value
        null_val = bytes([0x05, 0x00])
        # VarBind
        varbind = bytes([0x30, len(oid) + len(null_val)]) + oid + null_val
        # VarBindList
        varbind_list = bytes([0x30, len(varbind)]) + varbind
        # Request ID
        req_id = bytes([0x02, 0x04, 0x00, 0x00, 0x00, 0x01])
        # Error status + index
        error = bytes([0x02, 0x01, 0x00, 0x02, 0x01, 0x00])
        # PDU (GET-request = 0xA0)
        pdu_content = req_id + error + varbind_list
        pdu = bytes([0xa0, len(pdu_content)]) + pdu_content
        # Version (SNMPv2c = 1)
        version = bytes([0x02, 0x01, 0x01])
        # Community string
        comm = bytes([0x04, len(comm_bytes)]) + comm_bytes
        # Message
        msg_content = version + comm + pdu
        message = bytes([0x30, len(msg_content)]) + msg_content
        return message

    # ── Redis ────────────────────────────────────────────────

    def _test_redis(self, ip: str, port: int) -> list[CredentialResult]:
        """Test Redis for no-auth access."""
        results: list[CredentialResult] = []
        result = CredentialResult(
            ip=ip, port=port, service="redis",
            username="(no auth)",
            severity="CRITICAL",
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.send(b"PING\r\n")
            data = sock.recv(1024)
            sock.close()

            if b"+PONG" in data:
                result.success = True
                result.evidence = "Redis accepts commands without authentication"
                results.append(result)
                self._vprint(
                    f"    [creds] {ip}:{port} Redis: NO AUTH REQUIRED"
                )

        except Exception:
            pass

        return results

    # ── MySQL ────────────────────────────────────────────────

    def _test_mysql(self, ip: str, port: int) -> list[CredentialResult]:
        """Test MySQL for default credentials."""
        results: list[CredentialResult] = []

        try:
            import mysql.connector
        except ImportError:
            self._vprint("    [creds] mysql-connector not installed")
            return results

        for cred in DEFAULT_CREDS["mysql"]:
            result = CredentialResult(
                ip=ip, port=port, service="mysql",
                username=cred["user"],
            )
            try:
                conn = mysql.connector.connect(
                    host=ip, port=port,
                    user=cred["user"],
                    password=cred["pass"],
                    connection_timeout=self.timeout,
                )
                conn.close()

                result.success = True
                result.evidence = (
                    f"MySQL login successful with "
                    f"{cred['user']}:{cred['pass'] or '(blank)'}"
                )
                results.append(result)
                self._vprint(
                    f"    [creds] {ip}:{port} MySQL: "
                    f"DEFAULT CRED {cred['user']}"
                )
                break

            except Exception:
                continue

        return results

    # ── PostgreSQL ───────────────────────────────────────────

    def _test_postgres(
        self, ip: str, port: int,
    ) -> list[CredentialResult]:
        """Test PostgreSQL for default credentials."""
        results: list[CredentialResult] = []

        try:
            import psycopg2
        except ImportError:
            self._vprint("    [creds] psycopg2 not installed")
            return results

        for cred in DEFAULT_CREDS["postgres"]:
            result = CredentialResult(
                ip=ip, port=port, service="postgres",
                username=cred["user"],
            )
            try:
                conn = psycopg2.connect(
                    host=ip, port=port,
                    user=cred["user"],
                    password=cred["pass"],
                    connect_timeout=self.timeout,
                    dbname="postgres",
                )
                conn.close()

                result.success = True
                result.evidence = (
                    f"PostgreSQL login successful with "
                    f"{cred['user']}:{cred['pass'] or '(blank)'}"
                )
                results.append(result)
                self._vprint(
                    f"    [creds] {ip}:{port} PostgreSQL: "
                    f"DEFAULT CRED {cred['user']}"
                )
                break

            except Exception:
                continue

        return results

    # ── MongoDB ──────────────────────────────────────────────

    def _test_mongodb(
        self, ip: str, port: int,
    ) -> list[CredentialResult]:
        """Test MongoDB for no-auth access."""
        results: list[CredentialResult] = []

        try:
            import pymongo
        except ImportError:
            # Fallback: raw socket test
            return self._test_mongodb_socket(ip, port)

        result = CredentialResult(
            ip=ip, port=port, service="mongodb",
            username="(no auth)",
            severity="CRITICAL",
        )
        try:
            client = pymongo.MongoClient(
                ip, port,
                serverSelectionTimeoutMS=self.timeout * 1000,
                socketTimeoutMS=self.timeout * 1000,
            )
            # Try to list databases (requires auth if enabled)
            client.list_database_names()
            client.close()

            result.success = True
            result.evidence = "MongoDB accepts connections without authentication"
            results.append(result)
            self._vprint(
                f"    [creds] {ip}:{port} MongoDB: NO AUTH REQUIRED"
            )

        except Exception:
            pass

        return results

    def _test_mongodb_socket(
        self, ip: str, port: int,
    ) -> list[CredentialResult]:
        """Test MongoDB via raw socket (fallback)."""
        results: list[CredentialResult] = []
        result = CredentialResult(
            ip=ip, port=port, service="mongodb",
            username="(no auth)",
            severity="CRITICAL",
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send isMaster command (minimal wire protocol)
            # This is a simplified check
            sock.send(
                b"\x3e\x00\x00\x00"  # messageLength
                b"\x01\x00\x00\x00"  # requestID
                b"\x00\x00\x00\x00"  # responseTo
                b"\xd4\x07\x00\x00"  # opCode (OP_QUERY)
                b"\x00\x00\x00\x00"  # flags
                b"admin.$cmd\x00"    # fullCollectionName
                b"\x00\x00\x00\x00"  # numberToSkip
                b"\x01\x00\x00\x00"  # numberToReturn
                b"\x15\x00\x00\x00"  # document (BSON)
                b"\x10isMaster\x00"
                b"\x01\x00\x00\x00"
                b"\x00"
            )
            data = sock.recv(4096)
            sock.close()

            if data and len(data) > 20:
                result.success = True
                result.evidence = (
                    "MongoDB responds to queries without authentication"
                )
                results.append(result)

        except Exception:
            pass

        return results

    # ── Helpers ──────────────────────────────────────────────

    def _identify_service(self, port: int) -> str:
        """Identify service type from port number."""
        for service, ports in SERVICE_PORTS.items():
            if port in ports:
                return service
        return ""

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
