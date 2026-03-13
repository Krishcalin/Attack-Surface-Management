"""
EASM Scanner — Port Scanner Module
TCP port scanning with service banner grabbing.
Uses native Python sockets; wraps naabu/masscan if installed.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


# Default top ports (common web + service ports)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 2082, 2083, 2086, 2087,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
    8888, 9090, 9200, 27017,
]

# Known port-to-service mapping
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 27017: "mongodb",
}


@dataclass
class PortResult:
    """Result of a port scan for a single IP:port."""
    ip: str
    port: int
    state: str = "open"           # open, closed, filtered
    service: str = ""
    banner: str = ""
    tls: bool = False
    tls_subject: str = ""


class PortScanner:
    """Multi-threaded TCP port scanner with optional tool wrappers."""

    def __init__(
        self,
        ports: Optional[list[int]] = None,
        threads: int = 100,
        timeout: int = 3,
        verbose: bool = False,
    ) -> None:
        self.ports = ports or DEFAULT_PORTS
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────

    def scan(self, targets: list[str]) -> list[PortResult]:
        """Scan a list of IPs/hostnames for open ports.
        Tries naabu first, falls back to threaded Python scanning."""

        # Try naabu
        naabu_results = self._naabu_scan(targets)
        if naabu_results is not None:
            return naabu_results

        # Threaded Python fallback
        results: list[PortResult] = []

        tasks: list[tuple[str, int]] = []
        for target in targets:
            for port in self.ports:
                tasks.append((target, port))

        self._vprint(
            f"    [port-scan] scanning {len(targets)} host(s) x "
            f"{len(self.ports)} port(s) = {len(tasks)} probes"
        )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe, ip, port): (ip, port)
                for ip, port in tasks
            }
            for fut in as_completed(futures):
                result = fut.result()
                if result and result.state == "open":
                    with self._lock:
                        results.append(result)

        self._vprint(
            f"    [port-scan] found {len(results)} open port(s)"
        )
        return sorted(results, key=lambda r: (r.ip, r.port))

    def scan_single(self, ip: str) -> list[PortResult]:
        """Scan a single IP for open ports."""
        return self.scan([ip])

    # ── naabu wrapper ───────────────────────────────────────

    def _naabu_scan(self, targets: list[str]) -> Optional[list[PortResult]]:
        binary = shutil.which("naabu")
        if not binary:
            return None

        results: list[PortResult] = []
        stdin_data = "\n".join(targets)
        port_str = ",".join(str(p) for p in self.ports)

        try:
            proc = subprocess.run(
                [binary, "-silent", "-p", port_str],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=300,
            )
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if ":" in line:
                    host, port_s = line.rsplit(":", 1)
                    try:
                        port = int(port_s)
                    except ValueError:
                        continue
                    results.append(PortResult(
                        ip=host,
                        port=port,
                        state="open",
                        service=PORT_SERVICES.get(port, ""),
                    ))
            self._vprint(
                f"    [naabu] found {len(results)} open port(s)"
            )
        except (subprocess.TimeoutExpired, Exception) as exc:
            self._vprint(f"    [naabu] error: {exc}")
            return None

        # Grab banners for open ports
        self._grab_banners(results)
        return results

    # ── Python TCP probe ────────────────────────────────────

    def _probe(self, ip: str, port: int) -> Optional[PortResult]:
        """Probe a single IP:port via TCP connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((ip, port))
            if result_code != 0:
                sock.close()
                return None

            pr = PortResult(
                ip=ip,
                port=port,
                state="open",
                service=PORT_SERVICES.get(port, ""),
            )

            # Banner grab
            pr.banner = self._grab_banner(sock, ip, port)

            # TLS check for known TLS ports
            if port in (443, 993, 995, 8443, 2083, 2087):
                pr.tls = True
                pr.tls_subject = self._get_tls_subject(ip, port)

            sock.close()
            return pr

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab_banner(self, sock: socket.socket, ip: str,
                     port: int) -> str:
        """Attempt to grab a service banner."""
        try:
            # For HTTP ports, send a request
            if port in (80, 8000, 8080, 8888, 9090):
                sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                    f"Connection: close\r\n\r\n".encode()
                )
            elif port in (25, 110, 143, 21):
                pass  # These typically send banner on connect
            else:
                sock.sendall(b"\r\n")

            sock.settimeout(2)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:512]
        except Exception:
            return ""

    def _get_tls_subject(self, ip: str, port: int) -> str:
        """Get the TLS certificate subject CN."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(
                            x[0] for x in cert.get("subject", ())
                        )
                        return subject.get("commonName", "")
                    # binary_form fallback — just note TLS is present
                    return "(tls-present)"
        except Exception:
            return ""

    def _grab_banners(self, results: list[PortResult]) -> None:
        """Grab banners for a list of open ports in parallel."""
        def _do(pr: PortResult) -> None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((pr.ip, pr.port))
                pr.banner = self._grab_banner(sock, pr.ip, pr.port)
                if pr.port in (443, 993, 995, 8443, 2083, 2087):
                    pr.tls = True
                    pr.tls_subject = self._get_tls_subject(pr.ip, pr.port)
                sock.close()
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(_do, results))

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
