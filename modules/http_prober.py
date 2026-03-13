"""
EASM Scanner — HTTP Prober Module
Probes discovered hosts for live HTTP/HTTPS services.
Captures status codes, titles, headers, technology fingerprints.
Wraps httpx if installed; pure-Python fallback via requests.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import requests as _requests
    from requests.exceptions import RequestException
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# Technology signatures: {header/pattern: tech_name}
TECH_SIGNATURES: dict[str, list[tuple[str, str]]] = {
    "server": [
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("microsoft-iis", "IIS"),
        ("cloudflare", "Cloudflare"),
        ("gunicorn", "Gunicorn"),
        ("openresty", "OpenResty"),
        ("litespeed", "LiteSpeed"),
        ("envoy", "Envoy"),
        ("caddy", "Caddy"),
    ],
    "x-powered-by": [
        ("php", "PHP"),
        ("asp.net", "ASP.NET"),
        ("express", "Express.js"),
        ("next.js", "Next.js"),
        ("nuxt", "Nuxt.js"),
        ("django", "Django"),
        ("flask", "Flask"),
        ("rails", "Ruby on Rails"),
        ("spring", "Spring"),
    ],
}

# Title-based technology detection
TITLE_TECH: list[tuple[str, str]] = [
    ("wordpress", "WordPress"),
    ("drupal", "Drupal"),
    ("joomla", "Joomla"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("jenkins", "Jenkins"),
    ("gitlab", "GitLab"),
    ("sonarqube", "SonarQube"),
    ("phpmyadmin", "phpMyAdmin"),
    ("pgadmin", "pgAdmin"),
    ("minio", "MinIO"),
    ("traefik", "Traefik"),
    ("portainer", "Portainer"),
    ("consul", "HashiCorp Consul"),
    ("vault", "HashiCorp Vault"),
    ("harbor", "Harbor"),
    ("nexus", "Nexus"),
    ("artifactory", "Artifactory"),
    ("prometheus", "Prometheus"),
    ("alertmanager", "AlertManager"),
    ("argocd", "Argo CD"),
    ("rancher", "Rancher"),
]


@dataclass
class HTTPResult:
    """Result of an HTTP probe."""
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    favicon_hash: str = ""
    tls: bool = False
    error: str = ""


class HTTPProber:
    """Multi-threaded HTTP service prober with tech fingerprinting."""

    HTTP_PORTS = [80, 8000, 8080, 8888, 9090]
    HTTPS_PORTS = [443, 8443, 2083, 2087]

    def __init__(
        self,
        threads: int = 50,
        timeout: int = 10,
        follow_redirects: bool = True,
        verbose: bool = False,
    ) -> None:
        self.threads = threads
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self._lock = threading.Lock()

    # ── Public API ──────────────────────────────────────────

    def probe(
        self,
        targets: list[str],
        ports: Optional[list[int]] = None,
    ) -> list[HTTPResult]:
        """Probe targets (domains or IPs) for live HTTP services.
        Tries httpx first, falls back to threaded Python requests."""

        if ports is None:
            ports = self.HTTP_PORTS + self.HTTPS_PORTS

        # Try httpx
        httpx_results = self._httpx_probe(targets, ports)
        if httpx_results is not None:
            return httpx_results

        # Python fallback
        urls = self._build_urls(targets, ports)
        results: list[HTTPResult] = []

        self._vprint(
            f"    [http] probing {len(urls)} URL(s) across "
            f"{len(targets)} target(s)"
        )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe_url, url): url for url in urls}
            for fut in as_completed(futures):
                result = fut.result()
                if result and result.status_code > 0:
                    with self._lock:
                        results.append(result)

        self._vprint(f"    [http] {len(results)} live service(s) found")
        return sorted(results, key=lambda r: r.url)

    def probe_url(self, url: str) -> Optional[HTTPResult]:
        """Probe a single URL."""
        return self._probe_url(url)

    # ── httpx wrapper ───────────────────────────────────────

    def _httpx_probe(
        self,
        targets: list[str],
        ports: list[int],
    ) -> Optional[list[HTTPResult]]:
        binary = shutil.which("httpx")
        if not binary:
            return None

        results: list[HTTPResult] = []
        stdin_data = "\n".join(targets)
        port_str = ",".join(str(p) for p in ports)

        try:
            proc = subprocess.run(
                [
                    binary, "-silent",
                    "-ports", port_str,
                    "-status-code", "-title", "-server",
                    "-content-type", "-content-length",
                    "-follow-redirects",
                    "-json",
                ],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=300,
            )
            import json
            for line in proc.stdout.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    hr = HTTPResult(
                        url=obj.get("url", ""),
                        status_code=obj.get("status_code", 0),
                        title=obj.get("title", ""),
                        server=obj.get("webserver", ""),
                        content_type=obj.get("content_type", ""),
                        content_length=obj.get("content_length", 0),
                        redirect_url=obj.get("final_url", ""),
                        tls=obj.get("url", "").startswith("https://"),
                    )
                    hr.technologies = self._detect_tech_from_result(hr)
                    results.append(hr)
                except (json.JSONDecodeError, KeyError):
                    continue

            self._vprint(
                f"    [httpx] {len(results)} live service(s) found"
            )
        except (subprocess.TimeoutExpired, Exception) as exc:
            self._vprint(f"    [httpx] error: {exc}")
            return None

        return results

    # ── Python HTTP probe ───────────────────────────────────

    def _probe_url(self, url: str) -> Optional[HTTPResult]:
        if not _HAS_REQUESTS:
            return None

        hr = HTTPResult(url=url)
        try:
            resp = _requests.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=False,
                headers={
                    "User-Agent": (
                        "EASM-Scanner/1.0 "
                        "(Attack Surface Discovery)"
                    ),
                },
            )
            hr.status_code = resp.status_code
            hr.content_type = resp.headers.get("Content-Type", "")
            hr.server = resp.headers.get("Server", "")
            hr.tls = url.startswith("https://")

            cl = resp.headers.get("Content-Length", "0")
            try:
                hr.content_length = int(cl)
            except ValueError:
                hr.content_length = len(resp.content)

            if resp.url != url:
                hr.redirect_url = resp.url

            # Store select headers
            for h in ("Server", "X-Powered-By", "X-Frame-Options",
                       "Strict-Transport-Security", "Content-Security-Policy",
                       "X-Content-Type-Options", "X-XSS-Protection",
                       "Access-Control-Allow-Origin", "Set-Cookie"):
                v = resp.headers.get(h)
                if v:
                    hr.headers[h] = v

            # Extract title
            hr.title = self._extract_title(resp.text)

            # Tech fingerprinting
            hr.technologies = self._detect_tech_from_result(hr)

            # Favicon hash
            hr.favicon_hash = self._favicon_hash(url)

        except RequestException as exc:
            hr.error = str(exc)[:200]
        except Exception as exc:
            hr.error = str(exc)[:200]

        return hr

    # ── Tech fingerprinting ─────────────────────────────────

    def _detect_tech_from_result(self, hr: HTTPResult) -> list[str]:
        techs: list[str] = []

        # Header-based detection
        server_lower = hr.server.lower()
        for pattern, name in TECH_SIGNATURES.get("server", []):
            if pattern in server_lower:
                techs.append(name)

        xpb = hr.headers.get("X-Powered-By", "").lower()
        for pattern, name in TECH_SIGNATURES.get("x-powered-by", []):
            if pattern in xpb:
                techs.append(name)

        # Title-based detection
        title_lower = hr.title.lower()
        for pattern, name in TITLE_TECH:
            if pattern in title_lower:
                techs.append(name)

        # Security header presence
        if hr.headers.get("Strict-Transport-Security"):
            techs.append("HSTS")
        if hr.headers.get("Content-Security-Policy"):
            techs.append("CSP")

        return list(dict.fromkeys(techs))  # dedupe preserving order

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            title = m.group(1).strip()
            title = re.sub(r"\s+", " ", title)
            return title[:200]
        return ""

    def _favicon_hash(self, base_url: str) -> str:
        """Compute MMH3-style hash of favicon (simplified MD5 for now)."""
        if not _HAS_REQUESTS:
            return ""
        try:
            fav_url = base_url.rstrip("/") + "/favicon.ico"
            resp = _requests.get(fav_url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                return hashlib.md5(resp.content).hexdigest()[:16]
        except Exception:
            pass
        return ""

    @staticmethod
    def _build_urls(targets: list[str], ports: list[int]) -> list[str]:
        urls: list[str] = []
        for target in targets:
            for port in ports:
                if port in (443, 8443, 2083, 2087):
                    scheme = "https"
                else:
                    scheme = "http"
                if port in (80, 443):
                    urls.append(f"{scheme}://{target}")
                else:
                    urls.append(f"{scheme}://{target}:{port}")
        return list(dict.fromkeys(urls))  # dedupe

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# Suppress urllib3 InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
