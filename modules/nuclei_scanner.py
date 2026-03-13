"""
EASM Scanner -- Nuclei Scanner Wrapper
Wraps ProjectDiscovery's Nuclei for template-based vulnerability scanning.
Falls back to a pure-Python template-matching engine if nuclei is not installed.

Features:
  - Nuclei binary detection and execution
  - JSON output parsing
  - Template category selection
  - Rate limiting and timeout controls
  - Pure-Python fallback for basic HTTP template checks
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Built-in templates (pure-Python fallback) ──────────────────────
# Simplified versions of common Nuclei templates for when the binary
# is not installed.  These cover the most impactful checks.

BUILTIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "git-config-exposure",
        "name": "Git Config Exposure",
        "severity": "high",
        "path": "/.git/config",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["[core]", "[remote"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "env-file-exposure",
        "name": "Environment File Exposure",
        "severity": "critical",
        "path": "/.env",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "API_KEY"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "spring-actuator-env",
        "name": "Spring Actuator Environment Exposure",
        "severity": "high",
        "path": "/actuator/env",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["propertySources", "activeProfiles"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "phpinfo-exposure",
        "name": "PHP Info Exposure",
        "severity": "medium",
        "path": "/phpinfo.php",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["phpinfo()", "PHP Version"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "wp-config-backup",
        "name": "WordPress Config Backup",
        "severity": "critical",
        "path": "/wp-config.php.bak",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["DB_NAME", "DB_PASSWORD"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "swagger-ui-exposure",
        "name": "Swagger UI Exposure",
        "severity": "medium",
        "path": "/swagger-ui.html",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["swagger", "api-docs"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL Introspection Enabled",
        "severity": "medium",
        "path": "/graphql?query={__schema{types{name}}}",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["__schema", "__type"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "server-status-exposure",
        "name": "Apache Server-Status Exposure",
        "severity": "medium",
        "path": "/server-status",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["Apache Server Status", "Total accesses"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "elmah-exposure",
        "name": "ELMAH Error Log Exposure",
        "severity": "high",
        "path": "/elmah.axd",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["Error Log", "ELMAH"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "debug-toolbar-exposure",
        "name": "Django Debug Toolbar Exposure",
        "severity": "high",
        "path": "/__debug__/",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["djdt", "debug toolbar"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "adminer-exposure",
        "name": "Adminer Database Tool Exposure",
        "severity": "high",
        "path": "/adminer.php",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["Adminer", "Login"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "phpmyadmin-exposure",
        "name": "phpMyAdmin Exposure",
        "severity": "high",
        "path": "/phpmyadmin/",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["phpMyAdmin", "pma_"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "ds-store-exposure",
        "name": ".DS_Store File Exposure",
        "severity": "low",
        "path": "/.DS_Store",
        "method": "GET",
        "matchers": [
            {"type": "binary", "bytes": b"\x00\x00\x00\x01Bud1"},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "htpasswd-exposure",
        "name": ".htpasswd File Exposure",
        "severity": "critical",
        "path": "/.htpasswd",
        "method": "GET",
        "matchers": [
            {"type": "word", "words": ["$apr1$", "$2y$", "$2a$", ":{SHA}"]},
            {"type": "status", "status": [200]},
        ],
    },
    {
        "id": "trace-method-enabled",
        "name": "HTTP TRACE Method Enabled",
        "severity": "medium",
        "path": "/",
        "method": "TRACE",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "words": ["TRACE / HTTP"]},
        ],
    },
]


@dataclass
class NucleiResult:
    """Result from a Nuclei scan."""
    template_id: str
    name: str
    severity: str
    matched_at: str              # URL where vulnerability was found
    host: str = ""
    description: str = ""
    evidence: str = ""
    curl_command: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "host": self.host,
            "description": self.description,
            "evidence": self.evidence,
            "tags": self.tags,
        }


class NucleiScanner:
    """Nuclei vulnerability scanner wrapper with Python fallback."""

    def __init__(
        self,
        timeout: int = 15,
        rate_limit: int = 100,
        verbose: bool = False,
        templates_dir: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.templates_dir = templates_dir
        self._binary = shutil.which("nuclei")

    @property
    def has_nuclei(self) -> bool:
        return self._binary is not None

    # ── Public API ──────────────────────────────────────────

    def scan(
        self,
        targets: list[str],
        categories: Optional[list[str]] = None,
        severity_filter: Optional[list[str]] = None,
    ) -> list[NucleiResult]:
        """Scan targets using Nuclei or fallback engine."""
        if self._binary:
            return self._scan_nuclei(
                targets, categories, severity_filter
            )
        else:
            self._vprint(
                "    [nuclei] nuclei binary not found, "
                "using built-in template engine"
            )
            return self._scan_builtin(targets)

    # ── Nuclei binary scanner ───────────────────────────────

    def _scan_nuclei(
        self,
        targets: list[str],
        categories: Optional[list[str]] = None,
        severity_filter: Optional[list[str]] = None,
    ) -> list[NucleiResult]:
        """Run nuclei binary against targets."""
        results: list[NucleiResult] = []

        # Write targets to temp file
        tmp_dir = tempfile.mkdtemp(prefix="easm_nuclei_")
        targets_file = os.path.join(tmp_dir, "targets.txt")
        output_file = os.path.join(tmp_dir, "results.json")

        try:
            with open(targets_file, "w") as f:
                f.write("\n".join(targets))

            cmd = [
                self._binary,
                "-l", targets_file,
                "-jsonl",
                "-o", output_file,
                "-silent",
                "-rate-limit", str(self.rate_limit),
                "-timeout", str(self.timeout),
                "-no-color",
            ]

            # Template categories
            if categories:
                for cat in categories:
                    cmd.extend(["-tags", cat])

            # Severity filter
            if severity_filter:
                cmd.extend([
                    "-severity",
                    ",".join(severity_filter),
                ])

            # Custom templates directory
            if self.templates_dir:
                cmd.extend(["-t", self.templates_dir])

            self._vprint(
                f"    [nuclei] scanning {len(targets)} target(s)..."
            )

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * len(targets) + 120,
            )

            # Parse JSONL output
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            result = NucleiResult(
                                template_id=entry.get("template-id", ""),
                                name=entry.get("info", {}).get("name", ""),
                                severity=entry.get("info", {}).get(
                                    "severity", "unknown"
                                ),
                                matched_at=entry.get("matched-at", ""),
                                host=entry.get("host", ""),
                                description=entry.get("info", {}).get(
                                    "description", ""
                                ),
                                evidence=entry.get(
                                    "extracted-results", ""
                                ) or entry.get("matcher-name", ""),
                                tags=entry.get("info", {}).get("tags", []),
                            )
                            results.append(result)
                        except json.JSONDecodeError:
                            continue

            self._vprint(
                f"    [nuclei] found {len(results)} vulnerability(ies)"
            )

        except subprocess.TimeoutExpired:
            self._vprint("    [nuclei] scan timed out")
        except Exception as exc:
            self._vprint(f"    [nuclei] error: {exc}")
        finally:
            # Cleanup temp files
            try:
                os.remove(targets_file)
                if os.path.exists(output_file):
                    os.remove(output_file)
                os.rmdir(tmp_dir)
            except OSError:
                pass

        return results

    # ── Built-in template engine (fallback) ──────────────────

    def _scan_builtin(
        self, targets: list[str],
    ) -> list[NucleiResult]:
        """Pure-Python template scanner (fallback when nuclei not installed)."""
        if not HAS_REQUESTS:
            self._vprint("    [nuclei] requests library not available")
            return []

        results: list[NucleiResult] = []

        for target in targets:
            # Ensure target has scheme
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"

            for tmpl in BUILTIN_TEMPLATES:
                url = target.rstrip("/") + tmpl["path"]
                method = tmpl.get("method", "GET")

                try:
                    if method == "TRACE":
                        resp = _requests.request(
                            "TRACE", url,
                            timeout=self.timeout,
                            verify=False,
                            headers={"User-Agent": "EASM-Scanner/3.0"},
                        )
                    else:
                        resp = _requests.get(
                            url,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False,
                            headers={"User-Agent": "EASM-Scanner/3.0"},
                        )

                    if self._match_template(resp, tmpl):
                        result = NucleiResult(
                            template_id=tmpl["id"],
                            name=tmpl["name"],
                            severity=tmpl["severity"],
                            matched_at=url,
                            host=target,
                            evidence=(
                                f"HTTP {resp.status_code} "
                                f"({len(resp.content)} bytes)"
                            ),
                        )
                        results.append(result)
                        self._vprint(
                            f"    [nuclei-py] {target}: "
                            f"{tmpl['name']} ({tmpl['severity']})"
                        )

                except Exception:
                    continue

        self._vprint(
            f"    [nuclei-py] scanned {len(targets)} target(s), "
            f"found {len(results)} issue(s)"
        )
        return results

    @staticmethod
    def _match_template(resp: Any, tmpl: dict) -> bool:
        """Check if HTTP response matches template matchers."""
        for matcher in tmpl.get("matchers", []):
            mtype = matcher.get("type", "")

            if mtype == "status":
                if resp.status_code not in matcher.get("status", []):
                    return False

            elif mtype == "word":
                body_lower = resp.text[:10000].lower()
                words = matcher.get("words", [])
                if not any(w.lower() in body_lower for w in words):
                    return False

            elif mtype == "binary":
                expected = matcher.get("bytes", b"")
                if expected not in resp.content[:1000]:
                    return False

        return True

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
