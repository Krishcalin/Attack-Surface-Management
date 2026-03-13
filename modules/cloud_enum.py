"""
EASM Scanner -- Cloud Storage Enumeration
Enumerates and tests permissions on cloud storage buckets:
  - AWS S3 buckets
  - Azure Blob Storage containers
  - Google Cloud Storage (GCS) buckets

Detection methods:
  - Domain/subdomain pattern matching
  - HTTP HEAD/GET probing for public access
  - Permission testing (list, read)
  - Does NOT attempt write/delete operations
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Cloud storage URL patterns ─────────────────────────────────────

S3_PATTERNS = [
    r"([\w.-]+)\.s3\.amazonaws\.com",
    r"([\w.-]+)\.s3-[\w-]+\.amazonaws\.com",
    r"([\w.-]+)\.s3\.[\w-]+\.amazonaws\.com",
    r"s3\.amazonaws\.com/([\w.-]+)",
    r"s3-[\w-]+\.amazonaws\.com/([\w.-]+)",
]

AZURE_PATTERNS = [
    r"([\w.-]+)\.blob\.core\.windows\.net",
    r"([\w.-]+)\.blob\.core\.windows\.net/([\w.-]+)",
]

GCS_PATTERNS = [
    r"storage\.googleapis\.com/([\w.-]+)",
    r"([\w.-]+)\.storage\.googleapis\.com",
]


@dataclass
class CloudBucketResult:
    """Result of a cloud storage enumeration check."""
    provider: str              # "aws_s3", "azure_blob", "gcs"
    bucket_name: str
    url: str = ""
    publicly_listable: bool = False
    publicly_readable: bool = False
    objects_found: int = 0
    evidence: str = ""
    severity: str = "HIGH"
    source_domain: str = ""    # domain where bucket was discovered

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "bucket_name": self.bucket_name,
            "url": self.url,
            "publicly_listable": self.publicly_listable,
            "publicly_readable": self.publicly_readable,
            "objects_found": self.objects_found,
            "evidence": self.evidence,
            "severity": self.severity,
            "source_domain": self.source_domain,
        }


class CloudStorageEnumerator:
    """Enumerate and test cloud storage buckets."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def enumerate_from_domains(
        self,
        domains: list[str],
        org_name: str = "",
    ) -> list[CloudBucketResult]:
        """Generate bucket name candidates from domain names and org."""
        if not HAS_REQUESTS:
            self._vprint("    [cloud] requests library not available")
            return []

        candidates: dict[str, dict[str, str]] = {}  # name -> {provider, source}

        for domain in domains:
            parts = domain.replace(".", "-")
            base = domain.split(".")[0]
            root = ".".join(domain.split(".")[-2:]).replace(".", "-")

            # S3 candidates
            for name in (domain, parts, base, root,
                         f"{base}-backup", f"{base}-data",
                         f"{base}-assets", f"{base}-static",
                         f"{base}-uploads", f"{base}-media",
                         f"{base}-dev", f"{base}-staging",
                         f"{base}-prod", f"{base}-logs"):
                candidates[name] = {"provider": "aws_s3", "source": domain}

            # Azure candidates
            for name in (base, root, parts):
                candidates[name] = {"provider": "azure_blob", "source": domain}

            # GCS candidates
            for name in (domain, base, root,
                         f"{base}-public", f"{base}-storage"):
                candidates[name] = {"provider": "gcs", "source": domain}

        # Add org-based candidates
        if org_name:
            org_clean = re.sub(r"[^a-zA-Z0-9-]", "-", org_name.lower()).strip("-")
            for name in (org_clean, f"{org_clean}-backup",
                         f"{org_clean}-data", f"{org_clean}-assets",
                         f"{org_clean}-public", f"{org_clean}-uploads"):
                candidates[name] = {"provider": "aws_s3", "source": "org-name"}

        results: list[CloudBucketResult] = []
        checked = 0

        for bucket_name, info in candidates.items():
            if checked >= 200:  # safety cap
                break
            checked += 1

            provider = info["provider"]
            source = info["source"]

            if provider == "aws_s3":
                result = self._check_s3(bucket_name, source)
            elif provider == "azure_blob":
                result = self._check_azure(bucket_name, source)
            elif provider == "gcs":
                result = self._check_gcs(bucket_name, source)
            else:
                continue

            if result and (result.publicly_listable or result.publicly_readable):
                results.append(result)

        self._vprint(
            f"    [cloud] checked {checked} bucket candidate(s), "
            f"{len(results)} publicly accessible"
        )
        return results

    def check_urls(
        self, urls: list[str],
    ) -> list[CloudBucketResult]:
        """Check URLs for cloud storage references."""
        if not HAS_REQUESTS:
            return []

        results: list[CloudBucketResult] = []
        seen: set[str] = set()

        for url in urls:
            # Match S3
            for pattern in S3_PATTERNS:
                match = re.search(pattern, url, re.I)
                if match:
                    bucket = match.group(1)
                    if bucket not in seen:
                        seen.add(bucket)
                        result = self._check_s3(bucket, url)
                        if result:
                            results.append(result)

            # Match Azure
            for pattern in AZURE_PATTERNS:
                match = re.search(pattern, url, re.I)
                if match:
                    account = match.group(1)
                    container = match.group(2) if match.lastindex >= 2 else ""
                    key = f"{account}/{container}"
                    if key not in seen:
                        seen.add(key)
                        result = self._check_azure(
                            account, url, container
                        )
                        if result:
                            results.append(result)

            # Match GCS
            for pattern in GCS_PATTERNS:
                match = re.search(pattern, url, re.I)
                if match:
                    bucket = match.group(1)
                    if bucket not in seen:
                        seen.add(bucket)
                        result = self._check_gcs(bucket, url)
                        if result:
                            results.append(result)

        return results

    # ── S3 checks ────────────────────────────────────────────

    def _check_s3(
        self, bucket_name: str, source: str = "",
    ) -> Optional[CloudBucketResult]:
        """Check if an S3 bucket is publicly accessible."""
        url = f"https://{bucket_name}.s3.amazonaws.com"
        result = CloudBucketResult(
            provider="aws_s3",
            bucket_name=bucket_name,
            url=url,
            source_domain=source,
        )

        try:
            # HEAD request to check existence
            resp = _requests.head(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                headers={"User-Agent": "EASM-Scanner/3.0"},
            )

            if resp.status_code == 404:
                return None  # Bucket doesn't exist

            if resp.status_code == 403:
                # Bucket exists but not public
                result.evidence = "S3 bucket exists (403 Forbidden)"
                result.severity = "INFO"
                return result

            # Try to list bucket contents
            list_resp = _requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "EASM-Scanner/3.0"},
            )

            if list_resp.status_code == 200:
                body = list_resp.text[:5000]
                if "<ListBucketResult" in body:
                    result.publicly_listable = True
                    result.publicly_readable = True
                    result.severity = "CRITICAL"

                    # Count objects
                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    result.objects_found = len(keys)
                    result.evidence = (
                        f"S3 bucket publicly listable: "
                        f"{len(keys)} object(s) visible"
                    )
                    self._vprint(
                        f"    [cloud] S3 {bucket_name}: "
                        f"PUBLIC ({len(keys)} objects)"
                    )
                elif "AccessDenied" in body:
                    result.evidence = "S3 bucket exists (AccessDenied)"
                    result.severity = "INFO"

        except Exception:
            return None

        return result

    # ── Azure checks ─────────────────────────────────────────

    def _check_azure(
        self,
        account_name: str,
        source: str = "",
        container: str = "",
    ) -> Optional[CloudBucketResult]:
        """Check if an Azure Blob container is publicly accessible."""
        containers_to_check = [container] if container else [
            "$web", "public", "data", "backup", "assets",
            "uploads", "media", "static", "files",
        ]

        for cont in containers_to_check:
            if not cont:
                continue
            url = (
                f"https://{account_name}.blob.core.windows.net"
                f"/{cont}?restype=container&comp=list"
            )
            result = CloudBucketResult(
                provider="azure_blob",
                bucket_name=f"{account_name}/{cont}",
                url=url,
                source_domain=source,
            )

            try:
                resp = _requests.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": "EASM-Scanner/3.0"},
                )

                if resp.status_code == 200:
                    body = resp.text[:5000]
                    if "<EnumerationResults" in body or "<Blobs>" in body:
                        result.publicly_listable = True
                        result.publicly_readable = True
                        result.severity = "CRITICAL"

                        blobs = re.findall(r"<Name>([^<]+)</Name>", body)
                        result.objects_found = len(blobs)
                        result.evidence = (
                            f"Azure container publicly listable: "
                            f"{len(blobs)} blob(s) visible"
                        )
                        self._vprint(
                            f"    [cloud] Azure {account_name}/{cont}: "
                            f"PUBLIC ({len(blobs)} blobs)"
                        )
                        return result

            except Exception:
                continue

        return None

    # ── GCS checks ───────────────────────────────────────────

    def _check_gcs(
        self, bucket_name: str, source: str = "",
    ) -> Optional[CloudBucketResult]:
        """Check if a GCS bucket is publicly accessible."""
        url = f"https://storage.googleapis.com/{bucket_name}"
        result = CloudBucketResult(
            provider="gcs",
            bucket_name=bucket_name,
            url=url,
            source_domain=source,
        )

        try:
            resp = _requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "EASM-Scanner/3.0"},
            )

            if resp.status_code == 404:
                return None

            if resp.status_code == 200:
                body = resp.text[:5000]
                if "<ListBucketResult" in body:
                    result.publicly_listable = True
                    result.publicly_readable = True
                    result.severity = "CRITICAL"

                    keys = re.findall(r"<Key>([^<]+)</Key>", body)
                    result.objects_found = len(keys)
                    result.evidence = (
                        f"GCS bucket publicly listable: "
                        f"{len(keys)} object(s) visible"
                    )
                    self._vprint(
                        f"    [cloud] GCS {bucket_name}: "
                        f"PUBLIC ({len(keys)} objects)"
                    )
                    return result

            if resp.status_code == 403:
                result.evidence = "GCS bucket exists (403 Forbidden)"
                result.severity = "INFO"
                return result

        except Exception:
            return None

        return result

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
