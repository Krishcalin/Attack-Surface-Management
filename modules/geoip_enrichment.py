"""
EASM Scanner -- GeoIP Enrichment Module
Resolves IP addresses to geographic location and ISP/org information.
Uses free ip-api.com (no key) and ipinfo.io (optional token).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


@dataclass
class GeoIPInfo:
    """Geographic and ISP data for an IP address."""
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    isp: str = ""
    org: str = ""
    as_number: str = ""
    as_name: str = ""
    is_hosting: bool = False
    is_proxy: bool = False
    timezone: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "org": self.org,
            "as_number": self.as_number,
            "as_name": self.as_name,
            "is_hosting": self.is_hosting,
            "timezone": self.timezone,
        }

    @property
    def location_str(self) -> str:
        parts = [p for p in [self.city, self.region, self.country] if p]
        return ", ".join(parts) if parts else "Unknown"


class GeoIPEnrichment:
    """IP geolocation enrichment using free APIs."""

    # ip-api.com: 45 requests/min free tier
    IPAPI_URL = "http://ip-api.com/json/"
    IPAPI_BATCH_URL = "http://ip-api.com/batch"
    IPAPI_FIELDS = (
        "status,country,countryCode,regionName,city,lat,lon,"
        "isp,org,as,asname,hosting,proxy,timezone,query"
    )

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose
        self._cache: dict[str, GeoIPInfo] = {}
        self._last_call: float = 0.0

    # ── Public API ──────────────────────────────────────────

    def lookup(self, ip: str) -> GeoIPInfo:
        """Look up GeoIP for a single IP."""
        if ip in self._cache:
            return self._cache[ip]

        result = self._ipapi_single(ip)
        if result:
            self._cache[ip] = result
            return result

        empty = GeoIPInfo(ip=ip)
        self._cache[ip] = empty
        return empty

    def bulk_lookup(self, ips: list[str]) -> dict[str, GeoIPInfo]:
        """Look up GeoIP for multiple IPs (uses batch API)."""
        # Dedupe + filter cached
        unique = list({ip for ip in ips if ip and ip not in self._cache})
        results: dict[str, GeoIPInfo] = {}

        # Return cached first
        for ip in ips:
            if ip in self._cache:
                results[ip] = self._cache[ip]

        if not unique:
            return results

        # Batch lookup (ip-api supports up to 100 per batch)
        for i in range(0, len(unique), 100):
            batch = unique[i:i + 100]
            batch_results = self._ipapi_batch(batch)
            if batch_results:
                for ip, info in batch_results.items():
                    self._cache[ip] = info
                    results[ip] = info
            else:
                # Fallback: individual lookups
                for ip in batch:
                    info = self._ipapi_single(ip)
                    if info:
                        self._cache[ip] = info
                        results[ip] = info

        self._vprint(
            f"    [geoip] enriched {len(results)} IP(s)"
        )
        return results

    # ── ip-api.com ──────────────────────────────────────────

    def _ipapi_single(self, ip: str) -> Optional[GeoIPInfo]:
        if not _HAS_REQUESTS:
            return None

        self._rate_limit()
        try:
            resp = _requests.get(
                f"{self.IPAPI_URL}{ip}?fields={self.IPAPI_FIELDS}",
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            if data.get("status") != "success":
                return None

            return self._parse_ipapi(data)

        except Exception as exc:
            self._vprint(f"    [geoip] {ip}: error {exc}")
            return None

    def _ipapi_batch(
        self, ips: list[str],
    ) -> Optional[dict[str, GeoIPInfo]]:
        if not _HAS_REQUESTS:
            return None

        self._rate_limit()
        try:
            payload = [
                {"query": ip, "fields": self.IPAPI_FIELDS}
                for ip in ips
            ]
            resp = _requests.post(
                self.IPAPI_BATCH_URL,
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return None

            results: dict[str, GeoIPInfo] = {}
            for item in resp.json():
                if item.get("status") == "success":
                    info = self._parse_ipapi(item)
                    results[info.ip] = info

            return results

        except Exception as exc:
            self._vprint(f"    [geoip] batch error: {exc}")
            return None

    @staticmethod
    def _parse_ipapi(data: dict) -> GeoIPInfo:
        as_field = data.get("as", "")
        as_num = ""
        as_name = ""
        if as_field:
            parts = as_field.split(" ", 1)
            as_num = parts[0] if parts else ""
            as_name = parts[1] if len(parts) > 1 else ""

        return GeoIPInfo(
            ip=data.get("query", ""),
            country=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            latitude=data.get("lat", 0.0),
            longitude=data.get("lon", 0.0),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            as_number=as_num,
            as_name=as_name,
            is_hosting=data.get("hosting", False),
            is_proxy=data.get("proxy", False),
            timezone=data.get("timezone", ""),
            source="ip-api.com",
        )

    def _rate_limit(self) -> None:
        """Respect ip-api.com rate limit (45/min = ~1.3s between calls)."""
        elapsed = time.time() - self._last_call
        if elapsed < 1.4:
            time.sleep(1.4 - elapsed)
        self._last_call = time.time()

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)
