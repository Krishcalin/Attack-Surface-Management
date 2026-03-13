"""
EASM Scanner -- Technology Fingerprint Module
Deep technology stack detection from HTTP headers, HTML content, cookies,
JavaScript references, meta tags, and favicon hashes.

Extends the lightweight detection in http_prober.py with 150+ signatures.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


@dataclass
class TechProfile:
    """Technology profile for a web asset."""
    url: str
    technologies: list[str] = field(default_factory=list)
    categories: dict[str, list[str]] = field(default_factory=dict)
    # categories = {"web-server": ["Nginx"], "cms": ["WordPress"], ...}
    favicon_hash: str = ""
    meta_generator: str = ""
    cookies: list[str] = field(default_factory=list)
    js_libraries: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    cdn: str = ""
    waf: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "technologies": self.technologies,
            "categories": self.categories,
            "favicon_hash": self.favicon_hash,
            "meta_generator": self.meta_generator,
            "cdn": self.cdn,
            "waf": self.waf,
        }


# ── Signature database ──────────────────────────────────────────────

# Header-based: (header_name_lower, pattern, tech_name, category)
HEADER_SIGS: list[tuple[str, str, str, str]] = [
    # Web servers
    ("server", "nginx", "Nginx", "web-server"),
    ("server", "apache", "Apache", "web-server"),
    ("server", "microsoft-iis", "IIS", "web-server"),
    ("server", "litespeed", "LiteSpeed", "web-server"),
    ("server", "openresty", "OpenResty", "web-server"),
    ("server", "caddy", "Caddy", "web-server"),
    ("server", "envoy", "Envoy", "web-server"),
    ("server", "tengine", "Tengine", "web-server"),
    ("server", "gunicorn", "Gunicorn", "web-server"),
    ("server", "uvicorn", "Uvicorn", "web-server"),
    ("server", "cowboy", "Cowboy", "web-server"),
    ("server", "jetty", "Jetty", "web-server"),
    ("server", "tomcat", "Apache Tomcat", "web-server"),
    ("server", "wildfly", "WildFly", "web-server"),
    ("server", "kestrel", "Kestrel", "web-server"),
    # CDN / Edge
    ("server", "cloudflare", "Cloudflare", "cdn"),
    ("server", "amazons3", "Amazon S3", "cdn"),
    ("via", "cloudfront", "Amazon CloudFront", "cdn"),
    ("x-served-by", "cache-", "Fastly", "cdn"),
    ("server", "akamaighost", "Akamai", "cdn"),
    ("x-cdn", "incapsula", "Imperva Incapsula", "cdn"),
    ("server", "gws", "Google Web Server", "cdn"),
    ("x-azure-ref", ".", "Azure CDN", "cdn"),
    # Frameworks / Runtime
    ("x-powered-by", "php", "PHP", "language"),
    ("x-powered-by", "asp.net", "ASP.NET", "language"),
    ("x-powered-by", "express", "Express.js", "framework"),
    ("x-powered-by", "next.js", "Next.js", "framework"),
    ("x-powered-by", "nuxt", "Nuxt.js", "framework"),
    ("x-powered-by", "django", "Django", "framework"),
    ("x-powered-by", "flask", "Flask", "framework"),
    ("x-powered-by", "rails", "Ruby on Rails", "framework"),
    ("x-powered-by", "spring", "Spring", "framework"),
    ("x-powered-by", "laravel", "Laravel", "framework"),
    ("x-powered-by", "servlet", "Java Servlet", "framework"),
    ("x-powered-by", "phusion passenger", "Phusion Passenger", "framework"),
    # WAF
    ("server", "akamaighost", "Akamai WAF", "waf"),
    ("x-sucuri-id", ".", "Sucuri WAF", "waf"),
    ("x-dt-traceid", ".", "Dynatrace", "observability"),
    ("x-datadog-trace-id", ".", "Datadog", "observability"),
]

# Cookie-based: (cookie_name_pattern, tech_name, category)
COOKIE_SIGS: list[tuple[str, str, str]] = [
    ("__cfduid", "Cloudflare", "cdn"),
    ("cf_clearance", "Cloudflare", "cdn"),
    ("JSESSIONID", "Java Servlet", "framework"),
    ("PHPSESSID", "PHP", "language"),
    ("ASP.NET_SessionId", "ASP.NET", "language"),
    ("csrftoken", "Django", "framework"),
    ("_rails_", "Ruby on Rails", "framework"),
    ("laravel_session", "Laravel", "framework"),
    ("connect.sid", "Express.js", "framework"),
    ("wp-settings-", "WordPress", "cms"),
    ("XSRF-TOKEN", "Angular", "js-framework"),
    ("__stripe_", "Stripe", "payment"),
]

# HTML body patterns: (regex, tech_name, category)
BODY_SIGS: list[tuple[str, str, str]] = [
    # CMS
    (r"wp-content/|wp-includes/", "WordPress", "cms"),
    (r'content="WordPress', "WordPress", "cms"),
    (r"Drupal\.settings", "Drupal", "cms"),
    (r'content="Drupal', "Drupal", "cms"),
    (r"com_content|com_users", "Joomla", "cms"),
    (r"/sites/default/files/", "Drupal", "cms"),
    (r"Shopify\.theme", "Shopify", "ecommerce"),
    (r"cdn\.shopify\.com", "Shopify", "ecommerce"),
    (r"Magento", "Magento", "ecommerce"),
    (r"WooCommerce", "WooCommerce", "ecommerce"),
    # JS frameworks
    (r"__next", "Next.js", "framework"),
    (r"__nuxt|__NUXT__", "Nuxt.js", "framework"),
    (r"ng-version=", "Angular", "js-framework"),
    (r"react-root|__react", "React", "js-framework"),
    (r"data-v-[a-f0-9]{8}", "Vue.js", "js-framework"),
    (r"ember-view", "Ember.js", "js-framework"),
    (r"svelte", "Svelte", "js-framework"),
    # JS libraries
    (r"jquery[.-]?\d", "jQuery", "js-library"),
    (r"bootstrap[.-]?\d", "Bootstrap", "css-framework"),
    (r"tailwindcss|tailwind\.css", "Tailwind CSS", "css-framework"),
    (r"font-awesome|fontawesome", "Font Awesome", "icon-library"),
    (r"google-analytics\.com|gtag/js", "Google Analytics", "analytics"),
    (r"googletagmanager\.com", "Google Tag Manager", "analytics"),
    (r"hotjar\.com", "Hotjar", "analytics"),
    (r"segment\.com/analytics", "Segment", "analytics"),
    (r"matomo|piwik", "Matomo", "analytics"),
    # Infrastructure hints
    (r"recaptcha", "reCAPTCHA", "security"),
    (r"hcaptcha", "hCaptcha", "security"),
    (r"cloudflare", "Cloudflare", "cdn"),
    (r"akamai", "Akamai", "cdn"),
    # Admin panels / tools
    (r"/grafana/", "Grafana", "monitoring"),
    (r"kibana", "Kibana", "monitoring"),
    (r"jenkins", "Jenkins", "ci-cd"),
    (r"gitlab", "GitLab", "ci-cd"),
    (r"sonarqube", "SonarQube", "ci-cd"),
    (r"portainer", "Portainer", "container"),
    (r"rancher", "Rancher", "container"),
    (r"phpmyadmin", "phpMyAdmin", "database"),
    (r"pgadmin", "pgAdmin", "database"),
    (r"adminer", "Adminer", "database"),
]

# Meta generator patterns: (pattern, tech_name, category)
META_GEN_SIGS: list[tuple[str, str, str]] = [
    ("wordpress", "WordPress", "cms"),
    ("drupal", "Drupal", "cms"),
    ("joomla", "Joomla", "cms"),
    ("typo3", "TYPO3", "cms"),
    ("hugo", "Hugo", "ssg"),
    ("jekyll", "Jekyll", "ssg"),
    ("gatsby", "Gatsby", "ssg"),
    ("ghost", "Ghost", "cms"),
    ("wix.com", "Wix", "website-builder"),
    ("squarespace", "Squarespace", "website-builder"),
    ("shopify", "Shopify", "ecommerce"),
    ("magento", "Magento", "ecommerce"),
    ("prestashop", "PrestaShop", "ecommerce"),
    ("moodle", "Moodle", "lms"),
    ("mediawiki", "MediaWiki", "wiki"),
    ("confluence", "Confluence", "wiki"),
]


class TechFingerprinter:
    """Deep technology fingerprinting engine."""

    def __init__(
        self,
        timeout: int = 10,
        verbose: bool = False,
    ) -> None:
        self.timeout = timeout
        self.verbose = verbose

    # ── Public API ──────────────────────────────────────────

    def fingerprint(self, url: str) -> TechProfile:
        """Fingerprint a single URL for technology stack."""
        profile = TechProfile(url=url)

        if not _HAS_REQUESTS:
            return profile

        try:
            resp = _requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent": (
                        "EASM-Scanner/1.0 (Attack Surface Discovery)"
                    ),
                },
            )
        except Exception as exc:
            self._vprint(f"    [tech] {url}: error {exc}")
            return profile

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:100_000]  # cap body analysis

        # 1. Header analysis
        self._match_headers(profile, headers)

        # 2. Cookie analysis
        self._match_cookies(profile, resp.cookies)

        # 3. Body / HTML analysis
        self._match_body(profile, body)

        # 4. Meta generator
        gen = self._extract_meta_generator(body)
        if gen:
            profile.meta_generator = gen
            self._match_meta_gen(profile, gen)

        # 5. WAF detection
        self._detect_waf(profile, headers, body)

        # 6. CDN detection
        self._detect_cdn(profile, headers)

        # 7. Favicon hash
        profile.favicon_hash = self._favicon_hash(url)

        # Dedupe technologies
        profile.technologies = list(dict.fromkeys(profile.technologies))

        self._vprint(
            f"    [tech] {url}: {len(profile.technologies)} tech(s) - "
            f"{', '.join(profile.technologies[:8])}"
        )
        return profile

    def bulk_fingerprint(
        self, urls: list[str],
    ) -> dict[str, TechProfile]:
        """Fingerprint multiple URLs."""
        results: dict[str, TechProfile] = {}
        for url in urls:
            results[url] = self.fingerprint(url)
        self._vprint(f"    [tech] fingerprinted {len(results)} URL(s)")
        return results

    # ── Matching engines ────────────────────────────────────

    def _match_headers(
        self, profile: TechProfile, headers: dict[str, str],
    ) -> None:
        for header, pattern, tech, cat in HEADER_SIGS:
            val = headers.get(header, "").lower()
            if val and pattern in val:
                self._add_tech(profile, tech, cat)

    def _match_cookies(self, profile: TechProfile, cookies: Any) -> None:
        cookie_names = [c.name for c in cookies] if cookies else []
        for cookie_name in cookie_names:
            profile.cookies.append(cookie_name)
            for pattern, tech, cat in COOKIE_SIGS:
                if pattern.lower() in cookie_name.lower():
                    self._add_tech(profile, tech, cat)

    def _match_body(self, profile: TechProfile, body: str) -> None:
        for pattern, tech, cat in BODY_SIGS:
            if re.search(pattern, body, re.IGNORECASE):
                self._add_tech(profile, tech, cat)

    def _match_meta_gen(self, profile: TechProfile, gen: str) -> None:
        gen_lower = gen.lower()
        for pattern, tech, cat in META_GEN_SIGS:
            if pattern in gen_lower:
                self._add_tech(profile, tech, cat)

    def _detect_waf(
        self, profile: TechProfile,
        headers: dict[str, str], body: str,
    ) -> None:
        # Cloudflare
        if "cf-ray" in headers:
            profile.waf = "Cloudflare"
            self._add_tech(profile, "Cloudflare WAF", "waf")
        # AWS WAF
        if "x-amzn-waf-" in str(headers):
            profile.waf = "AWS WAF"
            self._add_tech(profile, "AWS WAF", "waf")
        # Imperva
        if "x-iinfo" in headers or "incap_ses_" in str(headers):
            profile.waf = "Imperva"
            self._add_tech(profile, "Imperva WAF", "waf")
        # Akamai
        if headers.get("server", "").lower().startswith("akamai"):
            profile.waf = "Akamai"
            self._add_tech(profile, "Akamai WAF", "waf")
        # F5 BIG-IP
        if "bigipserver" in headers or "x-cnection" in headers:
            profile.waf = "F5 BIG-IP"
            self._add_tech(profile, "F5 BIG-IP", "waf")
        # Barracuda
        if "barra_counter_session" in str(headers):
            profile.waf = "Barracuda WAF"
            self._add_tech(profile, "Barracuda WAF", "waf")

    def _detect_cdn(
        self, profile: TechProfile, headers: dict[str, str],
    ) -> None:
        if profile.cdn:
            return
        if "cf-ray" in headers or "cf-cache-status" in headers:
            profile.cdn = "Cloudflare"
        elif "x-amz-cf-id" in headers:
            profile.cdn = "Amazon CloudFront"
        elif "x-served-by" in headers and "cache-" in headers.get(
            "x-served-by", ""
        ):
            profile.cdn = "Fastly"
        elif "x-akamai-" in str(headers):
            profile.cdn = "Akamai"
        elif "x-azure-ref" in headers:
            profile.cdn = "Azure CDN"
        elif headers.get("server", "").lower() == "gws":
            profile.cdn = "Google"

    # ── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _add_tech(profile: TechProfile, tech: str, category: str) -> None:
        if tech not in profile.technologies:
            profile.technologies.append(tech)
        profile.categories.setdefault(category, [])
        if tech not in profile.categories[category]:
            profile.categories[category].append(tech)

    @staticmethod
    def _extract_meta_generator(html: str) -> str:
        m = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)',
            html, re.IGNORECASE,
        )
        return m.group(1).strip() if m else ""

    def _favicon_hash(self, base_url: str) -> str:
        if not _HAS_REQUESTS:
            return ""
        try:
            fav_url = base_url.rstrip("/") + "/favicon.ico"
            resp = _requests.get(fav_url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                return hashlib.md5(resp.content).hexdigest()
        except Exception:
            pass
        return ""

    def _vprint(self, msg: str) -> None:
        if self.verbose:
            print(msg)


# Suppress warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
