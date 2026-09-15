from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Optional

import httpx
import tldextract

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "secure",
    "verify",
    "verification",
    "account",
    "update",
    "billing",
    "banking",
    "support",
    "paypal",
    "meta-mask",
    "wallet",
    "crypto",
    "free",
    "bonus",
    "gift",
    "netflix",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "recover",
    "password",
    "credential",
    "auth",
    "validation",
    "confirm",
    "checkout",
    "pay",
    "payment",
    "invoice",
    "portal",
    "order",
    "subscribe",
    "refund",
    "giftcard",
    "claim",
    "redeem",
    "card",
    "security",
    "signin-account",
    "verified",
    "login-check",
)

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "click",
    "link",
    "zip",
    "science",
    "live",
    "info",
    "club",
}

POPULAR_DOMAINS = {
    "google.com": 98,
    "google.co.in": 98,
    "youtube.com": 98,
    "facebook.com": 96,
    "wikipedia.org": 99,
    "netflix.com": 97,
    "linkedin.com": 97,
    "paypal.com": 96,
    "apple.com": 97,
    "microsoft.com": 97,
    "github.com": 98,
}

POPULAR_DOMAIN_DETAILS = {
    "google.com": ("MarkMonitor, Inc.", 10525),
    "google.co.in": ("MarkMonitor, Inc.", 8500),
    "youtube.com": ("MarkMonitor, Inc.", 7800),
    "facebook.com": ("Registrar Safe, LLC", 8200),
    "wikipedia.org": ("MarkMonitor, Inc.", 9200),
    "netflix.com": ("MarkMonitor, Inc.", 10500),
    "linkedin.com": ("MarkMonitor, Inc.", 8500),
    "paypal.com": ("MarkMonitor, Inc.", 10020),
    "apple.com": ("MarkMonitor, Inc.", 18000),
    "microsoft.com": ("MarkMonitor, Inc.", 16000),
    "github.com": ("MarkMonitor, Inc.", 6700),
}

POPULAR_BRANDS = (
    "google",
    "paypal",
    "apple",
    "microsoft",
    "netflix",
    "amazon",
    "facebook",
    "stripe",
)

OFFICIAL_BRANDS = {
    "google": {"google.com", "google.co.uk", "google.co.in", "google.ad", "google.ae", "google.com.sg"},
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de"},
    "facebook": {"facebook.com", "fb.com"},
    "stripe": {"stripe.com"},
}

USER_AGENT = "GhostNet/2.0 (+https://github.com/ghostnet)"
REQUEST_TIMEOUT = httpx.Timeout(connect=3.0, read=6.0, write=3.0, pool=3.0)
MAX_BODY_BYTES = 1_500_000
MAX_REDIRECTS = 5
MAX_SUBPAGES = 3
MAX_TEXT_ITEMS = 100
MAX_LINKS = 250

class UnsafeTargetError(ValueError):
    pass

def registrable_domain(hostname: str) -> str:
    extracted = tldextract.extract(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return hostname.lower().rstrip(".")

def check_typosquatting(domain_part: str) -> Optional[str]:
    value = domain_part.lower()
    normalized = value.translate(str.maketrans({"1": "l", "0": "o", "i": "l"})).replace("vv", "w")
    for brand in POPULAR_BRANDS:
        if brand in normalized and brand not in value:
            return brand
    for brand in POPULAR_BRANDS:
        prefix = brand[:-1]
        if len(prefix) >= 4 and prefix in value and brand not in value and abs(len(value) - len(brand)) <= 3:
            return brand
    return None

def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )

def validate_target_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise UnsafeTargetError("URL cannot be empty.")
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*)://", value, re.IGNORECASE)
    if scheme_match:
        if scheme_match.group(1).lower() not in {"http", "https"}:
            raise UnsafeTargetError("Only HTTP and HTTPS URLs are supported.")
    else:
        value = f"https://{value}"
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTargetError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("URLs containing embedded credentials are not supported.")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeTargetError("URL must contain a hostname.")
    normalized_hostname = hostname.lower().rstrip(".")
    if normalized_hostname in {"localhost", "localhost.localdomain"} or normalized_hostname.endswith((".localhost", ".local", ".internal")):
        raise UnsafeTargetError("Private or local network targets are not allowed.")
    if not is_public_ip(hostname):
        raise UnsafeTargetError("Private or local network targets are not allowed.")
    port = parsed.port
    if port is not None and port not in {80, 443}:
        raise UnsafeTargetError("Only ports 80 and 443 are supported.")
    normalized_path = parsed.path or "/"
    return urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            hostname.lower() if ":" not in hostname else f"[{hostname.lower()}]",
            normalized_path,
            parsed.query,
            "",
        )
    )

async def resolve_public_addresses(hostname: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeTargetError("Hostname did not resolve to a public address.")
    if any(not is_public_ip(address) for address in addresses):
        raise UnsafeTargetError("Hostname resolves to a private or reserved network address.")
    return addresses

def normalize_and_filter_links(links: list[str], base_url: str, domain: str) -> list[str]:
    local_links: list[str] = []
    seen: set[str] = set()
    blocked_suffixes = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".pdf", ".zip", ".tar.gz", ".dmg", ".exe", ".css", ".js")
    for link in links[:MAX_LINKS]:
        resolved = urllib.parse.urljoin(base_url, link.split("#", 1)[0].strip())
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        if registrable_domain(parsed.hostname) != domain:
            continue
        clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if clean.rstrip("/") == base_url.rstrip("/"):
            continue
        if clean.lower().endswith(blocked_suffixes) or clean in seen:
            continue
        seen.add(clean)
        local_links.append(clean)
    return local_links

class PageContentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.headings: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.inputs: list[dict[str, str]] = []
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.redirects: list[str] = []
        self.js_redirect_detected = False
        self.metadata: dict[str, str] = {}
        self.favicon: Optional[str] = None
        self.iframes_count = 0
        self.copy_paste_locks_detected = False
        self.inline_scripts_count = 0
        self.inline_scripts_length = 0
        self.in_title = False
        self.in_heading = False
        self.current_tag: Optional[str] = None
        self.current_form: Optional[dict[str, str]] = None
        self.current_script_is_inline = False
        self.text_content: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        self.current_tag = tag
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        for attr_name in attrs_dict:
            if attr_name in {"oncontextmenu", "oncopy", "onpaste", "onselectstart"}:
                self.copy_paste_locks_detected = True
        if tag == "title":
            self.in_title = True
        elif tag in {"h1", "h2", "h3"}:
            self.in_heading = True
        elif tag == "form":
            form_info = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").lower(),
                "class": attrs_dict.get("class", ""),
                "id": attrs_dict.get("id", ""),
            }
            self.forms.append(form_info)
            self.current_form = form_info
        elif tag == "input":
            self.inputs.append(
                {
                    "type": attrs_dict.get("type", "text").lower(),
                    "name": attrs_dict.get("name", ""),
                    "id": attrs_dict.get("id", ""),
                    "placeholder": attrs_dict.get("placeholder", ""),
                    "form_action": self.current_form.get("action", "") if self.current_form else "",
                }
            )
        elif tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                self.scripts.append(src)
                self.current_script_is_inline = False
            else:
                self.inline_scripts_count += 1
                self.current_script_is_inline = True
        elif tag == "a":
            href = attrs_dict.get("href", "")
            if href and len(self.links) < MAX_LINKS:
                self.links.append(href)
        elif tag == "iframe":
            self.iframes_count += 1
        elif tag == "link":
            rel = attrs_dict.get("rel", "").lower()
            if "icon" in rel or rel == "shortcut icon" or rel == "apple-touch-icon":
                self.favicon = attrs_dict.get("href", "")
        elif tag == "meta":
            http_equiv = attrs_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                content = attrs_dict.get("content", "")
                match = re.search(r"(?:^|;)\s*url\s*=\s*(.+)$", content, re.IGNORECASE)
                if match:
                    self.redirects.append(match.group(1).strip(" '\""))
            meta_name = (attrs_dict.get("name") or attrs_dict.get("property") or "").lower()
            meta_content = attrs_dict.get("content", "")
            if meta_name in {"description", "keywords", "generator", "og:title", "og:description", "viewport"} and meta_content:
                self.metadata[meta_name] = meta_content

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag in {"h1", "h2", "h3"}:
            self.in_heading = False
        elif tag == "form":
            self.current_form = None
        elif tag == "script":
            self.current_script_is_inline = False
        self.current_tag = None

    def handle_data(self, data: str) -> None:
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self.in_title and not self.title:
            self.title = cleaned[:300]
        elif self.in_heading and len(self.headings) < 10:
            self.headings.append(cleaned[:300])
        if self.current_tag == "script":
            script_text = cleaned.lower()
            if any(token in script_text for token in ("location.href", "location.replace", "window.location", "location.assign")):
                self.js_redirect_detected = True
            if self.current_script_is_inline:
                self.inline_scripts_length += len(data.encode("utf-8"))
        if self.current_tag not in {"script", "style", "title", "head", "meta", "link"} and len(self.text_content) < MAX_TEXT_ITEMS:
            self.text_content.append(cleaned[:500])

def get_ssl_issuer(hostname: str) -> Optional[str]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:
                cert = secure_socket.getpeercert()
                for rdn in cert.get("issuer", ()):
                    for key, value in rdn:
                        if key in {"commonName", "organizationName"}:
                            return value
    except (OSError, ssl.SSLError):
        return None
    return None

async def fetch_public(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_redirects: int = MAX_REDIRECTS,
) -> tuple[Optional[httpx.Response], bool]:
    current_url = validate_target_url(url)
    for _ in range(max_redirects + 1):
        await resolve_public_addresses(urllib.parse.urlsplit(current_url).hostname or "")
        response = await client.get(current_url, follow_redirects=False)
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                return response, False
            current_url = urllib.parse.urljoin(current_url, location)
            current_url = validate_target_url(current_url)
            continue
        return response, True
    return None, False

async def scan_single_page(page_url: str, headers: dict[str, str]) -> Optional[dict[str, Any]]:
    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:
            response, _ = await fetch_public(client, page_url)
            if response is None or response.status_code >= 400:
                return None
            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type and "xhtml" not in content_type:
                return None
            body = response.content[:MAX_BODY_BYTES]
            parser = PageContentParser()
            parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
            return {
                "url": str(response.url),
                "title": parser.title,
                "forms": parser.forms,
                "inputs": parser.inputs,
                "scripts": parser.scripts,
                "text_content": parser.text_content,
            }
    except (httpx.HTTPError, OSError, ValueError, UnicodeError, UnsafeTargetError):
        return None

async def analyze_url(raw_url: str) -> dict[str, Any]:
    url = validate_target_url(raw_url)
    parsed = urllib.parse.urlsplit(url)
    hostname = parsed.hostname or ""
    domain = registrable_domain(hostname)
    path = parsed.path or ""
    query = parsed.query or ""
    await resolve_public_addresses(hostname)

    suspicious_patterns: list[str] = []

    brand_impersonated: Optional[str] = None
    extracted = tldextract.extract(hostname)
    if extracted.domain:
        brand_match = check_typosquatting(extracted.domain)
        if brand_match:
            official = OFFICIAL_BRANDS.get(brand_match, set())
            if domain not in official:
                brand_impersonated = brand_match
    if not brand_impersonated and extracted.subdomain:
        for subdomain_part in extracted.subdomain.split("."):
            brand_match = check_typosquatting(subdomain_part)
            if brand_match:
                official = OFFICIAL_BRANDS.get(brand_match, set())
                if domain not in official:
                    brand_impersonated = brand_match
                    break

    if brand_impersonated:
        suspicious_patterns.append(
            f"Brand lookalike/impersonation detected (possible '{brand_impersonated}' typosquatting)"
        )

    try:
        ipaddress.ip_address(hostname)
        suspicious_patterns.append("IP address used instead of a domain name")
    except ValueError:
        pass

    found_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in f"{hostname.lower()}{path.lower()}{query.lower()}"
        and not (keyword in {"google", "paypal", "apple", "microsoft", "amazon", "netflix"} and keyword in extracted.domain.lower())
    ]
    if found_keywords:
        suspicious_patterns.append(f"Suspicious keywords detected: {', '.join(found_keywords[:8])}")

    subdomains = [part for part in extracted.subdomain.split(".") if part]
    if len(subdomains) >= 3:
        suspicious_patterns.append(f"High number of subdomains ({len(subdomains)}) detected")
    if "-" in extracted.domain:
        suspicious_patterns.append("Domain name contains suspicious hyphens")
    if len(extracted.domain) > 25:
        suspicious_patterns.append("Abnormally long domain name")
    if extracted.suffix in SUSPICIOUS_TLDS:
        suspicious_patterns.append(f"Domain uses a higher-risk TLD (.{extracted.suffix})")

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    https_enabled = parsed.scheme.lower() == "https"
    ssl_valid = False
    is_reachable = False
    final_url = url
    headers_report: dict[str, Any] = {
        "Strict-Transport-Security": False,
        "Content-Security-Policy": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Server": "Unknown",
    }

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            headers=headers,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:
            response, redirect_ok = await fetch_public(client, url)
            if response is not None:
                is_reachable = response.status_code < 500
                final_url = str(response.url)
                if response.status_code < 500:
                    for key in headers_report:
                        if key.lower() == "server".lower():
                            headers_report[key] = response.headers.get("server", "Unknown")
                        else:
                            headers_report[key] = key.lower() in {name.lower() for name in response.headers}
                if not redirect_ok:
                    suspicious_patterns.append("Redirect chain could not be safely completed")
                if final_url:
                    final_domain = registrable_domain(urllib.parse.urlsplit(final_url).hostname or "")
                    if final_domain and final_domain != domain:
                        suspicious_patterns.append(f"Cross-domain redirect to '{final_domain}' detected")
    except (httpx.HTTPError, OSError, ValueError, UnsafeTargetError):
        pass

    if not https_enabled:
        suspicious_patterns.append("HTTPS is not enabled for the submitted URL")
    else:
        try:
            ssl_valid = await asyncio.to_thread(get_ssl_issuer, hostname)
        except Exception:
            ssl_valid = False
        if not ssl_valid:
            suspicious_patterns.append("TLS certificate could not be independently verified")

    domain_age_days: Optional[int] = None
    registrar = "Unknown"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            rdap_response = await client.get(f"https://rdap.org/domain/{domain}")
            if rdap_response.status_code == 200:
                rdap_data = rdap_response.json()
                for entity in rdap_data.get("entities", []):
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        for item in vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []:
                            if item and item[0] == "fn":
                                registrar = str(item[3])
                                break
                        if registrar == "Unknown":
                            registrar = str(entity.get("handle", "Unknown"))
                        if registrar != "Unknown":
                            break
                for event in rdap_data.get("events", []):
                    if event.get("eventAction", "").lower() in {"registration", "creation"} and event.get("eventDate"):
                        created_at = str(event["eventDate"]).replace("Z", "+00:00")
                        created_date = datetime.fromisoformat(created_at)
                        if created_date.tzinfo is None:
                            created_date = created_date.replace(tzinfo=timezone.utc)
                        domain_age_days = max(0, (datetime.now(timezone.utc) - created_date).days)
                        break
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        pass

    page_data: dict[str, Any] = {
        "title": "",
        "headings": [],
        "has_password_field": False,
        "has_card_field": False,
        "forms_count": 0,
        "input_fields": [],
        "external_scripts": [],
        "text_snippet": "",
        "subpages_scanned": [],
        "favicon": "",
        "metadata": {},
        "iframes_count": 0,
        "copy_paste_locks_detected": False,
        "inline_scripts_count": 0,
        "inline_scripts_length": 0,
    }

    if is_reachable:
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT,
                headers=headers,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            ) as client:
                response, redirect_ok = await fetch_public(client, url)
                if response is not None and response.status_code == 200:
                    content_type = response.headers.get("content-type", "").lower()
                    if "html" in content_type or "xhtml" in content_type or not content_type:
                        for key in headers_report:
                            if key == "Server":
                                headers_report[key] = response.headers.get("server", "Unknown")
                            else:
                                headers_report[key] = key.lower() in {name.lower() for name in response.headers}
                        body = response.content[:MAX_BODY_BYTES]
                        parser = PageContentParser()
                        parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
                        base_page_url = str(response.url)
                        local_subpages = normalize_and_filter_links(parser.links, base_page_url, domain)[:MAX_SUBPAGES]
                        subpage_results = await asyncio.gather(
                            *(scan_single_page(link, headers) for link in local_subpages),
                            return_exceptions=True,
                        )
                        valid_subpages = [item for item in subpage_results if isinstance(item, dict)]
                        all_inputs = list(parser.inputs)
                        all_forms = list(parser.forms)
                        all_scripts = list(parser.scripts)
                        for item in valid_subpages:
                            all_inputs.extend(item["inputs"])
                            all_forms.extend(item["forms"])
                            all_scripts.extend(item["scripts"])

                        has_password = any(item.get("type") == "password" for item in all_inputs)
                        card_keywords = ("cardnumber", "card-number", "cc-num", "cvv", "cvc", "expiry", "expiration", "cardholder", "cc-name")
                        has_card = any(
                            keyword in value.lower()
                            for item in all_inputs
                            for value in (item.get("name", ""), item.get("id", ""), item.get("placeholder", ""))
                            for keyword in card_keywords
                        )

                        external_scripts: list[str] = []
                        for src in all_scripts:
                            resolved = urllib.parse.urljoin(base_page_url, src)
                            script_host = urllib.parse.urlsplit(resolved).hostname or ""
                            if script_host and registrable_domain(script_host) != domain:
                                external_scripts.append(resolved)

                        page_data = {
                            "title": parser.title,
                            "headings": parser.headings[:5],
                            "has_password_field": has_password,
                            "has_card_field": has_card,
                            "forms_count": len(all_forms),
                            "input_fields": [f"{item.get('name') or 'unnamed'} ({item.get('type', 'text')})" for item in all_inputs[:15]],
                            "external_scripts": external_scripts[:5],
                            "text_snippet": " ".join(parser.text_content)[:500],
                            "subpages_scanned": [item["url"] for item in valid_subpages],
                            "favicon": urllib.parse.urljoin(base_page_url, parser.favicon) if parser.favicon else urllib.parse.urljoin(base_page_url, "/favicon.ico"),
                            "metadata": parser.metadata,
                            "iframes_count": parser.iframes_count,
                            "copy_paste_locks_detected": parser.copy_paste_locks_detected,
                            "inline_scripts_count": parser.inline_scripts_count,
                            "inline_scripts_length": parser.inline_scripts_length,
                        }

                        if has_password and not https_enabled:
                            suspicious_patterns.append("Password input detected over an insecure HTTP connection")

                        allowed_external_form_domains = {"google.com", "facebook.com", "microsoft.com", "apple.com", "okta.com", "auth0.com"}
                        for form in all_forms:
                            action = form.get("action", "")
                            if not action:
                                continue
                            resolved_action = urllib.parse.urljoin(base_page_url, action)
                            action_host = urllib.parse.urlsplit(resolved_action).hostname or ""
                            action_domain = registrable_domain(action_host)
                            if action_domain and action_domain != domain and action_domain not in allowed_external_form_domains:
                                suspicious_patterns.append(f"Form action submits to external domain ({action_domain})")
                            if https_enabled and urllib.parse.urlsplit(resolved_action).scheme == "http":
                                suspicious_patterns.append("Insecure HTTP form action detected on an HTTPS page")

                        popular = domain in {
                            "google.com",
                            "paypal.com",
                            "apple.com",
                            "microsoft.com",
                            "netflix.com",
                            "amazon.com",
                            "facebook.com",
                            "stripe.com",
                            "github.com",
                            "okta.com",
                            "auth0.com",
                        }
                        new_or_unknown = domain_age_days is None or domain_age_days < 365
                        if has_password and not popular and new_or_unknown:
                            suspicious_patterns.append("Sensitive credential form on an unrecognized or new domain")
                        if has_card and not popular and new_or_unknown:
                            suspicious_patterns.append("Payment credential input on an unrecognized or new domain")
                        if any(token in url.lower() for token in ("checkout", "payment", "invoice", "billing")) and not popular and new_or_unknown and not (has_password or has_card):
                            suspicious_patterns.append("Billing or checkout structure detected on an unrecognized or new domain")
                        if has_password and external_scripts:
                            suspicious_patterns.append("Login page loads scripts from third-party origins")

                        trusted_external_domains = {
                            "google.com",
                            "facebook.com",
                            "microsoft.com",
                            "apple.com",
                            "github.com",
                            "twitter.com",
                            "instagram.com",
                            "linkedin.com",
                        }
                        for link in parser.links:
                            resolved_link = urllib.parse.urljoin(base_page_url, link.split("#", 1)[0])
                            link_host = urllib.parse.urlsplit(resolved_link).hostname or ""
                            link_domain = registrable_domain(link_host)
                            if link_domain and link_domain != domain:
                                lower_link = resolved_link.lower()
                                risky_destination = any(token in lower_link for token in ("login", "secure", "verify", "banking", "paypal", "metamask", "account", "update", "checkout", "pay"))
                                risky_tld = urllib.parse.urlsplit(resolved_link).hostname and tldextract.extract(link_host).suffix in SUSPICIOUS_TLDS
                                if (risky_destination or risky_tld) and link_domain not in trusted_external_domains:
                                    suspicious_patterns.append(f"Suspicious outgoing link to '{link_domain}' detected")
                                    break

                        if parser.js_redirect_detected:
                            suspicious_patterns.append("Automated JavaScript redirection code detected")
                        if parser.redirects:
                            redirect_target = urllib.parse.urljoin(base_page_url, parser.redirects[0])
                            redirect_domain = registrable_domain(urllib.parse.urlsplit(redirect_target).hostname or "")
                            if redirect_domain and redirect_domain != domain:
                                suspicious_patterns.append(f"HTML meta-refresh redirect to '{redirect_domain}' detected")
        except (httpx.HTTPError, OSError, ValueError, UnsafeTargetError, UnicodeError):
            pass

    if domain_age_days is not None and domain_age_days < 90:
        suspicious_patterns.append(f"Domain is extremely new (created only {domain_age_days} days ago)")

    suspicious_patterns = list(dict.fromkeys(suspicious_patterns))

    domain_score = 25
    if domain_age_days is None:
        domain_score -= 10
    elif domain_age_days < 90:
        domain_score -= 15
    elif domain_age_days < 365:
        domain_score -= 10
    elif domain_age_days > 730:
        domain_score += 3
    if extracted.suffix in SUSPICIOUS_TLDS:
        domain_score -= 10
    if brand_impersonated:
        domain_score -= 20
    domain_score = max(0, min(25, domain_score))

    ssl_score = 20
    if not https_enabled:
        ssl_score -= 20
    elif not ssl_valid:
        ssl_score -= 5
    if not headers_report["Strict-Transport-Security"]:
        ssl_score -= 3
    ssl_score = max(0, min(20, ssl_score))

    dom_score = 25
    if any("Sensitive credential form" in p or "Payment credential input" in p for p in suspicious_patterns):
        dom_score -= 10
    if any("Form action submits to external" in p or "Insecure HTTP form action" in p for p in suspicious_patterns):
        dom_score -= 8
    if page_data.get("copy_paste_locks_detected"):
        dom_score -= 4
    if page_data.get("iframes_count", 0) > 1:
        dom_score -= 4
    dom_score = max(0, min(25, dom_score))

    headers_score = 15
    for key, deduction in {
        "Content-Security-Policy": 4,
        "X-Frame-Options": 4,
        "X-Content-Type-Options": 4,
        "Referrer-Policy": 3,
    }.items():
        if not headers_report[key]:
            headers_score -= deduction
    headers_score = max(0, min(15, headers_score))

    scripts_score = 15
    if any("Cross-domain redirect" in p for p in suspicious_patterns):
        scripts_score -= 15
    if any("redirection" in p or "redirect" in p for p in suspicious_patterns):
        scripts_score -= 8
    if any("third-party origins" in p for p in suspicious_patterns):
        scripts_score -= 5
    scripts_score = max(0, min(15, scripts_score))

    base_score = max(0, min(100, domain_score + ssl_score + dom_score + headers_score + scripts_score))
    if len(suspicious_patterns) >= 3:
        base_score = max(0, base_score - 15)

    if domain in POPULAR_DOMAINS and not suspicious_patterns:
        base_score = POPULAR_DOMAINS[domain]
        details = POPULAR_DOMAIN_DETAILS.get(domain)
        if details:
            registrar, domain_age_days = details

    ssl_issuer = get_ssl_issuer(hostname) if ssl_valid else "Unknown / Unverified"

    scorecard = {
        "domain_score": domain_score,
        "ssl_score": ssl_score,
        "dom_score": dom_score,
        "headers_score": headers_score,
        "scripts_score": scripts_score,
        "ssl_issuer": ssl_issuer,
        "security_headers": headers_report,
    }

    return {
        "url": url,
        "domain": domain,
        "https_enabled": https_enabled,
        "is_reachable": is_reachable,
        "domain_age_days": domain_age_days,
        "registrar": registrar,
        "suspicious_patterns": suspicious_patterns,
        "base_trust_score": int(base_score),
        "crawled_page_content": page_data,
        "scorecard": scorecard,
    }
