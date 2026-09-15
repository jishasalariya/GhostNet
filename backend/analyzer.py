from __future__ import annotations

import asyncio
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, List, Optional

import httpx
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "verification", "account", "update",
    "billing", "banking", "support", "paypal", "meta-mask", "wallet", "crypto",
    "free", "bonus", "gift", "netflix", "apple", "microsoft", "google", "amazon",
    "recover", "password", "credential", "auth", "validation", "confirm",
    "checkout", "pay", "payment", "invoice", "portal", "order", "subscribe",
    "refund", "giftcard", "claim", "redeem", "card", "security", "signin-account",
    "verified", "login-check"
]

POPULAR_DOMAINS = {
    "google.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 10525,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 98
    },
    "google.co.in": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 8500,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 98
    },
    "youtube.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 7800,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 98
    },
    "facebook.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 8200,
        "registrar": "Registrar Safe, LLC",
        "suspicious_patterns": [],
        "base_trust_score": 96
    },
    "wikipedia.org": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 9200,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 99
    },
    "netflix.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 10500,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 97
    },
    "linkedin.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 8500,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 97
    },
    "paypal.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 10020,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 96
    },
    "apple.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 18000,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 97
    },
    "microsoft.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 16000,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 97
    },
    "github.com": {
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 6700,
        "registrar": "MarkMonitor, Inc.",
        "suspicious_patterns": [],
        "base_trust_score": 98
    }
}

POPULAR_BRANDS = ["google", "paypal", "apple", "microsoft", "netflix", "amazon", "facebook", "stripe"]

def check_typosquatting(domain_part: str) -> Optional[str]:
    dp_lower = domain_part.lower()


    subs = dp_lower.replace("1", "l").replace("0", "o").replace("i", "l").replace("vv", "w")
    for brand in POPULAR_BRANDS:
        if brand in subs and brand not in dp_lower:
            return brand


    for brand in POPULAR_BRANDS:
        brand_prefix = brand[:-1]
        if len(brand_prefix) >= 4:
            if brand_prefix in dp_lower and brand not in dp_lower:
                if abs(len(dp_lower) - len(brand)) <= 3:
                    return brand

    return None

def normalize_and_filter_links(links: List[str], base_url: str, domain: str) -> List[str]:
    local_links = set()
    for l in links:
        resolved = urllib.parse.urljoin(base_url, l.split("#")[0])
        extracted_res = tldextract.extract(resolved)
        res_domain = f"{extracted_res.domain}.{extracted_res.suffix}"
        if res_domain == domain:
            if not resolved.lower().endswith((".png", ".jpg", ".jpeg", ".pdf", ".zip", ".tar.gz", ".dmg", ".exe", ".css", ".js")):
                local_links.add(resolved)
    local_links.discard(base_url)
    local_links.discard(base_url.rstrip("/"))
    local_links.discard(base_url + "/")
    return list(local_links)

async def scan_single_page(page_url: str, verify_ssl: bool, headers: dict) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=verify_ssl, headers=headers) as client:
            resp = await client.get(page_url)
            if resp.status_code == 200:
                parser = PageContentParser()
                parser.feed(resp.text)
                return {
                    "url": page_url,
                    "title": parser.title,
                    "forms": parser.forms,
                    "inputs": parser.inputs,
                    "scripts": parser.scripts,
                    "text_content": parser.text_content
                }
    except Exception:
        if verify_ssl:
            try:
                async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False, headers=headers) as client:
                    resp = await client.get(page_url)
                    if resp.status_code == 200:
                        parser = PageContentParser()
                        parser.feed(resp.text)
                        return {
                            "url": page_url,
                            "title": parser.title,
                            "forms": parser.forms,
                            "inputs": parser.inputs,
                            "scripts": parser.scripts,
                            "text_content": parser.text_content
                        }
            except Exception:
                pass
    return None

def get_ssl_issuer(hostname: str) -> Optional[str]:
    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert and "issuer" in cert:
                    for rdn in cert["issuer"]:
                        for key, val in rdn:
                            if key in ["commonName", "organizationName"]:
                                return val
    except Exception:
        pass
    return None

class PageContentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title: str = ""
        self.headings: List[str] = []
        self.forms: List[Dict[str, str]] = []
        self.inputs: List[Dict[str, str]] = []
        self.scripts: List[str] = []
        self.links: List[str] = []
        self.redirects: List[str] = []
        self.js_redirect_detected: bool = False
        self.metadata: Dict[str, str] = {}
        self.favicon: Optional[str] = None
        self.iframes_count: int = 0
        self.copy_paste_locks_detected: bool = False
        self.inline_scripts_count: int = 0
        self.inline_scripts_length: int = 0
        self.in_title: bool = False
        self.in_heading: bool = False
        self.current_tag: Optional[str] = None
        self.current_form: Optional[Dict[str, str]] = None
        self.current_script_is_inline: bool = False
        self.text_content: List[str] = []

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        attrs_dict = dict(attrs)


        for attr_name, attr_val in attrs:
            if attr_name.lower() in ["oncontextmenu", "oncopy", "onpaste", "onselectstart"]:
                self.copy_paste_locks_detected = True

        if tag == "title":
            self.in_title = True
        elif tag in ["h1", "h2", "h3"]:
            self.in_heading = True
        elif tag == "form":
            form_info = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get"),
                "class": attrs_dict.get("class", ""),
                "id": attrs_dict.get("id", "")
            }
            self.forms.append(form_info)
            self.current_form = form_info
        elif tag == "input":
            input_info = {
                "type": attrs_dict.get("type", "text"),
                "name": attrs_dict.get("name", ""),
                "id": attrs_dict.get("id", ""),
                "placeholder": attrs_dict.get("placeholder", ""),
                "form_action": self.current_form.get("action", "") if self.current_form else ""
            }
            self.inputs.append(input_info)
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
            if href:
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
                if "url=" in content.lower():
                    parts = content.split("url=")
                    if len(parts) > 1:
                        self.redirects.append(parts[1].strip("'\" "))
            meta_name = attrs_dict.get("name", "").lower() or attrs_dict.get("property", "").lower()
            meta_content = attrs_dict.get("content", "")
            if meta_name and meta_content:
                if meta_name in ["description", "keywords", "generator", "og:title", "og:description", "viewport"]:
                    self.metadata[meta_name] = meta_content

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag in ["h1", "h2", "h3"]:
            self.in_heading = False
        elif tag == "form":
            self.current_form = None
        elif tag == "script":
            self.current_script_is_inline = False
        self.current_tag = None

    def handle_data(self, data):
        cleaned_data = data.strip()
        if not cleaned_data:
            return

        if self.in_title:
            self.title = cleaned_data
        elif self.in_heading:
            self.headings.append(cleaned_data)

        if self.current_tag == "script":
            script_text = cleaned_data.lower()
            if "location.href" in script_text or "location.replace" in script_text or "window.location" in script_text or "location.assign" in script_text:
                self.js_redirect_detected = True
            if self.current_script_is_inline:
                self.inline_scripts_length += len(data)

        if self.current_tag not in ["script", "style", "title", "head", "meta", "link"]:
            self.text_content.append(cleaned_data)

async def analyze_url(url: str) -> dict:
    """
    Performs multiple cybersecurity checks on the provided URL:
    1. Standardizes URL schema.
    2. Runs pattern heuristics (phishing keywords, subdomains, etc.).
    3. Verifies HTTPS connectivity.
    4. Queries RDAP for domain age and registrar.
    """

    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:

        url = "http://" + url
        parsed_url = urllib.parse.urlparse(url)

    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""


    extracted = tldextract.extract(hostname)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else hostname




    suspicious_patterns = []


    official_domains = {
        "google": ["google.com", "google.co.uk", "google.co.in", "google.ad", "google.ae", "google.com.sg"],
        "paypal": ["paypal.com", "paypal.me"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
        "netflix": ["netflix.com"],
        "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
        "facebook": ["facebook.com", "fb.com"],
        "stripe": ["stripe.com"]
    }

    brand_impersonated = None
    if extracted.domain:
        brand_match = check_typosquatting(extracted.domain)
        if brand_match:
            is_official = False
            for official in official_domains.get(brand_match, []):
                if hostname.lower().endswith(official):
                    is_official = True
                    break
            if not is_official:
                brand_impersonated = brand_match

    if not brand_impersonated and extracted.subdomain:
        subdomains = [s for s in extracted.subdomain.split(".") if s]
        for sub in subdomains:
            brand_match = check_typosquatting(sub)
            if brand_match:
                is_official = False
                for official in official_domains.get(brand_match, []):
                    if hostname.lower().endswith(official):
                        is_official = True
                        break
                if not is_official:
                    brand_impersonated = brand_match
                    break

    if brand_impersonated:
        suspicious_patterns.append(f"Brand lookalike/impersonation (typosquatting) detected (impersonating '{brand_impersonated}')")


    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        suspicious_patterns.append("IP Address used instead of Domain Name")


    found_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in hostname.lower() or kw in path.lower() or kw in query.lower():

            if kw in ["google", "paypal", "apple", "microsoft", "amazon", "netflix"] and kw in extracted.domain.lower():
                continue
            found_keywords.append(kw)
    if found_keywords:
        suspicious_patterns.append(f"Suspicious keywords detected: {', '.join(found_keywords)}")


    subdomains = [s for s in extracted.subdomain.split(".") if s]
    if len(subdomains) >= 3:
        suspicious_patterns.append(f"High number of subdomains ({len(subdomains)}) detected")


    if "-" in extracted.domain:
        suspicious_patterns.append("Domain name contains suspicious hyphens")


    if len(extracted.domain) > 25:
        suspicious_patterns.append("Abnormally long domain name")


    https_enabled = False
    ssl_valid = False
    http_reachable = False

    headers_report = {
        "Strict-Transport-Security": False,
        "Content-Security-Policy": False,
        "X-Frame-Options": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Server": "Unknown"
    }


    test_urls = []
    if parsed_url.scheme == "https":
        test_urls = [url, url.replace("https://", "http://")]
    else:
        test_urls = [url.replace("http://", "https://"), url]


    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    final_resolved_url = None


    https_url = test_urls[0] if "https://" in test_urls[0] else test_urls[1]
    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, headers=headers) as client:
        try:
            response = await client.head(https_url)
            if response.status_code < 400:
                https_enabled = True
                ssl_valid = True
                http_reachable = True
                final_resolved_url = str(response.url)
            else:
                response_get = await client.get(https_url)
                if response_get.status_code < 500:
                    https_enabled = True
                    ssl_valid = True
                    http_reachable = True
                    final_resolved_url = str(response_get.url)
        except Exception:
            pass


    if not https_enabled:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False, headers=headers) as client:
            try:
                response = await client.head(https_url)
                if response.status_code < 400:
                    https_enabled = True
                    http_reachable = True
                    final_resolved_url = str(response.url)
                else:
                    response_get = await client.get(https_url)
                    if response_get.status_code < 500:
                        https_enabled = True
                        http_reachable = True
                        final_resolved_url = str(response_get.url)
            except Exception:
                pass


    if not http_reachable:
        http_url = test_urls[1] if "http://" in test_urls[1] else test_urls[0]
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, headers=headers) as client:
            try:
                response = await client.head(http_url)
                if response.status_code < 400:
                    http_reachable = True
                    final_resolved_url = str(response.url)
                else:
                    response_get = await client.get(http_url)
                    if response_get.status_code < 500:
                        http_reachable = True
                        final_resolved_url = str(response_get.url)
            except Exception:
                pass

    if not https_enabled:
        suspicious_patterns.append("HTTPS is not enabled or SSL certificate is invalid")
    elif not ssl_valid:
        suspicious_patterns.append("HTTPS is enabled but SSL certificate could not be verified")

    if not http_reachable:
        suspicious_patterns.append("Host is currently unresponsive or unreachable")


    if final_resolved_url:
        parsed_final = urllib.parse.urlparse(final_resolved_url)
        final_hostname = parsed_final.hostname or ""
        if final_hostname:
            extracted_final = tldextract.extract(final_hostname)
            final_domain = f"{extracted_final.domain}.{extracted_final.suffix}" if extracted_final.domain and extracted_final.suffix else final_hostname

            if final_domain.lower() != domain.lower():
                is_final_popular = final_domain.lower() in ["google.com", "facebook.com", "microsoft.com", "apple.com", "github.com", "twitter.com", "instagram.com", "linkedin.com", "google.co.in", "google.co.uk", "google.ad", "google.ae", "google.com.sg"]
                if not is_final_popular:
                    suspicious_patterns.append(f"Cross-domain redirect to unrecognized website '{final_domain}' detected")

    ssl_issuer = None
    if https_enabled and hostname:
        try:
            loop = asyncio.get_running_loop()
            ssl_issuer = await loop.run_in_executor(None, get_ssl_issuer, hostname)
        except Exception:
            pass


    domain_age_days = None
    registrar = "Unknown"

    if domain:
        try:
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True) as client:
                rdap_url = f"https://rdap.org/domain/{domain}"
                rdap_response = await client.get(rdap_url)
                if rdap_response.status_code == 200:
                    data = rdap_response.json()



                    entities = data.get("entities", [])
                    for entity in entities:
                        if "registrar" in entity.get("roles", []):

                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        registrar = item[3]
                                        break
                            if registrar == "Unknown":
                                registrar = entity.get("handle", "Unknown")
                            break


                    events = data.get("events", [])
                    created_date_str = None
                    for event in events:
                        action = event.get("eventAction", "").lower()
                        if action in ["registration", "creation"]:
                            created_date_str = event.get("eventDate")
                            break

                    if created_date_str:


                        created_date_str = created_date_str.replace("Z", "+00:00")
                        created_date = datetime.fromisoformat(created_date_str)
                        now = datetime.now(timezone.utc)
                        delta = now - created_date
                        domain_age_days = max(0, delta.days)

        except Exception as e:

            print(f"RDAP lookup failed for {domain}: {str(e)}")


    html_content = ""
    page_data = {
        "title": "",
        "headings": [],
        "has_password_field": False,
        "forms_count": 0,
        "input_fields": [],
        "external_scripts": [],
        "text_snippet": ""
    }

    if http_reachable:
        target_fetch_url = https_url if https_enabled else test_urls[1]
        try:
            verify_ssl = ssl_valid
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=verify_ssl, headers=headers) as client:
                resp = await client.get(target_fetch_url)
                if resp.status_code == 200:
                    html_content = resp.text
                    for h_name in headers_report.keys():
                        for k, v in resp.headers.items():
                            if k.lower() == h_name.lower():
                                if h_name == "Server":
                                    headers_report["Server"] = v
                                else:
                                    headers_report[h_name] = True
        except Exception:
            if verify_ssl:
                try:
                    async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, verify=False, headers=headers) as client:
                        resp = await client.get(target_fetch_url)
                        if resp.status_code == 200:
                            html_content = resp.text
                            for h_name in headers_report.keys():
                                for k, v in resp.headers.items():
                                    if k.lower() == h_name.lower():
                                        if h_name == "Server":
                                            headers_report["Server"] = v
                                        else:
                                            headers_report[h_name] = True
                except Exception:
                    pass

    if html_content:
        try:
            parser = PageContentParser()
            parser.feed(html_content)

            snippet = " ".join(parser.text_content[:30])
            if len(snippet) > 300:
                snippet = snippet[:300] + "..."


            local_subpages = normalize_and_filter_links(parser.links, target_fetch_url, domain)
            target_subpages = local_subpages[:3]

            subpage_results = []
            if target_subpages:
                tasks = [scan_single_page(sub_url, verify_ssl, headers) for sub_url in target_subpages]
                subpage_results = await asyncio.gather(*tasks)
                subpage_results = [r for r in subpage_results if r]


            all_inputs = list(parser.inputs)
            all_forms = list(parser.forms)
            all_scripts = list(parser.scripts)
            subpage_urls_scanned = []

            for r in subpage_results:
                all_inputs.extend(r["inputs"])
                all_forms.extend(r["forms"])
                all_scripts.extend(r["scripts"])
                subpage_urls_scanned.append(r["url"])

            has_pwd = any(inp.get("type", "").lower() == "password" for inp in all_inputs)


            has_card_field = False
            card_kws = ["cardnumber", "card-number", "cc-num", "cvv", "cvc", "expiry", "expiration", "cardholder", "cc-name"]
            for inp in all_inputs:
                name_attr = (inp.get("name") or "").lower()
                id_attr = (inp.get("id") or "").lower()
                placeholder_attr = (inp.get("placeholder") or "").lower()
                for kw in card_kws:
                    if kw in name_attr or kw in id_attr or kw in placeholder_attr:
                        has_card_field = True
                        break

            external_scripts = []
            for src in all_scripts:
                if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                    extracted_src = tldextract.extract(src)
                    src_domain = f"{extracted_src.domain}.{extracted_src.suffix}"
                    if src_domain != domain:
                        external_scripts.append(src)

            favicon_url = ""
            if parser.favicon:
                favicon_url = urllib.parse.urljoin(target_fetch_url, parser.favicon)
            else:

                favicon_url = urllib.parse.urljoin(target_fetch_url, "/favicon.ico")

            page_data = {
                "title": parser.title,
                "headings": parser.headings[:5],
                "has_password_field": has_pwd,
                "has_card_field": has_card_field,
                "forms_count": len(all_forms),
                "input_fields": [f"{inp.get('name') or 'unnamed'} ({inp.get('type')})" for inp in all_inputs[:15]],
                "external_scripts": external_scripts[:5],
                "text_snippet": snippet,
                "subpages_scanned": subpage_urls_scanned,
                "favicon": favicon_url,
                "metadata": parser.metadata,
                "iframes_count": parser.iframes_count,
                "copy_paste_locks_detected": parser.copy_paste_locks_detected,
                "inline_scripts_count": parser.inline_scripts_count,
                "inline_scripts_length": parser.inline_scripts_length
            }


            if has_pwd and not https_enabled:
                suspicious_patterns.append("Password input detected over insecure connection (HTTP)")

            for f in all_forms:
                act = f.get("action", "")
                if act.startswith("http://") or act.startswith("https://") or act.startswith("//"):
                    extracted_act = tldextract.extract(act)
                    act_domain = f"{extracted_act.domain}.{extracted_act.suffix}"
                    if act_domain != domain and act_domain not in ["google.com", "facebook.com", "microsoft.com", "apple.com", "okta.com", "auth0.com"]:
                        suspicious_patterns.append(f"Form action submits to external domain ({act_domain})")
                if https_enabled and act.startswith("http://"):
                    suspicious_patterns.append("Insecure form action (HTTP) detected on secure page (HTTPS)")


            is_popular = domain in ["google.com", "paypal.com", "apple.com", "microsoft.com", "netflix.com", "amazon.com", "facebook.com", "stripe.com", "github.com", "okta.com", "auth0.com"]
            is_new_or_unknown = (domain_age_days is None) or (domain_age_days < 365)
            if has_pwd and not is_popular and is_new_or_unknown:
                suspicious_patterns.append("Sensitive credential form hosted on unrecognized or new domain")

            if has_card_field and not is_popular and is_new_or_unknown:
                suspicious_patterns.append("Payment credential input forms hosted on unrecognized or new domain")


            has_payment_kw = any(kw in url.lower() for kw in ["checkout", "pay", "payment", "invoice", "billing"])
            if has_payment_kw and not is_popular and is_new_or_unknown:
                if not (has_pwd or has_card_field):
                    suspicious_patterns.append("Billing/checkout portal structure detected on unrecognized or new domain")


            if has_pwd and external_scripts:
                suspicious_patterns.append("Login page loads scripts from third-party external origins (potential session injection risk)")


            for l in parser.links:
                resolved = urllib.parse.urljoin(target_fetch_url, l.split("#")[0])
                extracted_res = tldextract.extract(resolved)
                res_domain = f"{extracted_res.domain}.{extracted_res.suffix}"

                if res_domain != domain and extracted_res.domain:
                    has_dest_kw = any(kw in resolved.lower() for kw in ["login", "secure", "verify", "banking", "paypal", "meta-mask", "account", "update", "checkout", "pay"])
                    has_dest_tld = extracted_res.suffix in ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "zip", "science", "live", "info", "club"]

                    if has_dest_kw or has_dest_tld:
                        if res_domain not in ["google.com", "facebook.com", "microsoft.com", "apple.com", "github.com", "twitter.com", "instagram.com", "linkedin.com", "google.co.in", "google.co.uk", "google.ad", "google.ae", "google.com.sg"]:
                            suspicious_patterns.append(f"Suspicious outgoing link (phishing gateway) to '{res_domain}' detected")
                            break


            if parser.js_redirect_detected:
                suspicious_patterns.append("Automated JavaScript redirection code detected in page script")
            if parser.redirects:
                resolved_redir = urllib.parse.urljoin(target_fetch_url, parser.redirects[0])
                extracted_redir = tldextract.extract(resolved_redir)
                redir_domain = f"{extracted_redir.domain}.{extracted_redir.suffix}"
                suspicious_patterns.append(f"HTML meta-refresh redirect to '{redir_domain}' detected")

        except Exception as e:
            print(f"HTML parsing error: {e}")


    SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "zip", "science", "live", "info", "club"]
    if extracted.suffix in SUSPICIOUS_TLDS:
        if len(suspicious_patterns) > 0 or page_data.get("has_password_field", False):
            suspicious_patterns.append(f"Untrusted top-level domain (.{extracted.suffix}) combined with suspicious indicators")


    if domain_age_days is not None and domain_age_days < 90:
        suspicious_patterns.append(f"Domain is extremely new (created only {domain_age_days} days ago)")


    domain_score = 25
    if not domain_age_days:
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
    if any("unrecognized or new domain" in p for p in suspicious_patterns):
        dom_score -= 15
    if any("Form action submits to external" in p or "Insecure form action" in p for p in suspicious_patterns):
        dom_score -= 8
    if page_data.get("copy_paste_locks_detected"):
        dom_score -= 4
    if page_data.get("iframes_count", 0) > 1:
        dom_score -= 4
    dom_score = max(0, min(25, dom_score))


    headers_score = 15
    if not headers_report["Content-Security-Policy"]:
        headers_score -= 4
    if not headers_report["X-Frame-Options"]:
        headers_score -= 4
    if not headers_report["X-Content-Type-Options"]:
        headers_score -= 4
    if not headers_report["Referrer-Policy"]:
        headers_score -= 3
    headers_score = max(0, min(15, headers_score))


    scripts_score = 15
    if any("Cross-domain redirect" in p for p in suspicious_patterns):
        scripts_score -= 15
    if any("Automated JavaScript redirection" in p or "HTML meta-refresh" in p for p in suspicious_patterns):
        scripts_score -= 10
    if any("Login page loads scripts from third-party" in p for p in suspicious_patterns):
        scripts_score -= 5
    scripts_score = max(0, min(15, scripts_score))

    base_score = domain_score + ssl_score + dom_score + headers_score + scripts_score


    if len(suspicious_patterns) >= 3:
        base_score -= 15
        suspicious_patterns.append("Multiple compounded risk indicators detected on website")

    base_score = max(0, min(100, int(base_score)))


    if domain.lower() in POPULAR_DOMAINS:
        pop = POPULAR_DOMAINS[domain.lower()]
        base_score = pop["base_trust_score"]
        domain_score = 25
        ssl_score = 20
        dom_score = 25
        headers_score = 13
        scripts_score = 15
        suspicious_patterns = []
        if pop.get("registrar"):
            registrar = pop["registrar"]
        if pop.get("domain_age_days"):
            domain_age_days = pop["domain_age_days"]
        for h_key in headers_report.keys():
            if h_key != "Server":
                headers_report[h_key] = True

    scorecard = {
        "domain_score": domain_score,
        "ssl_score": ssl_score,
        "dom_score": dom_score,
        "headers_score": headers_score,
        "scripts_score": scripts_score,
        "ssl_issuer": ssl_issuer or "Unknown / Unverified",
        "security_headers": headers_report
    }

    return {
        "url": url,
        "domain": domain,
        "https_enabled": https_enabled,
        "is_reachable": http_reachable,
        "domain_age_days": domain_age_days,
        "registrar": registrar,
        "suspicious_patterns": suspicious_patterns,
        "base_trust_score": base_score,
        "crawled_page_content": page_data,
        "scorecard": scorecard
    }
