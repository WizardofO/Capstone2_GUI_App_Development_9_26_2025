# Phishing URL Feature Extractor (Beginner Friendly)
import sys                                              # import sys was imported to get the system-specific parameters and functions like sys.exit()
import csv                                              # importing csv module to read and write CSV files
import json                                             # importing json module to handle JSON data
import re                                               # importing re module for regular expressions to get
import ssl                                              # importing ssl module to handle SSL connections and certificates
import socket                                           # importing socket module for low-level networking interface
import datetime as dt                                   # importing datetime module to handle date and time
from urllib.parse import urlparse, urljoin              # importing urlparse and urljoin from urllib.parse to parse and join URLs            
from dataclasses import dataclass                       # importing dataclass decorator to create data classes     
from typing import Optional, List, Dict, Any, Tuple     # importing typing module for type hints
import numpy as np

# importing optional modules for WHOIS and DNS
try:
    import whois as whois_module                        # importing whois module to get domain registration info
except Exception:
    whois_module = None

try:
    import dns.resolver                                 # importing dnspython module to perform DNS queries
except Exception:
    dns = None

import requests                                         # importing requests module to make HTTP requests       
from bs4 import BeautifulSoup                           # importing BeautifulSoup from bs4 to parse HTML content
import tldextract                                       # importing tldextract module to extract domain parts

# Standard PySide6 UI imports for GUI creation                           
from PySide6.QtWidgets import (                         # importing necessary PySide6 modules for GUI   
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog,
    QTextEdit, QLineEdit, QProgressBar, QCheckBox, QMessageBox
)
from PySide6.QtCore import Qt, QThread, Signal

# ------------------ Feature extraction utilities -------------------

DEFAULT_TIMEOUT = (10, 20)                                                      # (connect timeout, read timeout) to avoid hanging  
HEADERS = {"User-Agent": "URL-Feature-Extractor/1.0 (+https://example.local)"}  # Custom User-Agent for HTTP requests

# List of known URL shortener domains
SHORTENER_DOMAINS = set('''                                                 
bit.ly goo.gl ow.ly t.co tinyurl.com is.gd buff.ly bit.do lnkd.in
rebrand.ly t.ly v.gd tiny.cc shrtco.de cutt.ly adf.ly shorturl.at
rb.gy s.id tr.im cli.gs po.st bc.vc 2.gp q.gs
'''.split())                                        # set() creates a set of unique domains
                                                    # .split() splits the string into a list of domains     
                                                                             
                                                                        # Characters often used in phishing URLs    
SUSPICIOUS_CHARS = set(['?', '%', '&', '@'])                            # Characters often used in phishing URLs
STANDARD_PORTS = {80, 443, 8080, 8443}                                  # Standard HTTP/HTTPS ports

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")                      # Simple regex for IPv4 addresses from https://stackoverflow.com/questions/11264005/using-a-regex-to-match-ip-addresses                   
IPV6_RE = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")

# Patterns to detect suspicious JavaScript
JS_RIGHT_CLICK_PATTERNS = [
    re.compile(r"oncontextmenu\s*=\s*['\"]?return\s+false", re.I),      # this code is to disable right click and copy paste function
    re.compile(r"event\.button\s*==\s*2", re.I),                
    re.compile(r"document\.oncontextmenu\s*=", re.I),
]
JS_STATUSBAR_PATTERNS = [
    re.compile(r"window\.status\s*=", re.I),
    re.compile(r"status\s*=", re.I),
]
JS_POPUP_PATTERNS = [
    re.compile(r"window\.open\s*\(", re.I),
]
JS_REDIRECT_PATTERNS = [
    re.compile(r"window\.location\s*=", re.I),
    re.compile(r"location\.href\s*=", re.I),
    re.compile(r"location\.replace\s*\(", re.I),
]

META_REFRESH_URL_RE = re.compile(r'url\s*=\s*([^;]+)', re.I)

# ------------------ Utility Functions -------------------

def safe_get(url: str) -> Optional[requests.Response]:
    """
    INPUT: url (str) - The URL to fetch.
    OUTPUT: requests.Response object if successful, else None.
    Safely fetch a URL using requests. Returns None if any error occurs.
    """
    try:
        return requests.get(url, headers=HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None

def get_hostname(url: str) -> Tuple[str, str, Optional[int]]:
    """
    INPUT: url (str) - The URL to parse.
    OUTPUT: (host, scheme, port) - host (str), scheme (str), port (int or None).
    Extract hostname, scheme, and port from a URL.
    """
    # use imports from urllib.parse and tldextract
    p = urlparse(url)
    host = p.hostname or ""
    scheme = p.scheme or ""
    port = p.port
    return host, scheme, port

def is_ip_address(host: str) -> bool:
    """
    INPUT: host (str) - Hostname or IP address.
    OUTPUT: True if host is an IP address, else False.
    Check if the host is an IP address (IPv4 or IPv6).
    """
    #used imports are re,
    if IPV4_RE.match(host or ""):
        return True
    if IPV6_RE.match(host or ""):
        return True
    return False                                                        # checked and Working (Sept 18, 2025)
                                                                        # 17 counts of tabs
def count_double_slash_after_protocol(url: str) -> int:
    """
    INPUT: url (str) - The URL to check.
    OUTPUT: Number of double slashes after protocol (int).
    Count double slashes after the protocol in a URL.
    """
    try:
        after = url.split("://", 1)[1]
    except IndexError:
        after = url
    return after.count("//")

def has_nonstandard_port(port: Optional[int]) -> bool:
    """
    INPUT: port (int or None) - Port number.
    OUTPUT: True if port is not standard, else False.
    Check if the port is not a standard HTTP/HTTPS port.
    """
    if port is None:
        return False
    try:
        return int(port) not in STANDARD_PORTS
    except Exception:
        return False

def count_suspicious_chars(url: str) -> int:
    """
    INPUT: url (str) - The URL to check.
    OUTPUT: Number of suspicious characters (int).
    Count suspicious characters in the URL.
    """
    return sum(url.count(c) for c in SUSPICIOUS_CHARS)

def dot_count(url: str) -> int:
    """
    INPUT: url (str) - The URL to check.
    OUTPUT: Number of dots in the URL (int).
    Count the number of dots in the URL.
    """
    return url.count(".")

def domain_parts_count(host: str) -> int:
    """
    INPUT: host (str) - Hostname.
    OUTPUT: Number of domain parts (int).
    Count the number of parts in the domain (split by dot).
    """
    return len(host.split(".")) if host else 0

def has_hyphen_in_domain(host: str) -> bool:
    """
    INPUT: host (str) - Hostname.
    OUTPUT: True if domain contains hyphen, else False.
    Check if the domain contains a hyphen.
    """
    return "-" in (host or "")

def has_at_symbol(url: str) -> bool:
    """
    INPUT: url (str) - The URL to check.
    OUTPUT: True if '@' is present, else False.
    Check if the URL contains an '@' symbol.
    """
    return "@" in url

def contains_literal_https_outside_scheme(url: str) -> bool:
    """
    INPUT: url (str) - The URL to check.
    OUTPUT: True if 'https' appears outside scheme, else False.
    Check if 'https' appears in the URL outside the scheme.
    """
    if url.lower().startswith("https://"):
        body = url[8:]
    elif url.lower().startswith("http://"):
        body = url[7:]
    else:
        body = url
    return "https" in body.lower()

def is_shortener(host: str) -> bool:
    """
    INPUT: host (str) - Hostname.
    OUTPUT: True if host is a known shortener, else False.
    Check if the host is a known URL shortener.
    """
    if not host:
        return False
    ext = tldextract.extract(host)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return domain in SHORTENER_DOMAINS

def get_ssl_info(host: str, port: int = 443) -> Dict[str, Any]:
    """
    INPUT: host (str), port (int) - Hostname and port.
    OUTPUT: Dictionary with SSL certificate info.
    Get SSL certificate info for a host.
    """
    info: Dict[str, Any] = {
        "https_supported": False,
        "cert_valid": None,
        "cert_issuer": None,
        "cert_subject": None,
        "cert_not_before": None,
        "cert_not_after": None,
        "cert_days_until_expiry": None,
        "error": None
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                info["https_supported"] = True
                cert = ssock.getpeercert()
                # Extract subject and issuer fields
                try:
                    subj = cert.get("subject", [])
                    subj_dict = {}
                    for r in subj:
                        for k, v in r:
                            subj_dict.setdefault(k, v)
                    info["cert_subject"] = subj_dict
                except Exception:
                    info["cert_subject"] = None
                try:
                    issuer = cert.get("issuer", [])
                    issuer_dict = {}
                    for r in issuer:
                        for k, v in r:
                            issuer_dict.setdefault(k, v)
                    info["cert_issuer"] = issuer_dict
                except Exception:
                    info["cert_issuer"] = None
                nb = cert.get("notBefore")
                na = cert.get("notAfter")
                if nb:
                    info["cert_not_before"] = nb
                if na:
                    info["cert_not_after"] = na
                    try:
                        expires = dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        delta = expires - dt.datetime.utcnow()
                        info["cert_days_until_expiry"] = delta.days
                        info["cert_valid"] = delta.days > 0
                    except Exception:
                        info["cert_valid"] = None
    except Exception as e:
        info["error"] = str(e)
    return info

def whois_info(host: str) -> Dict[str, Any]:
    """
    INPUT: host (str) - Hostname.
    OUTPUT: Dictionary with WHOIS info.
    Get WHOIS info for a domain.
    """
    out = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "domain_age_days": None,
        "registration_length_days": None,
        "whois_error": None,
    }
    if not whois_module:
        out["whois_error"] = "python-whois not installed"
        return out
    try:
        w = whois_module.whois(host)
        def _first(d):
            if isinstance(d, list):
                return d[0]
            return d
        c = _first(w.creation_date) if hasattr(w, "creation_date") else None
        e = _first(w.expiration_date) if hasattr(w, "expiration_date") else None
        u = _first(w.updated_date) if hasattr(w, "updated_date") else None
        out["registrar"] = getattr(w, "registrar", None)
        out["creation_date"] = c.isoformat() if isinstance(c, dt.datetime) else (str(c) if c else None)
        out["expiration_date"] = e.isoformat() if isinstance(e, dt.datetime) else (str(e) if e else None)
        out["updated_date"] = u.isoformat() if isinstance(u, dt.datetime) else (str(u) if u else None)
        now = dt.datetime.utcnow()
        if isinstance(c, dt.datetime):
            out["domain_age_days"] = (now - c).days
        if isinstance(c, dt.datetime) and isinstance(e, dt.datetime):
            out["registration_length_days"] = (e - c).days
    except Exception as e:
        out["whois_error"] = str(e)
    return out

def dns_has_records(host: str) -> bool:
    """
    INPUT: host (str) - Hostname.
    OUTPUT: True if DNS records exist, else False.
    Check if DNS records exist for the host.
    """
    if dns is None:
        return False
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=5)       # 5 is timeout in seconds
        return len(list(answers)) > 0
    except Exception:
        return False

def parse_meta_redirect(soup: BeautifulSoup) -> Optional[str]:
    """
    INPUT: soup (BeautifulSoup) - Parsed HTML.
    OUTPUT: Redirect URL (str) if found, else None.
    Find meta refresh redirect URL in HTML.
    """
    for m in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}):
        content = m.get("content") or ""
        m2 = META_REFRESH_URL_RE.search(content)
        if m2:
            return m2.group(1).strip()
    return None

def scan_scripts_for_patterns(soup: BeautifulSoup, patterns: List[re.Pattern]) -> bool:
    """
    INPUT: soup (BeautifulSoup), patterns (list of regex patterns).
    OUTPUT: True if any pattern matches, else False.
    Scan HTML and scripts for suspicious JavaScript patterns.
    """
    for s in soup.find_all("script"):
        code = s.string or ""
        if not code:
            code = s.get_text() or ""
        for pat in patterns:
            if pat.search(code):
                return True
    html = str(soup)
    for pat in patterns:
        if pat.search(html):
            return True
    return False

def extract_logo_matches(soup: BeautifulSoup, base_domain: str) -> Dict[str, Any]:
    """
    INPUT: soup (BeautifulSoup), base_domain (str).
    OUTPUT: Dictionary with logo image stats.
    Find logo images and check if they are external.
    """
    logos = soup.select('img[alt*="logo" i], img[src*="logo" i]')
    total = len(logos)
    external = 0
    for img in logos:
        src = img.get("src") or ""
        src_abs = urljoin(f"https://{base_domain}", src)
        ext = is_external(src_abs, base_domain)
        if ext:
            external += 1
    return {
        "logo_img_count": total,
        "logo_external_count": external,
        "logo_external_ratio": (external / total) if total > 0 else None,
        "logo_domain_match": (total > 0 and external == 0)
    }

def extract_favicon_info(soup: Optional[BeautifulSoup], base_url: str, base_domain: str) -> Dict[str, Any]:
    """
    INPUT: soup (BeautifulSoup or None), base_url (str), base_domain (str).
    OUTPUT: Dictionary with favicon info.
    Find favicon and check if it is external.
    """
    info = {"favicon_href": None, "favicon_external": None}
    href = None
    if soup:
        link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if link:
            href = link.get("href")
    if not href:
        href = "/favicon.ico"
    abs_url = urljoin(base_url, href)
    info["favicon_href"] = abs_url
    ext = is_external(abs_url, base_domain)
    info["favicon_external"] = bool(ext)
    return info

def collect_links_resources(soup: BeautifulSoup, base_url: str, base_domain: str) -> Dict[str, Any]:
    """
    INPUT: soup (BeautifulSoup), base_url (str), base_domain (str).
    OUTPUT: Dictionary with resource counts and external ratios.
    Collect and count various resources (scripts, links, images, etc.) and check if they are external.
    """
    scripts = soup.find_all("script")
    links = soup.find_all("link", href=True)
    imgs = soup.find_all("img", src=True)
    iframes = soup.find_all("iframe")
    forms = soup.find_all("form")
    anchors = soup.find_all("a", href=True)
    metas = soup.find_all("meta")

    def _abs(u):
        return urljoin(base_url, u)

    def _is_ext(u):
        try:
            return is_external(_abs(u), base_domain)
        except Exception:
            return None

    script_srcs = [s.get("src") for s in scripts if s.get("src")]
    link_hrefs = [l.get("href") for l in links if l.get("href")]
    img_srcs = [i.get("src") for i in imgs if i.get("src")]

    script_ext = sum(1 for u in script_srcs if _is_ext(u))
    link_ext = sum(1 for u in link_hrefs if _is_ext(u))
    img_ext = sum(1 for u in img_srcs if _is_ext(u))

    meta_urls = []
    for m in metas:
        for attr in ("content", "property"):
            val = m.get(attr)
            if isinstance(val, str) and val.lower().startswith(("http://", "https://")):
                meta_urls.append(val)
    meta_ext = sum(1 for u in meta_urls if _is_ext(u))

    anchor_ext = 0
    for a in anchors:
        href = a.get("href") or ""
        if not href:
            continue
        uabs = urljoin(base_url, href)
        ext = is_external(uabs, base_domain)
        if ext:
            anchor_ext += 1

    form_external = 0
    for f in forms:
        action = f.get("action") or ""
        if action:
            uabs = urljoin(base_url, action)
            ext = is_external(uabs, base_domain)
            if ext:
                form_external += 1

    mailto_present = any(
        (a.get("href") or "").lower().startswith("mailto:")
        for a in anchors
    ) or any((f.get("action") or "").lower().startswith("mailto:") for f in forms)

    totals = {
        "scripts_total": len(scripts),
        "links_total": len(links),
        "imgs_total": len(imgs),
        "anchors_total": len(anchors),
        "forms_total": len(forms),
        "iframes_total": len(iframes),
    }

    return {
        **totals,
        "script_external_count": script_ext,
        "link_external_count": link_ext,
        "img_external_count": img_ext,
        "meta_external_count": meta_ext,
        "anchor_external_count": anchor_ext,
        "form_external_count": form_external,
        "script_external_ratio": (script_ext / len(script_srcs)) if script_srcs else None,
        "resource_external_ratio": ((script_ext + link_ext + img_ext) / (len(script_srcs) + len(link_hrefs) + len(img_srcs))) if (len(script_srcs) + len(link_hrefs) + len(img_srcs)) else None,
        "external_link_ratio": (anchor_ext / len(anchors)) if len(anchors) else None,
        "mailto_present": mailto_present
    }

def is_external(link: str, base_domain: str) -> Optional[bool]:
    """
    INPUT: link (str), base_domain (str).
    OUTPUT: True if link is external, False if internal, None if undetermined.
    Check if a link is external compared to the base domain.
    """
    try:
        p = urlparse(link)
        if not p.scheme and not p.netloc:
            return False
        host = p.hostname
        if not host:
            return None
        return base_domain != host
    except Exception:
        return None

# ---------------- Data structures ----------------

@dataclass
class URLFeatures:
    """
    INPUT: All extracted feature values for a URL.
    OUTPUT: Structured data for one URL's features.
    Data structure for storing extracted features for each URL.
    """
    url: str                                            # This code stores the URL being analyzed
    label: Optional[int]                                # THis code stores the label (1 for phishing, 0 for legitimate, None if unknown)
    host: Optional[str] = None                          # Hostname extracted from the URL
    scheme: Optional[str] = None                        # URL scheme (http, https, etc.)  
    port: Optional[int] = None
    url_length: Optional[int] = None
    is_shortened: Optional[bool] = None
    has_at_symbol: Optional[bool] = None
    double_slash_count_after_protocol: Optional[int] = None
    has_hyphen_in_domain: Optional[bool] = None
    subdomain_parts: Optional[int] = None
    contains_literal_https_outside_scheme: Optional[bool] = None
    dot_count: Optional[int] = None
    suspicious_char_count: Optional[int] = None
    ip_in_url: Optional[bool] = None
    nonstandard_port: Optional[bool] = None
    https_supported: Optional[bool] = None
    cert_valid: Optional[bool] = None
    cert_days_until_expiry: Optional[int] = None
    registrar: Optional[str] = None
    domain_age_days: Optional[int] = None
    registration_length_days: Optional[int] = None
    whois_error: Optional[str] = None
    dns_records_present: Optional[bool] = None
    favicon_external: Optional[bool] = None
    logo_img_count: Optional[int] = None
    logo_external_count: Optional[int] = None
    logo_external_ratio: Optional[float] = None
    logo_domain_match: Optional[bool] = None
    scripts_total: Optional[int] = None
    links_total: Optional[int] = None
    imgs_total: Optional[int] = None
    anchors_total: Optional[int] = None
    forms_total: Optional[int] = None
    iframes_total: Optional[int] = None
    script_external_count: Optional[int] = None
    link_external_count: Optional[int] = None
    img_external_count: Optional[int] = None
    meta_external_count: Optional[int] = None
    anchor_external_count: Optional[int] = None
    form_external_count: Optional[int] = None
    script_external_ratio: Optional[float] = None
    resource_external_ratio: Optional[float] = None
    external_link_ratio: Optional[float] = None
    mailto_present: Optional[bool] = None
    meta_refresh_redirect: Optional[str] = None
    js_statusbar_customization: Optional[bool] = None
    js_right_click_disabled: Optional[bool] = None
    js_popup_detected: Optional[bool] = None
    js_redirect_detected: Optional[bool] = None
    http_redirects_count: Optional[int] = None
    traffic_rank: Optional[int] = None
    pagerank_or_da: Optional[float] = None
    google_indexed: Optional[bool] = None
    backlink_count: Optional[int] = None
    blacklist: Optional[Dict[str, Any]] = None

# ---------------- Page retrieval & parsing ----------------

def get_page(url: str) -> Tuple[Optional[BeautifulSoup], Optional[requests.Response], Optional[str]]:
    """
    INPUT: url (str) - URL or local file path.
    OUTPUT: (soup, response, content_type)
        soup: BeautifulSoup object (parsed HTML) or None
        response: requests.Response object or None
        content_type: str or None
    Get the HTML page for a URL or local file.
    Returns BeautifulSoup object, response, and content type.
    """
    if url.startswith("file://") or os.path.exists(url):
        path = url[7:] if url.startswith("file://") else url
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read()
            soup = BeautifulSoup(html, "lxml")
            return soup, None, "text/html"
        except Exception:
            return None, None, None
    resp = safe_get(url)
    if not resp or not resp.text:
        return None, resp, None
    content_type = resp.headers.get("Content-Type", "")
    soup = BeautifulSoup(resp.text, "lxml")
    return soup, resp, content_type

# ---------------- Core extraction ----------------

def extract_features(url: str, label: Optional[int] = None) -> Dict[str, Any]:
    """
    INPUT: url (str), label (int or None)
    OUTPUT: Dictionary of extracted features for the URL.
    Extract all features for a given URL.
    """
    host, scheme, port = get_hostname(url)
    ip_in = is_ip_address(host)
    url_len = len(url)
    short = is_shortener(host)
    at_sym = has_at_symbol(url)
    dbl_slash_count = count_double_slash_after_protocol(url)
    hyphen = has_hyphen_in_domain(host)
    sub_parts = domain_parts_count(host)
    has_literal_https = contains_literal_https_outside_scheme(url)
    dots = dot_count(url)
    susp_cnt = count_suspicious_chars(url)
    nonstd_port = has_nonstandard_port(port)

    ssl_info = {"https_supported": False, "cert_valid": None, "cert_days_until_expiry": None}
    if scheme.lower() == "https" or (not scheme and port in (443, None)):
        try:
            ssl_info = get_ssl_info(host)
        except Exception:
            ssl_info = {"https_supported": False, "cert_valid": None, "cert_days_until_expiry": None}

    w = whois_info(host) if host else {"whois_error": "no-host"}
    dns_ok = dns_has_records(host) if host else False

    soup, resp, ctype = get_page(url)
    base_url = resp.url if resp is not None and hasattr(resp, "url") else f"{scheme}://{host}" if host else url
    favicon_external = None
    logo_stats = {"logo_img_count": None, "logo_external_count": None, "logo_external_ratio": None, "logo_domain_match": None}
    meta_refresh_url = None
    js_statusbar = None
    js_right_click = None
    js_popup = None
    js_redirect = None
    http_redirects_count = None
    res = {k: None for k in ("scripts_total","links_total","imgs_total","anchors_total","forms_total","iframes_total",
                             "script_external_count","link_external_count","img_external_count","meta_external_count",
                             "anchor_external_count","form_external_count","script_external_ratio","resource_external_ratio",
                             "external_link_ratio","mailto_present")}
    if resp is not None:
        try:
            http_redirects_count = len(resp.history)
        except Exception:
            http_redirects_count = None
    if soup is not None:
        base_domain = host
        fav = extract_favicon_info(soup, base_url, base_domain)
        favicon_external = fav["favicon_external"]
        logo_stats = extract_logo_matches(soup, base_domain)
        meta_refresh_url = parse_meta_redirect(soup)
        js_statusbar = scan_scripts_for_patterns(soup, JS_STATUSBAR_PATTERNS)
        js_right_click = scan_scripts_for_patterns(soup, JS_RIGHT_CLICK_PATTERNS)
        js_popup = scan_scripts_for_patterns(soup, JS_POPUP_PATTERNS)
        js_redirect = scan_scripts_for_patterns(soup, JS_REDIRECT_PATTERNS)
        res = collect_links_resources(soup, base_url, base_domain)

    # Assemble all features into a dictionary
    row = {
        "url": url,
        "label": label,
        "host": host,
        "scheme": scheme,
        "port": port,
        "url_length": url_len,
        "is_shortened": short,
        "has_at_symbol": at_sym,
        "double_slash_count_after_protocol": dbl_slash_count,
        "has_hyphen_in_domain": hyphen,
        "subdomain_parts": sub_parts,
        "contains_literal_https_outside_scheme": has_literal_https,
        "dot_count": dots,
        "suspicious_char_count": susp_cnt,
        "ip_in_url": ip_in,
        "nonstandard_port": nonstd_port,
        "https_supported": bool(ssl_info.get("https_supported")),
        "cert_valid": ssl_info.get("cert_valid"),
        "cert_days_until_expiry": ssl_info.get("cert_days_until_expiry"),
        "registrar": w.get("registrar"),
        "domain_age_days": w.get("domain_age_days"),
        "registration_length_days": w.get("registration_length_days"),
        "whois_error": w.get("whois_error"),
        "dns_records_present": dns_ok,
        "favicon_external": favicon_external,
        "logo_img_count": logo_stats.get("logo_img_count"),
        "logo_external_count": logo_stats.get("logo_external_count"),
        "logo_external_ratio": logo_stats.get("logo_external_ratio"),
        "logo_domain_match": logo_stats.get("logo_domain_match"),
        "scripts_total": res.get("scripts_total"),
        "links_total": res.get("links_total"),
        "imgs_total": res.get("imgs_total"),
        "anchors_total": res.get("anchors_total"),
        "forms_total": res.get("forms_total"),
        "iframes_total": res.get("iframes_total"),
        "script_external_count": res.get("script_external_count"),
        "link_external_count": res.get("link_external_count"),
        "img_external_count": res.get("img_external_count"),
        "meta_external_count": res.get("meta_external_count"),
        "anchor_external_count": res.get("anchor_external_count"),
        "form_external_count": res.get("form_external_count"),
        "script_external_ratio": res.get("script_external_ratio"),
        "resource_external_ratio": res.get("resource_external_ratio"),
        "external_link_ratio": res.get("external_link_ratio"),
        "mailto_present": res.get("mailto_present"),
        "meta_refresh_redirect": meta_refresh_url,
        "js_statusbar_customization": js_statusbar,
        "js_right_click_disabled": js_right_click,
        "js_popup_detected": js_popup,
        "js_redirect_detected": js_redirect,
        "http_redirects_count": http_redirects_count,
    }
    return row

# ---------------- Data Cleaning Functions ----------------

def normalize_numeric(rows, keys):
    """
    INPUT: rows (list of dicts), keys (list of str)
    OUTPUT: rows with normalized numeric columns (values in [0,1])
    Normalize numeric columns to [0,1] range and fill missing with mean.
    """
    numeric_keys = []
    for k in keys:
        vals = [r.get(k) for r in rows]
        if all(isinstance(v, (int, float, type(None))) for v in vals):
            numeric_keys.append(k)
    stats = {}
    for k in numeric_keys:
        vals = [r.get(k) for r in rows if r.get(k) is not None]
        if vals:
            stats[k] = (min(vals), max(vals), float(np.mean(vals)))
        else:
            stats[k] = (0, 1, 0)
    for r in rows:
        for k in numeric_keys:
            v = r.get(k)
            mn, mx, mean = stats[k]
            if v is None:
                r[k] = mean
            else:
                if mx > mn:
                    r[k] = (v - mn) / (mx - mn)
                else:
                    r[k] = 0.0
    return rows

def convert_bools(rows, keys):
    """
    INPUT: rows (list of dicts), keys (list of str)
    OUTPUT: rows with boolean columns converted to int (True->1, False->0)
    Convert boolean columns to integers (True->1, False->0).
    Fill missing booleans with 0.
    """
    for r in rows:
        for k in keys:
            v = r.get(k)
            if isinstance(v, bool):
                r[k] = int(v)
            elif v is None:
                if any(isinstance(row.get(k), bool) for row in rows):
                    r[k] = 0
    return rows

def fill_missing(rows, keys):
    """
    INPUT: rows (list of dicts), keys (list of str)
    OUTPUT: rows with missing values filled with 0
    Fill any remaining missing values (None) with 0.
    """
    for r in rows:
        for k in keys:
            if r.get(k) is None:
                r[k] = 0
    return rows

# ---------------- Worker thread for extraction ----------------

class ExtractWorker(QThread):
    """
    INPUT: inputs (list of (url, label) tuples)
    OUTPUT: Emits signals with progress, log, and finished results.
    Worker thread to extract features from URLs in the background.
    """
    progress = Signal(int, int)  # current, total
    log = Signal(str)
    finished_signal = Signal(list)  # list of dict rows

    def __init__(self, inputs: List[Tuple[str, Optional[int]]]):
        super().__init__()
        self.inputs = inputs

    def run(self):
        results = []
        total = len(self.inputs)
        for idx, (url, label) in enumerate(self.inputs, start=1):
            try:
                self.log.emit(f"[{idx}/{total}] Extracting: {url}")
                row = extract_features(url, label)
                results.append(row)
            except Exception as e:
                self.log.emit(f"[{idx}/{total}] ERROR for {url}: {e}")
                results.append({"url": url, "label": label, "error": str(e)})
            self.progress.emit(idx, total)
        self.finished_signal.emit(results)

# ---------------- GUI ----------------

class MainWindow(QWidget):
    """
    INPUT: User interacts via GUI.
    OUTPUT: Extracted features written to CSV/JSON, progress/log shown.
    Main window for the GUI application.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Feature Extractor (for ML)")
        self.resize(800, 600)

        v = QVBoxLayout(self)

        # Input CSV and manual additions
        row1 = QHBoxLayout()
        self.input_csv_line = QLineEdit()
        row1.addWidget(QLabel("Input CSV (url,label):"))
        row1.addWidget(self.input_csv_line)
        btn_browse_csv = QPushButton("Browse CSV")
        btn_browse_csv.clicked.connect(self.browse_csv)
        row1.addWidget(btn_browse_csv)
        v.addLayout(row1)

        row2 = QHBoxLayout()
        self.add_url_line = QLineEdit()
        row2.addWidget(QLabel("Add URL / file path / raw GitHub URL:"))
        row2.addWidget(self.add_url_line)
        btn_add = QPushButton("Add")
        btn_add.clicked.connect(self.add_manual)
        row2.addWidget(btn_add)
        v.addLayout(row2)

        # List (text area) of inputs
        v.addWidget(QLabel("Inputs (url and label, one per line, tab-separated):"))
        self.inputs_txt = QTextEdit()
        self.inputs_txt.setPlaceholderText("https://example.com\t0\nfile:///path/to/page.html\t1\nhttps://raw.githubusercontent.com/..../file.js\t0")
        v.addWidget(self.inputs_txt, 1)

        # Output selection and options
        row3 = QHBoxLayout()
        self.out_csv_line = QLineEdit()
        row3.addWidget(QLabel("Output CSV:"))
        row3.addWidget(self.out_csv_line)
        btn_browse_out = QPushButton("Browse")
        btn_browse_out.clicked.connect(self.browse_out_csv)
        row3.addWidget(btn_browse_out)
        v.addLayout(row3)

        row4 = QHBoxLayout()
        self.out_json_line = QLineEdit()
        row4.addWidget(QLabel("Output JSON:"))
        row4.addWidget(self.out_json_line)
        btn_browse_out2 = QPushButton("Browse")
        btn_browse_out2.clicked.connect(self.browse_out_json)
        row4.addWidget(btn_browse_out2)
        v.addLayout(row4)

        # Checkboxes for optional heavy features
        self.checkbox_whois = QCheckBox("Enable WHOIS lookups (python-whois)")
        self.checkbox_whois.setChecked(True if whois_module else False)
        self.checkbox_dns = QCheckBox("Enable DNS checks (dnspython)")
        self.checkbox_dns.setChecked(True if dns else False)
        hcb = QHBoxLayout()
        hcb.addWidget(self.checkbox_whois)
        hcb.addWidget(self.checkbox_dns)
        v.addLayout(hcb)

        # Controls
        hctrl = QHBoxLayout()
        self.btn_run = QPushButton("Run Extraction")
        self.btn_run.clicked.connect(self.run_extraction)
        hctrl.addWidget(self.btn_run)
        self.progress = QProgressBar()
        hctrl.addWidget(self.progress)

        # --- Added Stop and Clear buttons ---
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.stop_extraction)
        self.btn_stop.setEnabled(False)
        hctrl.addWidget(self.btn_stop)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.clear_all)
        hctrl.addWidget(self.btn_clear)
        # --- End added buttons ---

        v.addLayout(hctrl)

        # Log area
        v.addWidget(QLabel("Log:"))
        self.log_txt = QTextEdit()
        self.log_txt.setReadOnly(True)
        v.addWidget(self.log_txt, 1)

        # Internal state
        self.worker = None

    def browse_csv(self):
        """
        Browse and load input CSV file.
        """
        f, _ = QFileDialog.getOpenFileName(self, "Select input CSV", "", "CSV files (*.csv);;All files (*)")
        if f:
            self.input_csv_line.setText(f)
            try:
                with open(f, newline="", encoding="utf-8") as fh:
                    r = csv.DictReader(fh)
                    lines = []
                    for row in r:
                        u = row.get("url") or row.get("URL") or row.get("Url")
                        lab = None
                        for k in ("label", "Label", "phishing", "PHISHING"):
                            if k in row and row[k] != "":
                                try:
                                    lab = int(row[k])
                                except Exception:
                                    lab = None
                                break
                        if u:
                            lines.append(f"{u}\t{lab if lab is not None else ''}")
                    self.inputs_txt.setPlainText("\n".join(lines))
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to read CSV: {e}")

    def add_manual(self):
        """
        Add a manual URL and label to the input list.
        """
        t = self.add_url_line.text().strip()
        if not t:
            return
        if "\t" not in t:
            self.inputs_txt.append(f"{t}\t")
        else:
            self.inputs_txt.append(t)
        self.add_url_line.clear()

    def browse_out_csv(self):
        """
        Browse and select output CSV file.
        """
        f, _ = QFileDialog.getSaveFileName(self, "Select output CSV", "features.csv", "CSV files (*.csv);;All files (*)")
        if f:
            self.out_csv_line.setText(f)

    def browse_out_json(self):
        """
        Browse and select output JSON file.
        """
        f, _ = QFileDialog.getSaveFileName(self, "Select output JSON", "features.json", "JSON files (*.json);;All files (*)")
        if f:
            self.out_json_line.setText(f)

    def log(self, msg: str):
        """
        Log a message to the log area.
        """
        self.log_txt.append(msg)

    def run_extraction(self):
        """
        Start feature extraction for all input URLs.
        """
        text = self.inputs_txt.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "No inputs", "Please provide URLs or local files (one per line).")
            return
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        inputs = []
        for ln in lines:
            parts = ln.split("\t")
            url = parts[0].strip()
            label = None
            if len(parts) > 1 and parts[1].strip() != "":
                try:
                    label = int(parts[1].strip())
                except Exception:
                    label = None
            if os.path.exists(url) and not url.startswith("file://"):
                url = f"file://{os.path.abspath(url)}"
            inputs.append((url, label))

        out_csv = self.out_csv_line.text().strip()
        out_json = self.out_json_line.text().strip()
        if not out_csv and not out_json:
            QMessageBox.warning(self, "No outputs", "Please select at least one output (CSV or JSON).")
            return

        if self.checkbox_whois.isChecked() and not whois_module:
            QMessageBox.information(self, "WHOIS disabled", "python-whois not installed; WHOIS will be skipped.")
        if self.checkbox_dns.isChecked() and dns is None:
            QMessageBox.information(self, "DNS disabled", "dnspython not installed; DNS checks will be skipped.")

        self.progress.setValue(0)
        self.progress.setMaximum(len(inputs))
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)  # Enable Stop button
        self.log_txt.clear()
        self.worker = ExtractWorker(inputs)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self._on_log)
        self.worker.finished_signal.connect(lambda rows: self._on_finished(rows, out_csv, out_json))
        self.worker.start()

    def stop_extraction(self):
        """
        Stop the extraction process.
        """
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
            self.log("Extraction stopped by user.")
            self.btn_run.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.worker = None

    def clear_all(self):
        """
        Clear all input and output fields and logs.
        """
        self.input_csv_line.clear()
        self.add_url_line.clear()
        self.inputs_txt.clear()
        self.out_csv_line.clear()
        self.out_json_line.clear()
        self.log_txt.clear()
        self.progress.setValue(0)

    def _on_progress(self, current: int, total: int):
        """
        Update progress bar.
        """
        try:
            self.progress.setValue(current)
        except Exception:
            pass

    def _on_log(self, msg: str):
        """
        Log message from worker.
        """
        self.log(msg)

    def _on_finished(self, rows: List[Dict[str, Any]], out_csv: str, out_json: str):
        """
        Handle finished extraction: clean data and write outputs.
        """
        self.log("Extraction finished. Writing outputs...")
        keys = set()
        for r in rows:
            keys.update(r.keys())
        keys = sorted(keys)

        rows = convert_bools(rows, keys)
        rows = normalize_numeric(rows, keys)
        rows = fill_missing(rows, keys)

        if out_csv:
            try:
                with open(out_csv, "w", newline="", encoding="utf-8") as fh:
                    w = csv.DictWriter(fh, fieldnames=keys)
                    w.writeheader()
                    for r in rows:
                        row_out = {}
                        for k in keys:
                            v = r.get(k)
                            if isinstance(v, (dt.datetime,)):
                                row_out[k] = v.isoformat()
                            elif isinstance(v, dict) or isinstance(v, list):
                                row_out[k] = json.dumps(v, ensure_ascii=False)
                            else:
                                row_out[k] = v
                        w.writerow(row_out)
                self.log(f"Wrote CSV: {out_csv}")
            except Exception as e:
                self.log(f"Failed to write CSV: {e}")
                QMessageBox.warning(self, "Write error", f"Failed to write CSV: {e}")

        if out_json:
            try:
                with open(out_json, "w", encoding="utf-8") as fh:
                    json.dump(rows, fh, ensure_ascii=False, indent=2)
                self.log(f"Wrote JSON: {out_json}")
            except Exception as e:
                self.log(f"Failed to write JSON: {e}")
                QMessageBox.warning(self, "Write error", f"Failed to write JSON: {e}")

        QMessageBox.information(self, "Done", "Feature extraction complete.")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)  # Disable Stop button
        self.worker = None

# ----------------- Main ------------------

def main():
    """
    INPUT: None (called when script runs).
    OUTPUT: Starts the GUI application.
    Start the GUI application.
    """
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()