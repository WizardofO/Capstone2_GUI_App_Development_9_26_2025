# phishing_features.py
"""
Complete feature extractor for 35 phishing-related features.

Optional environment variables (set as appropriate):
  TRANCO_CSV_PATH  - local Tranco CSV (one domain per line or "rank,domain")
  LOGO_HASH_FILE   - JSON file (dict brand->md5 or list of md5) for known logos
  GOOGLE_API_KEY, GOOGLE_CX
  BING_API_KEY
  VT_API_KEY
  MOZ_ACCESS_ID, MOZ_SECRET_KEY (optional)
  GSB_API_KEY (Google Safe Browsing)
"""

import os
import re
import json
import time
import base64
import hmac
import hashlib
import socket
import whois
import requests
import tldextract
import dns.resolver
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

REQUESTS_TIMEOUT = 10
TRANC0_LOCAL = os.getenv("TRANCO_CSV_PATH", "tranco.csv")
LOGO_HASH_FILE = os.getenv("LOGO_HASH_FILE", "logo_hashes.json")

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CX = os.getenv("GOOGLE_CX")
BING_API_KEY = os.getenv("BING_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
MOZ_ACCESS_ID = os.getenv("MOZ_ACCESS_ID")
MOZ_SECRET_KEY = os.getenv("MOZ_SECRET_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")


def safe_requests_get(url, **kwargs):
    try:
        return requests.get(url, timeout=REQUESTS_TIMEOUT, **kwargs)
    except Exception:
        return None


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def normalize_domain(hostname: str) -> str:
    if not hostname:
        return ""
    return hostname.lower().strip().lstrip("www.")


class PhishingFeatureExtractor:
    def __init__(self, url: str = None, html_content: str = None, file_mode: bool = False):
        self.url = url
        self.file_mode = file_mode
        self.html = html_content
        self.parsed = urlparse(url) if url else None
        self.scheme = self.parsed.scheme if self.parsed else "http"
        self.domain = normalize_domain(self.parsed.hostname) if self.parsed else ""
        self.ext = tldextract.extract(url) if url else None
        self.soup = None
        if html_content is not None:
            self.soup = BeautifulSoup(html_content, "html.parser")
        elif url and not file_mode:
            self.html = self.fetch_html()
            self.soup = BeautifulSoup(self.html, "html.parser")

        self.known_logo_hashes = set()
        try:
            if os.path.exists(LOGO_HASH_FILE):
                with open(LOGO_HASH_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.known_logo_hashes = set(data.values())
                    elif isinstance(data, list):
                        self.known_logo_hashes = set(data)
        except Exception:
            self.known_logo_hashes = set()

    def fetch_html(self) -> str:
        try:
            headers = {"User-Agent": "PhishFeatureBot/1.0"}
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
            return r.text or ""
        except Exception:
            return ""

    # ---------- Features 1 - 14 ----------
    def ip_in_url(self) -> int:
        if not self.url:
            return 0
        return 1 if re.match(r"^https?://\d{1,3}(?:\.\d{1,3}){3}", self.url) else 0

    def url_length(self) -> int:
        return len(self.url) if self.url else 0

    def url_shortening(self) -> int:
        if not self.domain:
            return 0
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rb.gy"}
        return 1 if any(s in self.domain for s in shorteners) else 0

    def presence_at(self) -> int:
        return (self.url.count("@") if self.url else 0)

    def redirection_symbol(self) -> int:
        if not self.url:
            return 0
        total = self.url.count("//")
        return max(0, total - 1)

    def hyphen_in_domain(self) -> int:
        return self.domain.count("-") if self.domain else 0

    def too_many_subdomains(self) -> int:
        sub = self.ext.subdomain if self.ext else ""
        if not sub:
            return 0
        return sub.count(".") + 1

    def https_in_string(self) -> int:
        if not self.url:
            return 0
        path_and_query = (self.parsed.path or "") + (self.parsed.query or "")
        return path_and_query.lower().count("https") + (self.html.lower().count("https") if self.html else 0)

    def ssl_tls_validity(self) -> int:
        if not self.url:
            return 0
        if self.scheme != "https":
            return 0
        try:
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, verify=True)
            return 2 if r.status_code < 400 else 1
        except requests.exceptions.SSLError:
            return 1
        except Exception:
            return 0

    def domain_registration_length(self) -> int:
        if not self.domain:
            return 0
        try:
            w = whois.whois(self.domain)
            exp = w.expiration_date
            cre = w.creation_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(cre, list): cre = cre[0]
            if not exp or not cre:
                return 0
            if isinstance(exp, str): exp = datetime.fromisoformat(exp)
            if isinstance(cre, str): cre = datetime.fromisoformat(cre)
            return max(0, (exp - cre).days)
        except Exception:
            return 0

    def non_standard_ports(self) -> int:
        if not self.parsed:
            return 0
        port = self.parsed.port
        if port is None:
            return 0
        return 1 if port not in (80, 443) else 0

    def external_favicon(self) -> int:
        try:
            if not self.soup:
                return 0
            icon = None
            for tag in self.soup.find_all("link", rel=True):
                rels = [r.lower() for r in tag.get("rel", [])]
                if any("icon" in r for r in rels):
                    icon = tag.get("href")
                    break
            if not icon:
                return 0
            p = urlparse(icon)
            if not p.hostname:
                return 0
            return 1 if normalize_domain(p.hostname) != self.domain else 0
        except Exception:
            return 0

    def count_dots(self) -> int:
        return self.url.count(".") if self.url else 0

    def suspicious_chars(self) -> int:
        if not self.url:
            return 0
        return sum(self.url.count(c) for c in ["?", "%", "&", "=", "+"])

    # ---------- Feature 15: Known logo ----------
    def known_logo(self) -> int:
        if not self.soup or not self.known_logo_hashes:
            return 0
        imgs = []
        for img in self.soup.find_all("img"):
            src = img.get("src") or ""
            alt = (img.get("alt") or "").lower()
            if "logo" in src.lower() or "logo" in alt:
                imgs.append(src)
        for src in imgs:
            try:
                if not src.startswith("http"):
                    base = f"{self.scheme}://{self.domain}" if self.domain else ""
                    src = urljoin(base, src)
                r = safe_requests_get(src)
                if r and r.status_code == 200:
                    h = md5_bytes(r.content)
                    if h in self.known_logo_hashes:
                        return 1
            except Exception:
                continue
        return 0

    # ---------- Features 16 - 21 ----------
    def use_script(self) -> int:
        return len(self.soup.find_all("script")) if self.soup else 0

    def count_third_party_domains(self) -> int:
        if not self.soup:
            return 0
        domains = set()
        for tag in self.soup.find_all(["script", "img", "link", "iframe", "video", "audio", "embed", "source"]):
            src = tag.get("src") or tag.get("href")
            if not src:
                continue
            p = urlparse(src)
            host = normalize_domain(p.hostname) if p.hostname else ""
            if host and host != self.domain:
                domains.add(host)
        return len(domains)

    def use_meta(self) -> int:
        return len(self.soup.find_all("meta")) if self.soup else 0

    def script_external_ratio(self) -> int:
        if not self.soup:
            return 0
        scripts = self.soup.find_all("script")
        if not scripts:
            return 0
        ext = sum(1 for s in scripts if s.get("src"))
        return int((ext / len(scripts)) * 100)

    def use_form(self) -> int:
        return len(self.soup.find_all("form")) if self.soup else 0

    def mailto(self) -> int:
        if not self.html:
            return 0
        return self.html.lower().count("mailto:")

    # ---------- Features 22 - 27 ----------
    def website_forwarding(self) -> int:
        if not self.soup:
            return 0
        if self.soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            return 1
        txt = self.html.lower() if self.html else ""
        if "location.replace(" in txt or "window.location" in txt:
            return 1
        return 0

    def status_bar(self) -> int:
        txt = (self.html or "").lower()
        return int(bool(re.search(r"window\.status|history\.replaceState|pushState\(|onbeforeunload", txt)))

    def right_click_disabled(self) -> int:
        txt = (self.html or "").lower()
        if 'oncontextmenu="return false"' in txt or re.search(r"addEventListener\(['\"]contextmenu['\"],", txt):
            return 1
        return 0

    def popups(self) -> int:
        txt = (self.html or "").lower()
        return len(re.findall(r"window\.open\(", txt))

    def iframes(self) -> int:
        return len(self.soup.find_all("iframe")) if self.soup else 0

    def sensitive_forms(self) -> int:
        sensitive_keywords = ["password", "pass", "cardnumber", "creditcard", "card", "cvv", "cvc", "ssn", "socialsecurity"]
        txt = (self.html or "").lower()
        return sum(txt.count(k) for k in sensitive_keywords)

    # ---------- Features 28 - 29 ----------
    def domain_age(self) -> int:
        if not self.domain:
            return 0
        try:
            w = whois.whois(self.domain)
            cre = w.creation_date
            if isinstance(cre, list):
                cre = cre[0] if cre else None
            if not cre:
                return 0
            if isinstance(cre, str):
                try:
                    cre = datetime.fromisoformat(cre)
                except Exception:
                    try:
                        cre = datetime.strptime(cre, "%Y-%m-%d")
                    except Exception:
                        return 0
            return max(0, (datetime.utcnow() - cre).days)
        except Exception:
            return 0

    def dns_record(self) -> int:
        if not self.domain:
            return 0
        total = 0
        try:
            for qtype in ("A", "AAAA", "MX", "NS"):
                try:
                    answers = dns.resolver.resolve(self.domain, qtype, lifetime=5)
                    total += len(answers)
                except Exception:
                    continue
        except Exception:
            pass
        return total

    # ---------- Feature 30: traffic rank ----------
    def traffic_rank(self) -> int:
        try:
            if os.path.exists(TRANC0_LOCAL):
                with open(TRANC0_LOCAL, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if not line:
                            continue
                        if "," in line:
                            parts = [p.strip() for p in line.split(",")]
                            dom = normalize_domain(parts[-1])
                            if dom == self.domain:
                                return i + 1
                        else:
                            if normalize_domain(line) == self.domain:
                                return i + 1
            url = "https://tranco-list.eu/top-1m.csv"
            r = safe_requests_get(url)
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.split(",")
                    if len(parts) >= 2 and normalize_domain(parts[1]) == self.domain:
                        try:
                            return int(parts[0])
                        except Exception:
                            return 0
        except Exception:
            pass
        return 0

    # ---------- Feature 31: page ranking (Moz optional) ----------
    def page_ranking(self) -> int:
        # placeholder for Moz integration; fallback to backlinks
        return self.backlinks()

    # ---------- Feature 32: Google index ----------
    def google_index(self) -> int:
        if not GOOGLE_API_KEY or not GOOGLE_CX or not self.domain:
            return 0
        try:
            params = {"key": GOOGLE_API_KEY, "cx": GOOGLE_CX, "q": f"site:{self.domain}", "num": 1}
            r = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return 0
            data = r.json()
            total = data.get("searchInformation", {}).get("totalResults")
            if total is None:
                return 0
            return int(total)
        except Exception:
            return 0

    # ---------- Feature 33: backlinks via Bing ----------
    def backlinks(self) -> int:
        if not BING_API_KEY or not self.domain:
            return 0
        try:
            headers = {"Ocp-Apim-Subscription-Key": BING_API_KEY}
            params = {"q": f"link:{self.domain}", "count": 50}
            r = requests.get("https://api.bing.microsoft.com/v7.0/search", headers=headers, params=params, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return 0
            data = r.json()
            results = data.get("webPages", {}).get("value", [])
            return len(results)
        except Exception:
            return 0

    # ---------- Feature 34: blacklist ----------
    def blacklist(self) -> int:
        total_flags = 0
        if VT_API_KEY and self.domain:
            try:
                headers = {"x-apikey": VT_API_KEY}
                r = requests.get(f"https://www.virustotal.com/api/v3/domains/{self.domain}", headers=headers, timeout=REQUESTS_TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    total_flags += int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
            except Exception:
                pass
        if GSB_API_KEY and self.url:
            try:
                gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
                body = {
                    "client": {"clientId": "phishbot", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": self.url}]
                    }
                }
                r = requests.post(gsb_url, json=body, timeout=REQUESTS_TIMEOUT)
                if r.status_code == 200 and r.text.strip():
                    data = r.json()
                    if data and data.get("matches"):
                        total_flags += len(data.get("matches"))
            except Exception:
                pass
        return total_flags

    # ---------- Feature 35: WHOIS tokens ----------
    def whois_suspicious_tokens(self) -> int:
        if not self.domain:
            return 0
        try:
            w = whois.whois(self.domain)
            raw = json.dumps(w.__dict__, default=str).lower()
            tokens = ["privacy", "whoisguard", "domainsbyproxy", "redacted", "protected", "anonymous",
                      "clienthold", "clienttransferprohibited", "pendingdelete", "gmail.com", "yahoo.com",
                      "hotmail.com", "po box", "p.o. box", "xn--", "domainsbyproxy.com", "privacyprotect.org"]
            count = 0
            for t in tokens:
                if t in raw:
                    count += 1
            return count
        except Exception:
            return 0

    # ---------- Aggregate all ----------
    def extract_all(self) -> dict:
        result = {}
        result["ip_in_url"] = int(self.ip_in_url())
        result["url_length"] = int(self.url_length())
        result["url_shortening"] = int(self.url_shortening())
        result["presence_at"] = int(self.presence_at())
        result["redirection_symbol"] = int(self.redirection_symbol())
        result["hyphen_in_domain"] = int(self.hyphen_in_domain())
        result["too_many_subdomains"] = int(self.too_many_subdomains())
        result["https_in_string"] = int(self.https_in_string())
        result["ssl_tls_validity"] = int(self.ssl_tls_validity())
        result["domain_registration_length"] = int(self.domain_registration_length())
        result["non_standard_ports"] = int(self.non_standard_ports())
        result["external_favicon"] = int(self.external_favicon())
        result["count_dots"] = int(self.count_dots())
        result["suspicious_chars"] = int(self.suspicious_chars())

        result["known_logo"] = int(self.known_logo())
        result["use_script"] = int(self.use_script())
        result["count_third_party_domains"] = int(self.count_third_party_domains())
        result["use_meta"] = int(self.use_meta())
        result["script_external_ratio"] = int(self.script_external_ratio())
        result["use_form"] = int(self.use_form())
        result["mailto"] = int(self.mailto())

        result["website_forwarding"] = int(self.website_forwarding())
        result["status_bar_customization"] = int(self.status_bar())
        result["right_click_disabled"] = int(self.right_click_disabled())
        result["popups"] = int(self.popups())
        result["iframes"] = int(self.iframes())
        result["sensitive_forms"] = int(self.sensitive_forms())

        result["domain_age"] = int(self.domain_age())
        result["dns_record_count"] = int(self.dns_record())

        result["website_traffic_rank"] = int(self.traffic_rank())
        result["page_ranking"] = int(self.page_ranking())
        result["google_index"] = int(self.google_index())
        result["backlinks"] = int(self.backlinks())
        result["blacklist"] = int(self.blacklist())
        result["whois_suspicious_tokens"] = int(self.whois_suspicious_tokens())

        return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phishing feature extractor (URL or local file)")
    parser.add_argument("target", help="URL (http(s)://...) or path to local file (.html, .js, .css, .php)")
    args = parser.parse_args()

    target = args.target
    is_url = bool(re.match(r"^https?://", target))

    if is_url:
        extractor = PhishingFeatureExtractor(url=target)
    else:
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            content = ""
        extractor = PhishingFeatureExtractor(url=None, html_content=content, file_mode=True)

    features = extractor.extract_all()
    print(json.dumps(features, indent=2))
