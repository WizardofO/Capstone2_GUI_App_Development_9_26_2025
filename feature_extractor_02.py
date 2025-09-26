"""
phishing_features.py

Complete feature extractor for 35 phishing-related features.
Dependencies:
  pip install requests beautifulsoup4 tldextract python-whois dnspython

Optional (for better accuracy):
  - Provide GOOGLE_API_KEY + GOOGLE_CX for Google Custom Search
  - Provide BING_API_KEY for backlink search (Bing Web Search)
  - Provide VT_API_KEY for VirusTotal domain lookup
  - Provide a local 'tranco.csv' (one domain per line) or set TRanco_URL to download
  - Provide a 'logo_hashes.json' mapping brand->md5hash for logo matching

Outputs: A dict of 35 integer features.
"""

import os
import re
import socket
import hashlib
import json
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
import tldextract
import whois
import dns.resolver
from bs4 import BeautifulSoup

# ---------------------------
# Configuration / Helpers
# ---------------------------

TRANC0_LOCAL = "tranco.csv"  # optional local copy of tranco top domains (one domain per line)
LOGO_HASH_FILE = "logo_hashes.json"  # optional JSON of known brand logo md5 hashes: {"paypal":"md5...", ...}

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CX = os.getenv("GOOGLE_CX")
BING_API_KEY = os.getenv("BING_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

REQUESTS_TIMEOUT = 8


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


# ---------------------------
# Main extractor class
# ---------------------------

class PhishingFeatureExtractor:
    def __init__(self, url: str, html_content: str = None):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        self.scheme = self.parsed.scheme or "http"
        self.domain = normalize_domain(self.parsed.hostname)
        self.ext = tldextract.extract(self.url)
        self.html = html_content if html_content is not None else self.fetch_html()
        self.soup = BeautifulSoup(self.html, "html.parser") if self.html else BeautifulSoup("", "html.parser")

    # ---------- Basic URL / HTML helpers ----------
    def fetch_html(self) -> str:
        try:
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers={"User-Agent": "PhishFeatureBot/1.0"})
            return r.text or ""
        except Exception:
            return ""

    def _whois(self):
        try:
            return whois.whois(self.domain)
        except Exception:
            return None

    # -------------------------
    # Features 1 - 14 (straightforward)
    # -------------------------
    def ip_in_url(self) -> int:
        return 1 if re.match(r"^https?://\d{1,3}(?:\.\d{1,3}){3}[:/]?", self.url) else 0

    def url_length(self) -> int:
        return len(self.url)

    def url_shortening(self) -> int:
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rb.gy"}
        return 1 if any(s in self.domain for s in shorteners) else 0

    def presence_at(self) -> int:
        return self.url.count("@")

    def redirection_symbol(self) -> int:
        # Count '//' occurrences beyond the initial protocol e.g., "http://"
        total = self.url.count("//")
        return max(0, total - 1)

    def hyphen_in_domain(self) -> int:
        return self.domain.count("-") if self.domain else 0

    def too_many_subdomains(self) -> int:
        # number of subdomain labels (exclude registered domain + suffix)
        sub = self.ext.subdomain or ""
        if not sub:
            return 0
        return sub.count(".") + 1

    def https_in_string(self) -> int:
        # occurrences of literal 'https' in path/params or page content (excluding protocol)
        path_and_query = (self.parsed.path or "") + (self.parsed.query or "")
        count_in_url = path_and_query.lower().count("https")
        count_in_html = self.html.lower().count("https") if self.html else 0
        return count_in_url + count_in_html

    def ssl_tls_validity(self) -> int:
        # 2 = valid HTTPS cert (checked via requests), 1 = HTTPS without cert verification success, 0 = no HTTPS
        if self.scheme != "https":
            return 0
        try:
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, verify=True)
            # if verify succeeds, treat as valid
            return 2 if r.status_code < 400 else 1
        except requests.exceptions.SSLError:
            return 1
        except Exception:
            return 0

    def domain_registration_length(self) -> int:
        w = self._whois()
        if not w:
            return 0
        try:
            exp = w.expiration_date
            cre = w.creation_date
            # whois lib may return lists
            if isinstance(exp, list):
                exp = exp[0]
            if isinstance(cre, list):
                cre = cre[0]
            if not exp or not cre:
                return 0
            if isinstance(exp, str): exp = datetime.fromisoformat(exp)
            if isinstance(cre, str): cre = datetime.fromisoformat(cre)
            return max(0, (exp - cre).days)
        except Exception:
            return 0

    def non_standard_ports(self) -> int:
        port = self.parsed.port
        if port is None:
            return 0
        return 1 if port not in (80, 443) else 0

    def external_favicon(self) -> int:
        try:
            icon = None
            # common rel values
            for tag in self.soup.find_all("link", rel=True):
                rel = " ".join(tag.get("rel", [])).lower()
                if "icon" in rel or "shortcut" in rel:
                    icon = tag.get("href")
                    break
            if not icon:
                # fallback check /favicon.ico
                icon = urljoin(f"{self.scheme}://{self.domain}", "/favicon.ico")
            # resolve hostname
            parsed_icon = urlparse(icon)
            icon_host = normalize_domain(parsed_icon.hostname) if parsed_icon.hostname else ""
            # if icon relative path -> same domain
            if not parsed_icon.hostname:
                return 0
            return 1 if icon_host and icon_host != self.domain else 0
        except Exception:
            return 0

    def count_dots(self) -> int:
        return self.url.count(".")

    def suspicious_chars(self) -> int:
        return sum(self.url.count(c) for c in ["?", "%", "&", "=", "+"])

    # -------------------------
    # Feature 15: Known logo match (uses logo_hashes.json)
    # Returns integer count of matched logos (0/1)
    # -------------------------
    def known_logo(self) -> int:
        if not os.path.exists(LOGO_HASH_FILE):
            return 0
        try:
            with open(LOGO_HASH_FILE, "r", encoding="utf-8") as f:
                known = json.load(f)  # {brand: md5hash}
        except Exception:
            known = {}
        if not known:
            return 0

        imgs = []
        for img in self.soup.find_all("img"):
            src = img.get("src") or ""
            src_l = src.lower()
            # heuristics: filenames with logo/brand, or alt containing 'logo'
            alt = (img.get("alt") or "").lower()
            if "logo" in src_l or "logo" in alt or any(b in src_l for b in known.keys()):
                imgs.append(src)

        for src in imgs:
            try:
                if not src.startswith("http"):
                    src = urljoin(f"{self.scheme}://{self.domain}", src.lstrip("/"))
                r = safe_requests_get(src)
                if r and r.status_code == 200:
                    h = md5_bytes(r.content)
                    if h in set(known.values()):
                        return 1
            except Exception:
                continue
        return 0

    # -------------------------
    # Features 16 - 21 (HTML/JS heuristics)
    # -------------------------
    def use_script(self) -> int:
        return len(self.soup.find_all("script"))

    def count_third_party_domains(self) -> int:
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
        return len(self.soup.find_all("meta"))

    def script_external_ratio(self) -> int:
        scripts = self.soup.find_all("script")
        if not scripts:
            return 0
        ext = sum(1 for s in scripts if s.get("src"))
        # return percentage as integer 0-100
        return int((ext / len(scripts)) * 100)

    def use_form(self) -> int:
        return len(self.soup.find_all("form"))

    def mailto(self) -> int:
        # count mailto links and form actions pointing to mailto:
        count = 0
        for a in self.soup.find_all("a", href=True):
            if a["href"].lower().startswith("mailto:"):
                count += 1
        for f in self.soup.find_all("form", action=True):
            if f["action"].lower().startswith("mailto:"):
                count += 1
        return count

    # -------------------------
    # Features 22 - 27
    # -------------------------
    def website_forwarding(self) -> int:
        try:
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, allow_redirects=True)
            return len(r.history)
        except Exception:
            return 0

    def status_bar(self) -> int:
        # look for window.status or history.replaceState location hacks
        txt = self.html.lower()
        return int(bool(re.search(r"window\.status|history\.replaceState|pushState\(|onbeforeunload", txt)))

    def right_click_disabled(self) -> int:
        txt = self.html.lower()
        if 'oncontextmenu="return false"' in txt or re.search(r"addEventListener\(['\"]contextmenu['\"],", txt):
            return 1
        return 0

    def popups(self) -> int:
        txt = self.html.lower()
        return len(re.findall(r"window\.open\(", txt))

    def iframes(self) -> int:
        return len(self.soup.find_all("iframe"))

    def sensitive_forms(self) -> int:
        sensitive_keywords = ["password", "pass", "cardnumber", "creditcard", "card", "cvv", "cvc", "ssn", "socialsecurity"]
        txt = self.html.lower()
        return sum(txt.count(k) for k in sensitive_keywords)

    # -------------------------
    # Features 28 - 29: Domain age and DNS record checks
    # -------------------------
    def domain_age(self) -> int:
        w = self._whois()
        if not w:
            return 0
        cre = w.creation_date
        if isinstance(cre, list):
            cre = cre[0] if cre else None
        if not cre:
            return 0
        if isinstance(cre, str):
            try:
                cre = datetime.fromisoformat(cre)
            except Exception:
                # try many formats
                try:
                    cre = datetime.strptime(cre, "%Y-%m-%d")
                except Exception:
                    return 0
        return max(0, (datetime.utcnow() - cre).days)

    def dns_record(self) -> int:
        # return number of valid A/AAAA/MX/NS records found (sum)
        total = 0
        if not self.domain:
            return 0
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

    # -------------------------
    # Feature 30: Traffic rank via Tranco local CSV or remote list
    # Returns rank (1-based) or 0
    # -------------------------
    def traffic_rank(self) -> int:
        # Try local tranco file first
        try:
            if os.path.exists(TRANC0_LOCAL):
                with open(TRANC0_LOCAL, "r", encoding="utf-8") as f:
                    for i, line in enumerate(f):
                        domain_line = line.strip().lower()
                        if domain_line == self.domain:
                            return i + 1
            # fallback: attempt to fetch latest tranco list (may be large; optional)
            tranco_url = "https://tranco-list.eu/top-1m.csv"  # placeholder (may not be publicly accessible)
            resp = safe_requests_get(tranco_url)
            if resp and resp.status_code == 200:
                # parse lines "rank,domain"
                lines = resp.text.splitlines()
                for line in lines:
                    parts = line.split(",")
                    if len(parts) >= 2 and normalize_domain(parts[1]) == self.domain:
                        try:
                            return int(parts[0])
                        except Exception:
                            return 0
        except Exception:
            pass
        return 0

    # -------------------------
    # Feature 31: Page ranking (simple heuristic using backlinks as proxy)
    # -------------------------
    def page_ranking(self) -> int:
        # use backlinks() result as proxy
        return self.backlinks()

    # -------------------------
    # Feature 32: Google index count via Custom Search API
    # -------------------------
    def google_index(self) -> int:
        if not GOOGLE_API_KEY or not GOOGLE_CX:
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

    # -------------------------
    # Feature 33: Backlinks via Bing Search API (counts returned results)
    # -------------------------
    def backlinks(self) -> int:
        # Requires BING_API_KEY (Bing Web Search)
        if not BING_API_KEY:
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

    # -------------------------
    # Feature 34: Blacklist report via VirusTotal (malicious count)
    # -------------------------
    def blacklist(self) -> int:
        # Returns number of engines that flagged domain as malicious on VirusTotal
        if not VT_API_KEY:
            return 0
        try:
            headers = {"x-apikey": VT_API_KEY}
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{self.domain}", headers=headers, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return 0
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # sum suspicious/malicious positives
            return int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        except Exception:
            return 0

    # -------------------------
    # Feature 35: WHOIS suspicious tokens
    # -------------------------
    def whois_suspicious_tokens(self) -> int:
        try:
            w = self._whois()
            if not w:
                return 0
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

    # -------------------------
    # Final aggregator: returns all 35 features as integers
    # -------------------------
    def extract_all(self) -> dict:
        features = {
            # 1-14
            "ip_in_url": int(self.ip_in_url()),
            "url_length": int(self.url_length()),
            "url_shortening": int(self.url_shortening()),
            "presence_at": int(self.presence_at()),
            "redirection_symbol": int(self.redirection_symbol()),
            "hyphen_in_domain": int(self.hyphen_in_domain()),
            "too_many_subdomains": int(self.too_many_subdomains()),
            "https_in_string": int(self.https_in_string()),
            "ssl_tls_validity": int(self.ssl_tls_validity()),
            "domain_registration_length": int(self.domain_registration_length()),
            "non_standard_ports": int(self.non_standard_ports()),
            "external_favicon": int(self.external_favicon()),
            "count_dots": int(self.count_dots()),
            "suspicious_chars": int(self.suspicious_chars()),

            # 15-21
            "known_logo": int(self.known_logo()),
            "use_script": int(self.use_script()),
            "count_third_party_domains": int(self.count_third_party_domains()),
            "use_meta": int(self.use_meta()),
            "script_external_ratio": int(self.script_external_ratio()),
            "use_form": int(self.use_form()),
            "mailto": int(self.mailto()),

            # 22-27
            "website_forwarding": int(self.website_forwarding()),
            "status_bar_customization": int(self.status_bar()),
            "right_click_disabled": int(self.right_click_disabled()),
            "popups": int(self.popups()),
            "iframes": int(self.iframes()),
            "sensitive_forms": int(self.sensitive_forms()),

            # 28-29
            "domain_age": int(self.domain_age()),
            "dns_record_count": int(self.dns_record()),

            # 30-35
            "website_traffic_rank": int(self.traffic_rank()),
            "page_ranking": int(self.page_ranking()),
            "google_index": int(self.google_index()),
            "backlinks": int(self.backlinks()),
            "blacklist": int(self.blacklist()),
            "whois_suspicious_tokens": int(self.whois_suspicious_tokens()),
        }
        return features


# ---------------------------
# Example usage
# ---------------------------
if __name__ == "__main__":
    #TEST_URL = "http://example.com"
    TEST_URL = "index_features.html"
    print("Phishing feature extraction demo for:", TEST_URL)
    ext = PhishingFeatureExtractor(TEST_URL)
    feats = ext.extract_all()
    for k, v in feats.items():
        print(f"{k}: {v}")
    # save to JSON
    with open("features_output.json", "w", encoding="utf-8") as f:
        json.dump(feats, f, indent=2)
    print("Saved features_output.json")
