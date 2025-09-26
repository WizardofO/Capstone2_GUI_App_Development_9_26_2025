import re
import socket
import tldextract
import requests
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

class PhishingFeatureExtractor:
    def __init__(self, url, html_content=""):
        self.url = url
        self.html = html_content or self.fetch_html()
        self.parsed = urlparse(url)
        self.domain = self.parsed.hostname or ""
        self.ext = tldextract.extract(url)

    def fetch_html(self):
        try:
            return requests.get(self.url, timeout=10).text
        except Exception:
            return ""

    # === 1 IP Address in URL
    def ip_in_url(self):
        return 1 if re.match(r"^https?://\d{1,3}(\.\d{1,3}){3}", self.url) else 0

    # === 2 URL Length
    def url_length(self):
        return len(self.url)

    # === 3 URL Shortening
    def url_shortening(self):
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "buff.ly"]
        return 1 if any(s in self.domain for s in shorteners) else 0

    # === 4 Presence of @
    def presence_at(self):
        return self.url.count("@")

    # === 5 Extra //
    def redirection_symbol(self):
        return self.url.count("//") - 1  # discount protocol //

    # === 6 Hyphen in domain
    def hyphen_in_domain(self):
        return self.domain.count("-")

    # === 7 Too many subdomains
    def too_many_subdomains(self):
        return self.ext.subdomain.count(".") + (1 if self.ext.subdomain else 0)

    # === 8 "https" in URL string line
    def https_in_string(self):
        return self.url.lower().count("https")

    # === 9 SSL/TLS validity (stub: always valid if https)
    def ssl_tls_validity(self):
        return 1 if self.url.startswith("https") else 0

    # === 10 Domain Registration length
    def domain_registration_length(self):
        try:
            w = whois.whois(self.domain)
            if w.expiration_date and w.creation_date:
                # handle list type
                exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                return (exp - cre).days
        except Exception:
            return 0
        return 0

    # === 11 Non-standard ports
    def non_standard_ports(self):
        return 1 if self.parsed.port not in [80, 443, None] else 0

    # === 12 External Favicon
    def external_favicon(self):
        soup = BeautifulSoup(self.html, "html.parser")
        icon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon and "href" in icon.attrs:
            fav = urlparse(icon["href"]).hostname
            return 1 if fav and fav != self.domain else 0
        return 0

    # === 13 Count dots
    def count_dots(self):
        return self.url.count(".")

    # === 14 Suspicious chars ?,%,&
    def suspicious_chars(self):
        return sum(self.url.count(c) for c in ["?", "%", "&", "="])

    # === 15 Known logo match (stub)
    def known_logo(self):
        return 0  # needs brand database

    # === 16 Use of <script>
    def use_script(self):
        return self.html.lower().count("<script")

    # === 17 Third-party domains
    def count_third_party_domains(self):
        soup = BeautifulSoup(self.html, "html.parser")
        domains = set()
        for tag in soup.find_all(["script", "img", "link", "iframe"]):
            src = tag.get("src") or tag.get("href")
            if src:
                d = urlparse(src).hostname
                if d and d != self.domain:
                    domains.add(d)
        return len(domains)

    # === 18 Use of <meta>
    def use_meta(self):
        return self.html.lower().count("<meta")

    # === 19 Script external ratio
    def script_external_ratio(self):
        soup = BeautifulSoup(self.html, "html.parser")
        scripts = soup.find_all("script")
        if not scripts: return 0
        ext_count = sum(1 for s in scripts if s.get("src"))
        return int((ext_count / len(scripts)) * 100)

    # === 20 Use of <form>
    def use_form(self):
        return self.html.lower().count("<form")

    # === 21 mailto
    def mailto(self):
        return self.html.lower().count("mailto:")

    # === 22 Forwarding (stub)
    def website_forwarding(self):
        try:
            r = requests.get(self.url, timeout=5, allow_redirects=True)
            return len(r.history)
        except Exception:
            return 0

    # === 23 Status bar customization
    def status_bar(self):
        return self.html.lower().count("window.status")

    # === 24 Right click disabled
    def right_click_disabled(self):
        return 1 if "contextmenu" in self.html.lower() else 0

    # === 25 Pop-ups
    def popups(self):
        return self.html.lower().count("window.open")

    # === 26 iframes
    def iframes(self):
        return self.html.lower().count("<iframe")

    # === 27 sensitive forms
    def sensitive_forms(self):
        sensitive = ["password", "credit", "card", "ssn", "cvv"]
        return sum(self.html.lower().count(s) for s in sensitive)

    # === 28 Domain age
    def domain_age(self):
        try:
            w = whois.whois(self.domain)
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            return (datetime.now() - cre).days
        except Exception:
            return 0

    # === 29 DNS record
    def dns_record(self):
        try:
            return 1 if socket.gethostbyname(self.domain) else 0
        except Exception:
            return 0

    # === 30 Traffic rank (stub)
    def traffic_rank(self):
        return 0  # requires API

    # === 31 Page ranking (stub)
    def page_ranking(self):
        return 0

    # === 32 Google index (stub)
    def google_index(self):
        return 0

    # === 33 Backlinks (stub)
    def backlinks(self):
        return 0

    # === 34 Blacklist report (stub)
    def blacklist(self):
        return 0

    # === 35 WHOIS suspicious tokens
    def whois_suspicious_tokens(self):
        try:
            w = whois.whois(self.domain)
            raw = str(w)
            tokens = ["privacy", "whoisguard", "proxy", "redacted", "protected", "gmail.com"]
            return sum(raw.lower().count(t) for t in tokens)
        except Exception:
            return 0

    # === Aggregate all features into dict
    def extract_all(self):
        return {
            "ip_in_url": self.ip_in_url(),
            "url_length": self.url_length(),
            "url_shortening": self.url_shortening(),
            "presence_at": self.presence_at(),
            "redirection_symbol": self.redirection_symbol(),
            "hyphen_in_domain": self.hyphen_in_domain(),
            "too_many_subdomains": self.too_many_subdomains(),
            "https_in_string": self.https_in_string(),
            "ssl_tls_validity": self.ssl_tls_validity(),
            "domain_registration_length": self.domain_registration_length(),
            "non_standard_ports": self.non_standard_ports(),
            "external_favicon": self.external_favicon(),
            "count_dots": self.count_dots(),
            "suspicious_chars": self.suspicious_chars(),
            "known_logo": self.known_logo(),
            "use_script": self.use_script(),
            "count_third_party_domains": self.count_third_party_domains(),
            "use_meta": self.use_meta(),
            "script_external_ratio": self.script_external_ratio(),
            "use_form": self.use_form(),
            "mailto": self.mailto(),
            "website_forwarding": self.website_forwarding(),
            "status_bar": self.status_bar(),
            "right_click_disabled": self.right_click_disabled(),
            "popups": self.popups(),
            "iframes": self.iframes(),
            "sensitive_forms": self.sensitive_forms(),
            "domain_age": self.domain_age(),
            "dns_record": self.dns_record(),
            "traffic_rank": self.traffic_rank(),
            "page_ranking": self.page_ranking(),
            "google_index": self.google_index(),
            "backlinks": self.backlinks(),
            "blacklist": self.blacklist(),
            "whois_suspicious_tokens": self.whois_suspicious_tokens(),
        }

# === Example usage
if __name__ == "__main__":
    url = "http://example.com"
    extractor = PhishingFeatureExtractor(url)
    features = extractor.extract_all()
    for k, v in features.items():
        print(f"{k}: {v}")
