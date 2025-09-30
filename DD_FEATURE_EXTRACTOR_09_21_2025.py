# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva 
"""
REQUIREMENTS:
PySide6 GUI wrapper around the 35-feature phishing extractor.
1. Load CSV (input,label) where input is URL or local file path and label is 1 or 0.
2. Buttons Functions:
        Add CSV, 
        Clear, 
        Start Extract
        Stop
        Save CSV
        Save JSON.
3. Concurrent extraction using ThreadPoolExecutor (configurable workers).
"""
import sys
import os
import csv
import json
import re
import time
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from datetime import datetime
from urllib.parse import urlparse, urljoin

# GUI
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QTableWidget, QTableWidgetItem, QProgressBar,
    QLabel, QSpinBox, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QObject

# Networking / parsing libs
import requests                                                     # requests is for HTTP requests                               
import whois                                                        # whois is for domain WHOIS lookups
import tldextract                                                   # tldextract is for domain parsing
import dns.resolver                                                 # dns.resolver is for DNS lookups    
import hashlib                                                      # hashlib is for hashing (logo detection)
from bs4 import BeautifulSoup                                       # BeautifulSoup is for HTML parsing        

# Optional API keys via environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")                        # Google Custom Search API key
GOOGLE_CX = os.getenv("GOOGLE_CX")                                  # Google Custom Search Engine ID
BING_API_KEY = os.getenv("BING_API_KEY")                            # Bing Search API key
VT_API_KEY = os.getenv("VT_API_KEY")                                # VirusTotal API key
GSB_API_KEY = os.getenv("GSB_API_KEY")                              # Google Safe Browsing API key
TRANC0_LOCAL = os.getenv("TRANCO_CSV_PATH", "tranco.csv")           # Local Tranco CSV file path (optional)
LOGO_HASH_FILE = os.getenv("LOGO_HASH_FILE", "logo_hashes.json")    # Local logo hashes JSON file path (optional)

REQUESTS_TIMEOUT = 10                                               # Requests timeout in seconds is for network operations used to fetch HTML, WHOIS, DNS, APIs and the 10 is a reasonable timeout for network operations.

# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Core extractor (complete 35 features)
# Included inline so GUI is self-contained.
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def safe_requests_get(url, **kwargs):
    try:
        return requests.get(url, timeout=REQUESTS_TIMEOUT, **kwargs)
    except Exception:
        return None
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def normalize_domain(hostname: str) -> str:
    if not hostname:
        return ""
    return hostname.lower().strip().lstrip("www.")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
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
            self.html = html_content
            self.soup = BeautifulSoup(html_content, "html.parser")
        elif url and not file_mode:
            self.html = self.fetch_html()
            self.soup = BeautifulSoup(self.html or "", "html.parser")

        # load optional logo hashes
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def fetch_html(self) -> str:
        if not self.url:
            return ""
        try:
            headers = {"User-Agent": "PhishFeatureBot/1.0"}
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
            return r.text or ""
        except Exception:
            return ""
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 1
    def ip_in_url(self) -> int:
        if not self.url:
            return 0
        return 1 if re.match(r"^https?://\d{1,3}(?:\.\d{1,3}){3}", self.url) else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 2
    def url_length(self) -> int:
        return len(self.url) if self.url else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 3
    def url_shortening(self) -> int:
        if not self.domain:
            return 0
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rb.gy"}
        return 1 if any(s in self.domain for s in shorteners) else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 4
    def presence_at(self) -> int:
        return (self.url.count("@") if self.url else 0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 5
    def redirection_symbol(self) -> int:
        if not self.url:
            return 0
        total = self.url.count("//")
        return max(0, total - 1)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 6
    def hyphen_in_domain(self) -> int:
        return self.domain.count("-") if self.domain else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 7
    def too_many_subdomains(self) -> int:
        sub = self.ext.subdomain if self.ext else ""
        if not sub:
            return 0
        return sub.count(".") + 1
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 8
    def https_in_string(self) -> int:
        if not self.url:
            return 0
        path_and_query = (self.parsed.path or "") + (self.parsed.query or "")
        return path_and_query.lower().count("https") + (self.html.lower().count("https") if self.html else 0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 9
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 10
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
            if isinstance(exp, str):
                exp = datetime.fromisoformat(exp)
            if isinstance(cre, str):
                cre = datetime.fromisoformat(cre)
            return max(0, (exp - cre).days)
        except Exception:
            return 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 11
    def non_standard_ports(self) -> int:
        if not self.parsed:
            return 0
        port = self.parsed.port
        if port is None:
            return 0
        return 1 if port not in (80, 443) else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 12
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 13
    def count_dots(self) -> int:
        return self.url.count(".") if self.url else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 14
    def suspicious_chars(self) -> int:
        if not self.url:
            return 0
        return sum(self.url.count(c) for c in ["?", "%", "&", "=", "+"])
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 15
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 16
    def use_script(self) -> int:
        return len(self.soup.find_all("script")) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 17
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 18
    def use_meta(self) -> int:
        return len(self.soup.find_all("meta")) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 19
    def script_external_ratio(self) -> int:
        if not self.soup:
            return 0
        scripts = self.soup.find_all("script")
        if not scripts:
            return 0
        ext = sum(1 for s in scripts if s.get("src"))
        return int((ext / len(scripts)) * 100)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 20
    def use_form(self) -> int:
        return len(self.soup.find_all("form")) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 21
    def mailto(self) -> int:
        if not self.html:
            return 0
        return self.html.lower().count("mailto:")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 22
    def website_forwarding(self) -> int:
        if not self.soup:
            return 0
        if self.soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)}):
            return 1
        txt = self.html.lower() if self.html else ""
        if "location.replace(" in txt or "window.location" in txt:
            return 1
        return 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 23
    def status_bar(self) -> int:
        txt = (self.html or "").lower()
        return int(bool(re.search(r"window\.status|history\.replaceState|pushState\(|onbeforeunload", txt)))
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 24
    def right_click_disabled(self) -> int:
        txt = (self.html or "").lower()
        if 'oncontextmenu="return false"' in txt or re.search(r"addEventListener\(['\"]contextmenu['\"],", txt):
            return 1
        return 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 25
    def popups(self) -> int:
        txt = (self.html or "").lower()
        return len(re.findall(r"window\.open\(", txt))
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 26
    def iframes(self) -> int:
        return len(self.soup.find_all("iframe")) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 27
    def sensitive_forms(self) -> int:
        sensitive_keywords = ["password", "pass", "cardnumber", "creditcard", "card", "cvv", "cvc", "ssn", "socialsecurity"]
        txt = (self.html or "").lower()
        return sum(txt.count(k) for k in sensitive_keywords)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 28
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 29
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 30
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 31
    def page_ranking(self) -> int:
        return self.backlinks()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 32
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 33
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 34
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 35
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
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

# ------------------------------------------------------------------------------------------------------------------------------------------ #
#                                                        GUI helpers & worker signalling
# ------------------------------------------------------------------------------------------------------------------------------------------ #

class WorkerSignals(QObject):
    row_done = Signal(int, dict, str)   # index, features dict, error string
    progress = Signal(int, int)         # done_count, total
    finished = Signal()

# Worker that uses ThreadPoolExecutor and emits signals
class BatchWorker:
    def __init__(self, rows, max_workers=8, whois_pause=0.0, signals: WorkerSignals=None):
        """
        rows: list of tuples (index, input_str, label)
        """
        self.rows = rows
        self.max_workers = max_workers
        self.whois_pause = whois_pause
        self.signals = signals or WorkerSignals()
        self._stop_event = threading.Event()
        self._executor = None
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def stop(self):
        self._stop_event.set()
        if self._executor:
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def run(self):
        total = len(self.rows)
        done = 0
        # start thread pool
        self._executor = ThreadPoolExecutor(max_workers=self.max_workers)
        futures = {}
        try:
            for (idx, input_str, label) in self.rows:
                if self._stop_event.is_set():
                    break
                # submit job
                fut = self._executor.submit(self._process_single, idx, input_str, label)
                futures[fut] = (idx, input_str)
            # iterate completion
            for fut in as_completed(futures):
                if self._stop_event.is_set():
                    break
                idx, input_str = futures[fut]
                try:
                    feat_dict, err = fut.result()
                except Exception as e:
                    feat_dict = {}
                    err = f"exception: {e}\\n{traceback.format_exc()}"
                done += 1
                if self.signals:
                    self.signals.row_done.emit(idx, feat_dict, err)
                    self.signals.progress.emit(done, total)
                # small pause if requested (throttle)
                if self.whois_pause:
                    time.sleep(self.whois_pause)
        finally:
            try:
                self._executor.shutdown(wait=False)
            except Exception:
                pass
            if self.signals:
                self.signals.finished.emit()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _process_single(self, index, input_str, label):
        err = ""
        try:
            is_url = input_str.strip().lower().startswith("http://") or input_str.strip().lower().startswith("https://")
            if is_url:
                extractor = PhishingFeatureExtractor(url=input_str)
            else:
                content = ""
                try:
                    with open(input_str, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception as e:
                    err = f"file_error: {e}"
                extractor = PhishingFeatureExtractor(url=None, html_content=content, file_mode=True)
            feats = extractor.extract_all()
            # attach metadata
            feats["input"] = input_str
            feats["label"] = int(label) if str(label).strip() in ("0","1") else label
            return feats, err
        except Exception as e:
            return {}, f"exception: {e}\\n{traceback.format_exc()}"

# ------------------------------------------------------------------------------------------------------------------------------------------ #
#                                                               Main Window
# ------------------------------------------------------------------------------------------------------------------------------------------ #

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Feature Extractor - GUI_Capstone2_NIEVA OSIAS JR")
        self.resize(1100, 700)

        self.rows = []  # list of (index, input, label)
        self.results = {}  # index -> feature dict or error
        self.worker = None
        self.worker_thread = None

        # UI
        self._build_ui()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _build_ui(self):
        w = QWidget()
        self.setCentralWidget(w)
        v = QVBoxLayout()
        w.setLayout(v)

        # Top controls
        controls = QHBoxLayout()
        self.btn_add_csv = QPushButton("Add CSV")
        self.btn_add_csv.clicked.connect(self.on_add_csv)
        controls.addWidget(self.btn_add_csv)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.on_clear)
        controls.addWidget(self.btn_clear)

        self.btn_start = QPushButton("Start Extract")
        self.btn_start.clicked.connect(self.on_start)
        controls.addWidget(self.btn_start)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self.on_stop)
        controls.addWidget(self.btn_stop)

        self.btn_save_csv = QPushButton("Save CSV")
        self.btn_save_csv.clicked.connect(self.on_save_csv)
        controls.addWidget(self.btn_save_csv)

        self.btn_save_json = QPushButton("Save JSON")
        self.btn_save_json.clicked.connect(self.on_save_json)
        controls.addWidget(self.btn_save_json)

        controls.addStretch()

        controls.addWidget(QLabel("Workers:"))
        self.spin_workers = QSpinBox()
        self.spin_workers.setRange(1, 64)
        self.spin_workers.setValue(8)
        controls.addWidget(self.spin_workers)

        v.addLayout(controls)

        # Progress
        self.progress = QProgressBar()
        v.addWidget(self.progress)

        # Table
        self.table = QTableWidget()
        v.addWidget(self.table)

        # Status bar
        self.statusbar = QLabel("Ready")
        v.addWidget(self.statusbar)

        # Initialize empty table with columns (input,label, then 35 features)
        sample_extractor = PhishingFeatureExtractor(url=None, html_content="<html></html>", file_mode=True)
        sample = sample_extractor.extract_all()
        # Keep column order deterministic
        self.feature_keys = list(sample.keys())
        # ensure input, label first
        columns = ["input", "label"] + self.feature_keys
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # UI slots
    def on_add_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open CSV file", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        # read CSV
        added = 0
        try:
            with open(path, newline="", encoding="utf-8", errors="ignore") as csvfile:
                reader = csv.reader(csvfile)
                for i, row in enumerate(reader):
                    if not row: continue
                    if len(row) < 2:
                        continue
                    idx = len(self.rows)
                    input_str = row[0].strip()
                    label = row[1].strip()
                    self.rows.append((idx, input_str, label))
                    added += 1
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read CSV: {e}")
            return
        self.statusbar.setText(f"Loaded {added} rows from {os.path.basename(path)}")
        self._refresh_table()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_clear(self):
        if self.worker:
            QMessageBox.warning(self, "Warning", "Stop current extraction first.")
            return
        self.rows = []
        self.results = {}
        self._refresh_table()
        self.statusbar.setText("Cleared")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_start(self):
        if not self.rows:
            QMessageBox.information(self, "No rows", "Please add a CSV first.")
            return
        if self.worker:
            QMessageBox.information(self, "Running", "Extraction already running.")
            return
        workers = self.spin_workers.value()
        self.progress.setValue(0)
        self.progress.setMaximum(len(self.rows))
        # prepare signals and worker
        signals = WorkerSignals()
        signals.row_done.connect(self.on_row_done)
        signals.progress.connect(self.on_progress)
        signals.finished.connect(self.on_finished)

        self.worker = BatchWorker(self.rows, max_workers=workers, whois_pause=0.0, signals=signals)
        # run worker in a dedicated thread so GUI stays responsive
        self.worker_thread = threading.Thread(target=self.worker.run, daemon=True)
        self.worker_thread.start()
        self.statusbar.setText("Extraction started")
        self.btn_start.setEnabled(False)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_stop(self):
        if not self.worker:
            self.statusbar.setText("No active extraction")
            return
        self.worker.stop()
        self.statusbar.setText("Stop requested")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_save_csv(self):
        if not self.results:
            QMessageBox.information(self, "No data", "No results to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "features_output.csv", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        try:
            # columns: input,label + feature_keys
            fieldnames = ["input","label"] + self.feature_keys + ["scan_error"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for idx, (i, inp, lab) in enumerate(self.rows):
                    row = {}
                    res = self.results.get(idx, {})
                    row["input"] = res.get("input", inp)
                    row["label"] = res.get("label", lab)
                    for key in self.feature_keys:
                        row[key] = res.get(key, "")
                    row["scan_error"] = res.get("_error", "")
                    writer.writerow(row)
            self.statusbar.setText(f"Saved CSV: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save CSV: {e}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_save_json(self):
        if not self.results:
            QMessageBox.information(self, "No data", "No results to save.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "features_output.json", "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            out = []
            for idx, (i, inp, lab) in enumerate(self.rows):
                res = self.results.get(idx, {})
                # fill defaults
                entry = {"input": res.get("input", inp), "label": res.get("label", lab)}
                for key in self.feature_keys:
                    entry[key] = res.get(key, None)
                entry["_error"] = res.get("_error", "")
                out.append(entry)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
            self.statusbar.setText(f"Saved JSON: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save JSON: {e}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # worker signal handlers
    def on_row_done(self, idx, features, err):
        # store result and update table row
        if features is None:
            features = {}
        # add error to features
        features["_error"] = err or ""
        self.results[idx] = features
        # update table row
        rowpos = idx
        # ensure table has enough rows
        if rowpos >= self.table.rowCount():
            self.table.setRowCount(rowpos + 1)
        # fill input and label first
        input_val = features.get("input", self.rows[idx][1])
        label_val = features.get("label", self.rows[idx][2])
        self.table.setItem(rowpos, 0, QTableWidgetItem(str(input_val)))
        self.table.setItem(rowpos, 1, QTableWidgetItem(str(label_val)))
        # fill features columns
        for col_i, key in enumerate(self.feature_keys, start=2):
            val = features.get(key, "")
            it = QTableWidgetItem(str(val))
            self.table.setItem(rowpos, col_i, it)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_progress(self, done, total):
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.statusbar.setText(f"Progress: {done}/{total}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_finished(self):
        self.statusbar.setText("Extraction finished")
        self.btn_start.setEnabled(True)
        self.worker = None
        self.worker_thread = None
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _refresh_table(self):
        n = len(self.rows)
        self.table.setRowCount(n)
        # clear cells
        for r in range(n):
            input_str = self.rows[r][1]
            label = self.rows[r][2]
            self.table.setItem(r, 0, QTableWidgetItem(input_str))
            self.table.setItem(r, 1, QTableWidgetItem(str(label)))
            for c in range(2, self.table.columnCount()):
                self.table.setItem(r, c, QTableWidgetItem(""))

# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Run app the MAIN app
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
# ---------------------------------------------------end of code --------------------------------------------------------------------------- #