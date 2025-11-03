# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva 
import os
import sys
import json
import re
import time
import traceback
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin

#PYSIDE6 Libraries
import subprocess
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QProgressBar, QMessageBox,
    QTableWidget, QTableWidgetItem, QLineEdit, QStackedWidget, QGridLayout,
    QSizePolicy, QGroupBox, QSpacerItem, QSlider, QGraphicsDropShadowEffect,
    QFrame
)
from PySide6.QtCore import Qt, Signal, QThread, QSize, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QPalette, QColor, QIcon

# Remove PyQt5 imports as we're using PySide6
# ------------------------------------------------------------------------------------------------------------------------------------------ #
# ML libs
import pandas as pd                                        # Pandas is used for data manipulation and analysis.Used in this code specifically for handling datasets like CSV files, dataframes, and tabular data.                 
import numpy as np                                         # NumPy is used for numerical operations and array manipulations. Used in this code specifically for handling numerical data, arrays, and mathematical computations.
import joblib                                              # Joblib is used for saving and loading machine learning models. Used in this code specifically for persisting trained ML models to disk and loading them back for predictions.
from sklearn.ensemble import RandomForestClassifier, VotingClassifier   
from sklearn.tree import DecisionTreeClassifier            # DecisionTreeClassifier is used for classification tasks. Used in this code specifically for building decision tree models for phishing detection.
from sklearn.naive_bayes import GaussianNB                 # GaussianNB is used for classification tasks based on Bayes' theorem. Used in this code specifically for building Naive Bayes models for phishing detection.
from sklearn.preprocessing import StandardScaler           # StandardScaler is used for feature scaling. Used in this code specifically for normalizing feature values to have zero mean and unit variance.
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
# ------------------------------------------------------------------------------------------------------------------------------------------ #

# optional SMOTE
try:
    from imblearn.over_sampling import SMOTE                # SMOTE was use to handle imbalanced datasets during model training
    IMBLEARN_AVAILABLE = True
except Exception:
    IMBLEARN_AVAILABLE = False
# ------------------------------------------------------------------------------------------------------------------------------------------ #

# networking/parsing
import requests                                             # requests is used to fetch HTML content and perform network operations
import whois                                                # whois is used to retrieve domain registration information
import tldextract                                           # tldextract is used to parse domain components
import dns.resolver                                         # dnspython is used to perform DNS queries           
import hashlib
from bs4 import BeautifulSoup
# ------------------------------------------------------------------------------------------------------------------------------------------ #

import subprocess                                           # subprocess is used to run external commands and scripts from within Python code
# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Optional API keys via environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")                        # Google Custom Search API key
GOOGLE_CX = os.getenv("GOOGLE_CX")                                  # Google Custom Search Engine ID
BING_API_KEY = os.getenv("BING_API_KEY")                            # Bing Search API key
VT_API_KEY = os.getenv("VT_API_KEY")                                # VirusTotal API key
GSB_API_KEY = os.getenv("GSB_API_KEY")                              # Google Safe Browsing API key
TRANC0_LOCAL = os.getenv("TRANCO_CSV_PATH", "tranco.csv")           # Local Tranco CSV file path (optional)
LOGO_HASH_FILE = os.getenv("LOGO_HASH_FILE", "logo_hashes.json")    # Local logo hashes JSON file path (optional)
REQUESTS_TIMEOUT = 10                                       # This line of code was used to set a timeout value (in seconds) for network requests made using the requests library to prevent hanging requests.
LOGO_HASH_FILE = os.getenv('LOGO_HASH_FILE', 'logo_hashes.json')
TRANC0_LOCAL = os.getenv('TRANCO_CSV_PATH', 'tranco_L7N94_1M.csv')

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
        return ''
    return hostname.lower().strip().lstrip('www.')
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class PhishingFeatureExtractor:
    def __init__(self, url: str = None, html_content: str = None, file_mode: bool = False):
        self.url = url
        self.file_mode = file_mode
        self.html = html_content
        self.parsed = urlparse(url) if url else None
        self.scheme = self.parsed.scheme if self.parsed else 'http'
        self.domain = normalize_domain(self.parsed.hostname) if self.parsed else ''
        self.ext = tldextract.extract(url) if url else None
        self.soup = None
        if html_content is not None:
            self.html = html_content
            self.soup = BeautifulSoup(html_content, 'html.parser')
        elif url and not file_mode:
            self.html = self.fetch_html()
            self.soup = BeautifulSoup(self.html or '', 'html.parser')

        # load optional logo hashes
        self.known_logo_hashes = set()
        try:
            if os.path.exists(LOGO_HASH_FILE):
                with open(LOGO_HASH_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.known_logo_hashes = set(data.values())
                    elif isinstance(data, list):
                        self.known_logo_hashes = set(data)
        except Exception:
            self.known_logo_hashes = set()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # Purpose is to fetch the HTML content of a given URL using the requests library the output of this function is a string 
    # containing the HTML content of the webpage if the URL is valid and accessible otherwise it returns an empty string.
    def fetch_html(self) -> str:    
        if not self.url:
            return ''
        try:
            headers = {'User-Agent': 'PhishFeatureBot/1.0'}
            try:
                # First try with SSL verification
                r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=True)
            except requests.exceptions.SSLError:
                # If SSL verification fails, retry without verification but log it
                print(f"[WARNING] SSL verification failed for {self.url}, proceeding without verification")
                r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
            return r.text or '' 
        except Exception as e:
            print(f"[ERROR] Failed to fetch HTML for {self.url}: {str(e)}")
            return '' 
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 1
    def ip_in_url(self) -> int:
        if not self.url:
            return 0
        return 1 if re.match(r'^https?://\d{1,3}(?:\.\d{1,3}){3}', self.url) else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 2
    def url_length(self) -> int:
        return len(self.url) if self.url else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 3
    def url_shortening(self) -> int:
        if not self.domain:
            return 0
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rb.gy'}
        return 1 if any(s in self.domain for s in shorteners) else 0
    
    # Le Page, S., Jourdan, G.-V., v. Bochmann, G., Flood, J., & Onut, I.-V. (2018). Using URL Shorteners to Compare Phishing and Malware Attacks 
    # (Paper presented at eCrime Research 2018). Retrieved from https://docs.apwg.org/ecrimeresearch/2018/5351273.pdf
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 4
    def presence_at(self) -> int:
        return (self.url.count('@') if self.url else 0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 5
    def redirection_symbol(self) -> int:
        if not self.url:
            return 0
        total = self.url.count('//')
        return max(0, total - 1)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 6
    def hyphen_in_domain(self) -> int:
        return self.domain.count('-') if self.domain else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 7
    def too_many_subdomains(self) -> int:
        sub = self.ext.subdomain if self.ext else ''
        if not sub:
            return 0
        return sub.count('.') + 1
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 8
    def https_in_string(self) -> int:
        if not self.url:
            return 0
        path_and_query = (self.parsed.path or '') + (self.parsed.query or '')
        return path_and_query.lower().count('https') + (self.html.lower().count('https') if self.html else 0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 9
    def ssl_tls_validity(self) -> int:
        if not self.url:
            return 0
        if self.scheme != 'https':
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
            for tag in self.soup.find_all('link', rel=True):
                rels = [r.lower() for r in tag.get('rel', [])]
                if any('icon' in r for r in rels):
                    icon = tag.get('href')
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
        return self.url.count('.') if self.url else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 14
    def suspicious_chars(self) -> int:
        if not self.url:
            return 0
        return sum(self.url.count(c) for c in ['?', '%', '&', '=', '+'])
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 15
    def known_logo(self) -> int:
        if not self.soup or not self.known_logo_hashes:
            return 0
        imgs = []
        for img in self.soup.find_all('img'):
            src = img.get('src') or ''
            alt = (img.get('alt') or '').lower()
            if 'logo' in src.lower() or 'logo' in alt:
                imgs.append(src)
        for src in imgs:
            try:
                if not src.startswith('http'):
                    base = f"{self.scheme}://{self.domain}" if self.domain else ''
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
        return len(self.soup.find_all('script')) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 17
    def count_third_party_domains(self) -> int:
        if not self.soup:
            return 0
        domains = set()
        for tag in self.soup.find_all(['script', 'img', 'link', 'iframe', 'video', 'audio', 'embed', 'source']):
            src = tag.get('src') or tag.get('href')
            if not src:
                continue
            p = urlparse(src)
            host = normalize_domain(p.hostname) if p.hostname else ''
            if host and host != self.domain:
                domains.add(host)
        return len(domains)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 18
    def use_meta(self) -> int:
        return len(self.soup.find_all('meta')) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 19
    def script_external_ratio(self) -> int:
        if not self.soup:
            return 0
        scripts = self.soup.find_all('script')
        if not scripts:
            return 0
        ext = sum(1 for s in scripts if s.get('src'))
        return int((ext / len(scripts)) * 100)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 20
    def use_form(self) -> int:
        return len(self.soup.find_all('form')) if self.soup else 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 21
    def mailto(self) -> int:
        if not self.html:
            return 0
        return self.html.lower().count('mailto:')
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 22
    def website_forwarding(self) -> int:
        if not self.soup:
            return 0
        if self.soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)}):
            return 1
        txt = self.html.lower() if self.html else ''
        if 'location.replace(' in txt or 'window.location' in txt:
            return 1
        return 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 23
    def status_bar(self) -> int:
        txt = (self.html or '').lower()
        return int(bool(re.search(r'window\.status|history\.replaceState|pushState\(|onbeforeunload', txt)))
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 24
    def right_click_disabled(self) -> int:
        txt = (self.html or "").lower()
        # Check for inline disabling
        if 'oncontextmenu="return false"' in txt or "oncontextmenu='return false'" in txt:
            return 1
        # Check for addEventListener or attachEvent
        if re.search(r"addEventListener\(['\"]contextmenu['\"],", txt):
            return 1
        if re.search(r"attachEvent\(['\"]oncontextmenu['\"],", txt):
            return 1
        # Check for jQuery style
        if re.search(r"\.on\(['\"]contextmenu['\"],", txt):
            return 1
        # Check for body or html tag disabling
        if self.soup:
            for tag in self.soup.find_all(["body", "html"]):
                if tag.has_attr("oncontextmenu") and tag["oncontextmenu"].strip().lower() == "return false":
                    return 1
        # Check for script disabling right-click
        if re.search(r"event\.button\s*==\s*2", txt) or re.search(r"event\.which\s*==\s*3", txt):
            return 1
        return 0
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 25
    def popups(self) -> int:
        txt = (self.html or '').lower()
        return len(re.findall(r'window\.open\(', txt))
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 26
    def iframes(self) -> int:
        count = 0
        if self.soup:
            # Count all iframe tags
            count += len(self.soup.find_all("iframe"))
        # Also check for dynamically created iframes in scripts
        txt = (self.html or "").lower()
        # Look for document.createElement('iframe') or similar patterns
        dynamic_iframe_patterns = [
            r"document\.createelement\(['\"]iframe['\"]\)",
            r"<iframe[\s>]",
            r"window\.frames",
            r"appendchild\s*\(\s*iframe",
        ]
        for pat in dynamic_iframe_patterns:
            if re.search(pat, txt):
                count += 1
        return count
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 27
    def sensitive_forms(self) -> int:
        sensitive_keywords = ["password", "username", "user", "pass", "cardnumber", "creditcard", "card", "cvv", "cvc", "ssn", 
                              "socialsecurity", "ip","victim","ipaddress", "useragent", "browser" ,"id", "__csrf", "captchaKey"]
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
                        cre = datetime.strptime(cre, '%Y-%m-%d')
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
            for qtype in ('A', 'AAAA', 'MX', 'NS'):
                try:
                    answers = dns.resolver.resolve(self.domain, qtype, lifetime=5)
                    total += len(answers)
                except Exception:
                    continue
        except Exception:
            pass
        return total
    # Explanation of DNS Record Types:
    # A = Maps the IPV4 Record
    # AAAA =  Maps the IPV6 Record
    # MX - Maps the Mail Exchange Records
    # NS - Name Server Records
# ------------------------------------------------------------------------------------------------------------------------------------------ #

    # 30
    def traffic_rank(self) -> int:
        try:
            if os.path.exists(TRANC0_LOCAL):
                with open(TRANC0_LOCAL, 'r', encoding='utf-8') as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if not line:
                            continue
                        if ',' in line:
                            parts = [p.strip() for p in line.split(',')]
                            dom = normalize_domain(parts[-1])
                            if dom == self.domain:
                                return i + 1
                        else:
                            if normalize_domain(line) == self.domain:
                                return i + 1
            url = 'https://tranco-list.eu/top-1m.csv'
            r = safe_requests_get(url)
            if r and r.status_code == 200:
                for line in r.text.splitlines():
                    parts = line.split(',')
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
            tokens = ['privacy', 'whoisguard', 'domainsbyproxy', 'redacted', 'protected', 'anonymous',
                      'clienthold', 'clienttransferprohibited', 'pendingdelete', 'gmail.com', 'yahoo.com',
                      'hotmail.com', 'po box', 'p.o. box', 'xn--', 'domainsbyproxy.com', 'privacyprotect.org']
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
        result['ip_in_url'] = int(self.ip_in_url())
        result['url_length'] = int(self.url_length())
        result['url_shortening'] = int(self.url_shortening())
        result['presence_at'] = int(self.presence_at())
        result['redirection_symbol'] = int(self.redirection_symbol())
        
        result['hyphen_in_domain'] = int(self.hyphen_in_domain())
        result['too_many_subdomains'] = int(self.too_many_subdomains())
        result['https_in_string'] = int(self.https_in_string())
        result['ssl_tls_validity'] = int(self.ssl_tls_validity())
        result['domain_registration_length'] = int(self.domain_registration_length())
        
        result['non_standard_ports'] = int(self.non_standard_ports())
        result['external_favicon'] = int(self.external_favicon())
        result['count_dots'] = int(self.count_dots())
        result['suspicious_chars'] = int(self.suspicious_chars())
        result['known_logo'] = int(self.known_logo())
        
        result['use_script'] = int(self.use_script())
        result['count_third_party_domains'] = int(self.count_third_party_domains())
        result['use_meta'] = int(self.use_meta())
        result['script_external_ratio'] = int(self.script_external_ratio())
        result['use_form'] = int(self.use_form())
        
        result['mailto'] = int(self.mailto())
        result['website_forwarding'] = int(self.website_forwarding())
        result['status_bar_customization'] = int(self.status_bar())
        result['right_click_disabled'] = int(self.right_click_disabled())
        result['popups'] = int(self.popups())
        
        result['iframes'] = int(self.iframes())
        result['sensitive_forms'] = int(self.sensitive_forms())
        result['domain_age'] = int(self.domain_age())
        result['dns_record_count'] = int(self.dns_record())
        result['website_traffic_rank'] = int(self.traffic_rank())
        
        result['page_ranking'] = int(self.page_ranking())
        result['google_index'] = int(self.google_index())
        result['backlinks'] = int(self.backlinks())
        result['blacklist'] = int(self.blacklist())
        result['whois_suspicious_tokens'] = int(self.whois_suspicious_tokens())

        return result
# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Single URL worker using full extractor
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class SingleURLWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)
    progress = Signal(int)

    def __init__(self, url, model_path=None, model_features=None, parent=None):
        super().__init__(parent)
        self.url = url
        self.model_path = model_path
        self.model_features = model_features

    def run(self):
        try:
            self.progress.emit(5)
            ext = PhishingFeatureExtractor(url=self.url)
            feats = ext.extract_all()
            feats['input'] = self.url
            self.progress.emit(40)

            if not self.model_path or not os.path.exists(self.model_path):
                self.finished.emit({'features': feats, 'prediction': None, 'explain': 'No model loaded'})
                return

            bundle = joblib.load(self.model_path)
            model = bundle.get('model')
            scaler = bundle.get('scaler')
            feature_list = self.model_features if self.model_features else bundle.get('features', [])

            # Normalize feature_list to a plain Python list (handle numpy arrays, pandas Index, etc.)
            try:
                # convert numpy arrays / pandas Index to list
                if hasattr(feature_list, 'tolist') and not isinstance(feature_list, list):
                    feature_list = feature_list.tolist()
                # pandas Index may not have tolist in some versions, try casting
                if 'pandas' in sys.modules and hasattr(sys.modules['pandas'], 'Index') and isinstance(feature_list, sys.modules['pandas'].Index):
                    feature_list = list(feature_list)
            except Exception:
                # best-effort conversion; fall back to wrapping single string
                pass

            if isinstance(feature_list, str):
                feature_list = [feature_list]

            # Ensure feature_list is a list and remove duplicates while preserving order
            try:
                seen = set()
                cleaned = []
                for f in list(feature_list):
                    if f not in seen:
                        cleaned.append(f)
                        seen.add(f)
                feature_list = cleaned
            except Exception:
                # If anything unexpected, coerce to plain list
                feature_list = list(feature_list) if hasattr(feature_list, '__iter__') else [feature_list]

            # Build feature vector in the model's expected order
            X = [feats.get(f, 0) for f in feature_list]
            X_arr = np.array(X).reshape(1, -1)

            # Debugging output (comment out after testing)
            print("[DEBUG][Worker] feature_list:", feature_list)
            print("[DEBUG][Worker] X_arr raw:", X_arr.tolist())

            # Verify feature count matches model expectation
            if hasattr(model, 'n_features_in_') and X_arr.shape[1] != model.n_features_in_:
                # Provide clearer debug info to help diagnose mismatches
                print(f"[DEBUG][Worker] MISMATCH: built {X_arr.shape[1]} features but model expects {model.n_features_in_}")
                print("[DEBUG][Worker] final feature_list:", feature_list)
                print("[DEBUG][Worker] feats keys:", sorted(list(feats.keys())))
                self.error.emit(f'Input has {X_arr.shape[1]} features, but model expects {model.n_features_in_} features.\nPlease verify the model feature list and that features are not duplicated.')
                return

            # Apply scaler only for models that require it (e.g., GaussianNB). For tree-based models, use raw X.
            name = type(model).__name__.lower()
            feed = X_arr
            if scaler is not None and 'gaussiannb' in name:
                try:
                    feed = scaler.transform(X_arr)
                except Exception as e:
                    print("[DEBUG][Worker] scaler.transform failed:", e)
                    feed = X_arr

            print("[DEBUG][Worker] feed (post-scale):", feed.tolist())

            # Predict
            pred = int(model.predict(feed)[0])
            prob = None
            try:
                probs = model.predict_proba(feed)
                # if binary, second column is phishing probability
                prob = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())
            except Exception as e:
                print("[DEBUG][Worker] predict_proba error:", e)
                prob = None

            # Build explanation if available
            explanation = []
            try:
                if hasattr(model, 'feature_importances_'):
                    importances = np.array(model.feature_importances_)
                    idxs = np.argsort(importances)[::-1][:10]  # Top 10 features
                    for i in idxs:
                        explanation.append({'feature': feature_list[i], 'importance': float(importances[i]), 'value': feats.get(feature_list[i])})
            except Exception:
                pass

            self.progress.emit(100)
            self.finished.emit({'features': feats, 'prediction': pred, 'probability': prob, 'explain': explanation})
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f'Extraction/prediction error: {e}\n{tb}')

# ------------------------------------------------------------------------------------------------------------------------------------------ #
class AnimatedButton(QPushButton):
    def __init__(self, icon_file, parent=None):
        super().__init__(parent)
        self.setIcon(QIcon(icon_file))
        self.setIconSize(QSize(220, 220))
        self.setFixedSize(260, 260)
        self.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 30);
                border-radius: 20px;
            }
        """)
        self.anim = QPropertyAnimation(self, b"iconSize")
        self.anim.setDuration(200)
        self.anim.setEasingCurve(QEasingCurve.OutQuad)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def enterEvent(self, event):
        self.anim.stop()
        self.anim.setStartValue(self.iconSize())
        self.anim.setEndValue(QSize(240, 240))
        self.anim.start()
        super().enterEvent(event)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def leaveEvent(self, event):
        self.anim.stop()
        self.anim.setStartValue(self.iconSize())
        self.anim.setEndValue(QSize(220, 220))
        self.anim.start()
        super().leaveEvent(event)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class MainWindow(QMainWindow):
        # User-adjustable minimum threshold for phishing probability

    def open_feature_extractor(self):
        try:
            subprocess.Popen([sys.executable, 
                            os.path.join(os.path.dirname(__file__), 'DD_FEATURE_EXTRACTOR_10_04_2025.py')],
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open Feature Extractor: {str(e)}")

    def open_model_training(self):
        try:
            subprocess.Popen([sys.executable, 
                            os.path.join(os.path.dirname(__file__), 'DD_MODEL_TRAINING_10_04_2025.py')],
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open Model Training: {str(e)}")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cybersecurity Suite - For Phishing, Malware and Ransomware - Designed by: Osias Nieva Jr.")
        self.resize(1400, 900)  # Increased window size
        self.model_path = None
        self._build_ui()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _build_ui(self):                                                    # MMDC LOGO, TITLE, VERSION, MY LOGO @ TOP LEFT
        central = QWidget()
        self.setCentralWidget(central)
        
        # Create main layout
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
        # --- Top bar with MMDC logo and TITLE ---
        top_bar = QHBoxLayout()
        mmdc_logo = QLabel()
        mmdc_logo.setPixmap(QIcon("mmdc.png").pixmap(250, 80))              # MMDC LOGO IMAGE
        mmdc_logo.setScaledContents(True)
        top_bar.addWidget(mmdc_logo, alignment=Qt.AlignLeft)
# ------------------------------------------------------------------------------------------------------------------------------------------ #

        # TITLE centered next to logo                                       # Top CENTER TITLE TEXT
        title_label = QLabel(
            "TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits\n"
            "for Machine Learning-Based Detection\n"
            "A Case Study Using BlackEye, Hiddeneye and Zphisher and Other Phishing Sites"
        )
        title_label.setFont(QFont("Arial", 15, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: white; margin-top: 10px; margin-bottom: 10px;")
        top_bar.addWidget(title_label, stretch=2)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
        # Right-side logos
        right_layout = QVBoxLayout()
        logo_row = QHBoxLayout()
        logo_row.addStretch(1)
        my_logo = QLabel()
        my_logo.setPixmap(QIcon("ods.png").pixmap(50, 50))
        my_logo.setScaledContents(True)
        logo_row.addWidget(my_logo, alignment=Qt.AlignCenter)
        logo_row.addStretch(1)
        version_label = QLabel("Version 1.1 - Nov 3, 2025")          # VERSION TEXT AT TOP RIGHT
        version_label.setFont(QFont("Arial", 10, QFont.Bold))
        version_label.setStyleSheet("color: white; margin: 10px;")
        version_label.setAlignment(Qt.AlignRight)
        right_layout.addLayout(logo_row)
        right_layout.addWidget(version_label)
        top_bar.addLayout(right_layout)
        main_layout.addLayout(top_bar)

        # ------------------------------------------------------- Main stack -------------------------------------------------------- # 
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, stretch=1)

        # ------------------------------------------------------- 3 Icon page ------------------------------------------------------- # 
        cards_page = QWidget()
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(25)
        cards_layout.addStretch(2)
        cards_layout.addLayout(self.create_app_card("malware.png", "Signature Based Malware Detector \n (Future App)", lambda: self.stack.setCurrentWidget(self.page_malware)))
        cards_layout.addLayout(self.create_app_card("phish.png", "Signature-Based Phishing Detector \n (ACTUAL CAPSTONE APP)", lambda: self.stack.setCurrentWidget(self.page_phish)))
        cards_layout.addLayout(self.create_app_card("ransom.png", "Signature-Based Ransomware Detector \n (Future App)", lambda: self.stack.setCurrentWidget(self.page_ransom)))
        cards_layout.addStretch(2)
        cards_page.setLayout(cards_layout)

        # ------------------------------------------------------- Disclaimer ------------------------------------------------------- #
        bottom_text2 = QLabel(
            "Application Designed by: Osias Nieva Jr. for MMDC-Capstone 2_2025-2026\n email: lr.onieva@mmdc.mcl.edu.ph"
        )
        bottom_text2.setFont(QFont("Arial", 9,QFont.Bold))
        bottom_text2.setAlignment(Qt.AlignCenter)
        bottom_text2.setStyleSheet("color: white; margin-top: 30px;")
        disclaimer = QLabel(
            ("This application is an exclusive property of Mapua-Malayan Digital College and is protected under Republic Act No. 8293,"
                "otherwise known as the Intellectual Property Code of the Philippines. Unauthorized reproduction,\n"
                "distribution, or use of this software, in whole or in part, is strictly prohibited and may result in civil and criminal liabilities."
                "For permissions or inquiries, please contact MMDC-ISD at isd@mmdc.mcl.edu.ph."))
        disclaimer.setFont(QFont("Arial", 8))
        disclaimer.setAlignment(Qt.AlignCenter)
        disclaimer.setStyleSheet("color: white; margin-top: 10px; margin-bottom: 5px;")

        main_layout.addWidget(bottom_text2)
        main_layout.addWidget(disclaimer, alignment=Qt.AlignCenter)

        # --- Pages ---
        self.page_phish = self._make_phishing_page()
        self.page_ransom = self._make_stub_page('Ransomware Detector', 'Ransomware detection not implemented yet.')
        self.page_malware = self._make_stub_page('Malware Detector', 'Malware detection not implemented yet.')

        self.stack.addWidget(cards_page)
        self.stack.addWidget(self.page_phish)
        self.stack.addWidget(self.page_ransom)
        self.stack.addWidget(self.page_malware)

        self.status = QLabel('Ready')
        main_layout.addWidget(self.status)

        # --- Set background color ---
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(0, 150, 175))
        self.setAutoFillBackground(True)
        self.setPalette(palette)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def create_app_card(self, icon_file, tagline, callback):
        card = QVBoxLayout()
        card.setSpacing(4)
        card.addSpacerItem(QSpacerItem(150, 150, QSizePolicy.Minimum, QSizePolicy.Expanding))
        button = AnimatedButton(icon_file)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setXOffset(3)
        shadow.setYOffset(3)
        shadow.setColor(QColor(0, 0, 0, 160))
        button.setGraphicsEffect(shadow)
        button.clicked.connect(callback)
        tagline_label = QLabel(tagline)
        tagline_label.setFont(QFont("Arial", 11, QFont.Bold))
        tagline_label.setAlignment(Qt.AlignCenter)
        tagline_label.setStyleSheet("color: white;")
        card.addWidget(button, alignment=Qt.AlignCenter)
        card.addWidget(tagline_label)
        card.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        return card
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _make_stub_page(self, title, message):
        w = QWidget()
        v = QVBoxLayout()
        w.setLayout(v)
        lbl = QLabel(f'<h2>{title}</h2>')
        v.addWidget(lbl)
        txt = QLabel(message)
        txt.setWordWrap(True)
        v.addWidget(txt)
        back = QPushButton('Back to Hub')
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        v.addStretch()
        v.addWidget(back)
        return w
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _make_phishing_page(self):
        # Ensure attribute exists
        if not hasattr(self, "custom_phishing_threshold"):
            self.custom_phishing_threshold = 0.65

        w = QWidget()
        main_h = QHBoxLayout(w)

        # --- Left: Sidebar for controls ---
        sidebar = QVBoxLayout()
        sidebar.setAlignment(Qt.AlignTop)

        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setStyleSheet("background-color: #e0f7fa; border-radius: 12px;")

        title = QLabel("Phishing Detector")
        title.setAlignment(Qt.AlignLeft)
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: #00796b; margin-top: 10px; margin-bottom: 18px;")
        sidebar.addWidget(title, alignment=Qt.AlignLeft)

        # Define button styles first
        btn_style = """
            QPushButton {
                background: transparent;
                color: #00796b;
                border: 1px solid #00796b;
                border-radius: 8px;
                padding: 4px 10px;
                min-width: 120px;
                max-width: 140px;
            }
            QPushButton:hover {
                background: #b2dfdb;
                color: black;
            }
        """

        controls_label = QLabel("Model Controls")
        controls_label.setFont(QFont("Arial", 13, QFont.Bold))
        controls_label.setStyleSheet("color: #00796b; margin-bottom: 10px; margin-top: 10px;")
        sidebar.addWidget(controls_label, alignment=Qt.AlignHCenter)

        # Model Status Section
        self.model_status = QLabel("No model loaded")
        self.model_status.setFont(QFont("Arial", 10))
        self.model_status.setStyleSheet("color: #004d40; margin-bottom: 10px; padding: 5px; background-color: #b2dfdb; border-radius: 5px;")
        self.model_status.setWordWrap(True)
        self.model_status.setAlignment(Qt.AlignCenter)
        sidebar.addWidget(self.model_status, alignment=Qt.AlignHCenter)

        # Add Feature Extractor and Model Training buttons here inside Model Controls
        btn_feature_extractor = QPushButton("Feature Extractor")
        btn_feature_extractor.setStyleSheet(btn_style)
        btn_feature_extractor.clicked.connect(self.open_feature_extractor)
        sidebar.addWidget(btn_feature_extractor, alignment=Qt.AlignHCenter)
        
        btn_model_training = QPushButton("Model Training")
        btn_model_training.setStyleSheet(btn_style)
        btn_model_training.clicked.connect(self.open_model_training)
        sidebar.addWidget(btn_model_training, alignment=Qt.AlignHCenter)

        # Add a separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("background-color: #b2dfdb;")
        sidebar.addWidget(separator)

        # Note about threshold
        threshold_note = QLabel("Using balanced threshold (0.5) with SMOTE")
        threshold_note.setFont(QFont("Arial", 9))
        threshold_note.setStyleSheet("color: #004d40; margin: 10px; font-style: italic;")
        threshold_note.setWordWrap(True)
        threshold_note.setAlignment(Qt.AlignCenter)
        sidebar.addWidget(threshold_note)

        btn_load_csv = QPushButton('Load Features CSV')
        btn_load_csv.setStyleSheet(btn_style)
        btn_load_csv.clicked.connect(getattr(self, "_phish_load_csv", lambda: None))
        sidebar.addWidget(btn_load_csv, alignment=Qt.AlignHCenter)

        btn_train = QPushButton('Train Models')
        btn_train.setStyleSheet(btn_style)
        btn_train.clicked.connect(getattr(self, "_phish_train", lambda: None))
        sidebar.addWidget(btn_train, alignment=Qt.AlignHCenter)

        btn_load_model = QPushButton('Load Model')
        btn_load_model.setStyleSheet(btn_style)
        btn_load_model.clicked.connect(getattr(self, "_phish_load_model", lambda: None))
        sidebar.addWidget(btn_load_model, alignment=Qt.AlignHCenter)

        btn_predict_csv = QPushButton('Predict on CSV')
        btn_predict_csv.setStyleSheet(btn_style)
        btn_predict_csv.clicked.connect(getattr(self, "_phish_predict_csv", lambda: None))
        sidebar.addWidget(btn_predict_csv, alignment=Qt.AlignHCenter)

        sidebar.addStretch(1)

        output_label = QLabel("Detection Output")
        output_label.setFont(QFont("Arial", 15, QFont.Bold))
        output_label.setStyleSheet("color: #00796b; margin-bottom: 10px;")
        sidebar.addWidget(output_label, alignment=Qt.AlignHCenter)

        self.icon_label = QLabel('')
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet('font-size: 48px;')
        sidebar.addWidget(self.icon_label, alignment=Qt.AlignHCenter)

        self.prob_label = QLabel('')
        self.prob_label.setAlignment(Qt.AlignCenter)
        self.prob_label.setFont(QFont("Arial", 13, QFont.Bold))
        sidebar.addWidget(self.prob_label, alignment=Qt.AlignHCenter)

        main_h.addWidget(sidebar_widget, 2)

        # --- Right: Main content ---
        right_v = QVBoxLayout()
        right_v.setAlignment(Qt.AlignTop)

        top_bar = QHBoxLayout()
        top_bar.addStretch(1)
        back_btn = QPushButton()
        back_btn.setIcon(QIcon.fromTheme("go-previous"))
        back_btn.setFixedSize(32, 32)
        back_btn.setStyleSheet("""
            QPushButton {
                background: white;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #e0e0e0;
            }
        """)

        # safe connect: only call stack switch if stack exists
        if hasattr(self, "stack") and getattr(self, "stack") is not None:
            back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        else:
            back_btn.clicked.connect(lambda: None)

        top_bar.addWidget(back_btn)
        right_v.addLayout(top_bar)

        single_group = QGroupBox('Single-URL Prediction')
        sg = QHBoxLayout(single_group)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('Enter full URL, e.g. https://example.com/login')
        self.url_input.setMinimumWidth(300)
        sg.addWidget(self.url_input)

        small_btn_style = """
            QPushButton {
                background: #00796b;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 2px 10px;
                min-width: 80px;
                max-width: 90px;
                font-size: 12px;
            }
            QPushButton:hover {
                background: #009688;
                color: #fff;
            }
        """
        btn_extract = QPushButton('Extract & Predict')
        btn_extract.setStyleSheet(small_btn_style)
        btn_extract.clicked.connect(getattr(self, "_phish_single_url", lambda: None))
        sg.addWidget(btn_extract)

        btn_stop = QPushButton('Stop')
        btn_stop.setStyleSheet(small_btn_style)
        btn_stop.clicked.connect(getattr(self, "_phish_stop", lambda: None))
        sg.addWidget(btn_stop)

        btn_clear = QPushButton('Clear')
        btn_clear.setStyleSheet(small_btn_style)
        btn_clear.clicked.connect(getattr(self, "_phish_clear", lambda: None))
        sg.addWidget(btn_clear)

        right_v.addWidget(single_group, alignment=Qt.AlignLeft)

        # Features table + explainability
        result_h = QHBoxLayout()
        mid_box = QVBoxLayout()
        features_label = QLabel('Extracted features')
        features_label.setFont(QFont("Arial", 12, QFont.Bold))
        mid_box.addWidget(features_label, alignment=Qt.AlignLeft)

        # Features table
        self.features_table = QTableWidget(0, 3)
        self.features_table.setHorizontalHeaderLabels(['Feature', 'Value', 'Explanation'])
        self.features_table.setMinimumWidth(400)
        self.features_table.setMinimumHeight(350)
        mid_box.addWidget(self.features_table)
        
        result_h.addLayout(mid_box, 4)
        right_box = QVBoxLayout()
        explain_label = QLabel('Explainability (top features)')
        explain_label.setFont(QFont("Arial", 12, QFont.Bold))
        right_box.addWidget(explain_label, alignment=Qt.AlignLeft)
        self.explain_text = QTextEdit()
        self.explain_text.setReadOnly(True)
        self.explain_text.setMinimumWidth(300)
        self.explain_text.setMinimumHeight(350)
        right_box.addWidget(self.explain_text)
        result_h.addLayout(right_box, 3)

        right_v.addLayout(result_h)

        self.phish_progress = QProgressBar()
        right_v.addWidget(self.phish_progress)
        self.phish_status = QLabel('')
        right_v.addWidget(self.phish_status)

        # Export buttons in horizontal layout aligned to right
        export_box = QHBoxLayout()
        export_box.addStretch()  # Push buttons to the right
        
        export_label = QLabel("Export Options:")
        export_label.setFont(QFont("Arial", 10, QFont.Bold))
        export_label.setStyleSheet("color: #00796b;")
        export_box.addWidget(export_label)
        
        btn_export_csv = QPushButton("Export CSV")
        btn_export_csv.setStyleSheet(small_btn_style)
        btn_export_csv.clicked.connect(self._export_csv)
        export_box.addWidget(btn_export_csv)
        
        btn_export_json = QPushButton("Export JSON")
        btn_export_json.setStyleSheet(small_btn_style)
        btn_export_json.clicked.connect(self._export_json)
        export_box.addWidget(btn_export_json)
        
        btn_export_txt = QPushButton("Export Report")
        btn_export_txt.setStyleSheet(small_btn_style)
        btn_export_txt.clicked.connect(self._export_txt)
        export_box.addWidget(btn_export_txt)
        
        btn_print = QPushButton("Print Report")
        btn_print.setStyleSheet(small_btn_style)
        btn_print.clicked.connect(self._print_report)
        export_box.addWidget(btn_print)

        right_v.addLayout(export_box)
        
        main_h.addLayout(right_v, 8)

        return w

# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # --- Phishing callbacks (same as your original code) ---
    def _phish_load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open features CSV', '', 'CSV Files (*.csv);;All Files (*)')
        if not path:
            return
        self.phish_features_csv = path
        self.phish_status.setText(f'Loaded CSV: {os.path.basename(path)}')
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _phish_train(self):
        if not hasattr(self, 'phish_features_csv'):
            QMessageBox.information(self, 'Need CSV', 'Please load a features CSV first.')
            return
        out_path, _ = QFileDialog.getSaveFileName(self, 'Save model as', 'best_phishing_model.pkl', 'Pickle Files (*.pkl);;All Files (*)')
        if not out_path:
            return
        self.phish_status.setText('Training started...')
        self.phish_progress.setValue(0)
        def train_job():
            try:
                df = pd.read_csv(self.phish_features_csv, encoding='utf-8')
                label_col = next((c for c in ['label','Label','y'] if c in df.columns), None)
                if label_col is None:
                    raise ValueError('No label column found in CSV')
                df[label_col] = pd.to_numeric(df[label_col], errors='coerce')
                df = df.dropna(subset=[label_col])
                df[label_col] = df[label_col].astype(int)
                numeric = df.select_dtypes(include=[np.number]).copy()
                if label_col not in numeric.columns:
                    numeric[label_col] = df[label_col]
                numeric = numeric.loc[:, numeric.nunique() > 1]
                X = numeric.drop(columns=[label_col])
                y = numeric[label_col]
                X = X.fillna(X.median())
                from sklearn.model_selection import train_test_split
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
                if IMBLEARN_AVAILABLE:
                    sm = SMOTE(random_state=42)
                    X_train_bal, y_train_bal = sm.fit_resample(X_train, y_train)
                else:
                    X_train_bal, y_train_bal = X_train, y_train
                scaler = StandardScaler()
                X_train_s = scaler.fit_transform(X_train_bal)
                X_test_s = scaler.transform(X_test)
                rf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
                dt = DecisionTreeClassifier(random_state=42, class_weight='balanced')
                nb = GaussianNB()
                voting = VotingClassifier([('rf', rf), ('dt', dt)], voting='hard')

                models = {
                    'RandomForest': (rf, X_train_bal, X_test),
                    'DecisionTree': (dt, X_train_bal, X_test),
                    'NaiveBayes': (nb, X_train_s, X_test_s),
                    'VotingTrees': (voting, X_train_bal, X_test)
                }
                results = {}
                total = len(models)
                i = 0

                for name, (model, Xt_train, Xt_test) in models.items():
                    i += 1
                    self.phish_progress.setValue(10 + int(70 * (i/total)))
                    model.fit(Xt_train, y_train_bal if name != 'NaiveBayes' else y_train_bal)
                    y_pred = model.predict(Xt_test)
                    try:
                        y_proba = model.predict_proba(Xt_test)[:,1]
                    except Exception:
                        y_proba = None
                    metrics = {
                        'accuracy': float(accuracy_score(y_test, y_pred)),
                        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
                        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
                        'f1': float(f1_score(y_test, y_pred, zero_division=0)),
                        'roc_auc': float(roc_auc_score(y_test, y_proba)) if y_proba is not None else None
                    }
                    results[name] = metrics
                best = max(results.keys(), key=lambda k: results[k]['f1'])
                best_model = models[best][0]
                bundle = {'model': best_model, 'scaler': scaler, 'features': list(X.columns), 'label_col': label_col}
                joblib.dump(bundle, out_path)
                self.model_path = out_path
                self.phish_progress.setValue(100)
                self.phish_status.setText(f'Training finished. Best: {best}. Model saved to {out_path}')
            except Exception as e:
                self.phish_status.setText(f'Training failed: {e}')
                traceback.print_exc()
        t = threading.Thread(target=train_job, daemon=True)
        t.start()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _phish_load_model(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Load model', '', 'Pickle Files (*.pkl *.joblib);;All Files (*)')
        if not path:
            return
        try:
            print("[DEBUG] Loading model from:", path)
            bundle = joblib.load(path)
            if not isinstance(bundle, dict) or 'model' not in bundle:
                QMessageBox.warning(self, 'Bad model', "Loaded file doesn't contain expected model bundle")
                return
            self.model_path = path
            # Use the feature list from the saved model bundle if present
            # Normalize to a plain list to avoid pandas/ndarray surprises later
            raw_feats = bundle.get('features', None)
            if raw_feats is None:
                self.model_features = []
            else:
                try:
                    if hasattr(raw_feats, 'tolist') and not isinstance(raw_feats, list):
                        self.model_features = raw_feats.tolist()
                    else:
                        self.model_features = list(raw_feats) if not isinstance(raw_feats, list) else raw_feats
                except Exception:
                    # fallback
                    self.model_features = list(raw_feats) if hasattr(raw_feats, '__iter__') else [raw_feats]
            self.loaded_model = bundle.get('model', None)
            # Update both debug output and UI
            model_type = type(self.loaded_model).__name__
            num_features = len(self.model_features) if self.model_features else 0
            print("[DEBUG] Loaded model info:")
            print("- Model type:", model_type)
            print("- Number of model features:", num_features)
            print("- Feature list:", self.model_features)
            # Update model status in UI
            model_info = f"Model: {model_type}\nFeatures: {num_features}"
            self.model_status.setText(model_info)
            self.model_status.setStyleSheet("color: #004d40; padding: 5px; background-color: #b2dfdb; border-radius: 5px;")
            if self.model_features is None:
                QMessageBox.warning(self, 'Model missing features', 'Loaded model does not contain a feature list. Please retrain and save model with feature list.')
                self.model_features = []
            self.phish_status.setText(f'Loaded model: {os.path.basename(path)}')
        except Exception as e:
            QMessageBox.critical(self, 'Load error', f'Failed to load: {e}')
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _phish_predict_csv(self):
        if not self.model_path:
            QMessageBox.information(self, 'No model', 'Load or train a model first.')
            return
        inpath, _ = QFileDialog.getOpenFileName(self, 'CSV to predict', '', 'CSV Files (*.csv);;All Files (*)')
        if not inpath:
            return
        outpath, _ = QFileDialog.getSaveFileName(self, 'Save predictions as', 'predictions.csv', 'CSV Files (*.csv);;All Files (*)')
        if not outpath:
            return
        try:
            bundle = joblib.load(self.model_path)
            model = bundle['model']
            scaler = bundle.get('scaler')
            features = bundle.get('features')
            df_new = pd.read_csv(inpath, encoding='utf-8')
            new_num = df_new.select_dtypes(include=[np.number]).copy()
            for col in features:
                if col not in new_num.columns:
                    new_num[col] = np.nan
            new_num = new_num[features].fillna(new_num.median())
            X = new_num.values
            if scaler is not None:
                try:
                    Xs = scaler.transform(X)
                except Exception:
                    Xs = X
            else:
                Xs = X
            name = model.__class__.__name__.lower()
            feed = Xs if 'gaussiannb' in name else X
            preds = model.predict(feed)
            df_out = df_new.copy()
            df_out['predicted_label'] = preds
            df_out.to_csv(outpath, index=False)
            QMessageBox.information(self, 'Saved', f'Predictions saved to {outpath}')
        except Exception as e:
            QMessageBox.critical(self, 'Predict error', f"{e}\n{traceback.format_exc()}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _phish_single_url(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, "No URL", "Enter a URL first.")
            return
        if not hasattr(self, 'model_features') or not self.model_features:
            QMessageBox.warning(self, "Model features missing", "Model feature list not loaded. Please load a valid model.")
            return
        print("[DEBUG] Starting single URL prediction")
        print("[DEBUG] Model features before worker:", self.model_features)
        
        self.worker = SingleURLWorker(url, model_path=self.model_path, model_features=self.model_features)
        self.worker.model_features = self.model_features
        
        # Connect debug message handler
        self.worker.progress.connect(lambda p: self.phish_progress.setValue(p))
        self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.worker.finished.connect(self._on_single_result)
        self.phish_status.setText("Extracting & predicting...")
        self.worker.start()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _on_single_result(self, out: dict):
        # Import feature groups from app.py
        features_35 = [
            "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
            "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
            "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
            "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
            "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization",
            "right_click_disabled", "popups", "iframes", "sensitive_forms", "domain_age", "dns_record_count",
            "website_traffic_rank", "page_ranking", "google_index", "backlinks", "blacklist", "whois_suspicious_tokens"
        ]
        
        # Feature explanations from app.py
        feature_explanations = {
            "ip_in_url": "Checks if the URL contains an IP address (common in phishing).",
            "url_length": "Long URLs are often used to obfuscate phishing attempts.",
            "url_shortening": "URL shorteners can hide the true destination (phishing tactic).",
            "presence_at": "The '@' symbol in URLs can redirect to malicious sites.",
            "redirection_symbol": "Multiple '//' in URL path may indicate redirection tricks.",
            "hyphen_in_domain": "Hyphens in domain names are more common in phishing sites.",
            "too_many_subdomains": "Excessive subdomains can mimic legitimate domains.",
            "https_in_string": "'https' in the path/query may be used to appear secure.",
            "ssl_tls_validity": "Checks if SSL/TLS is valid (phishing sites may lack it).",
            "domain_registration_length": "Short-lived domains are often used for phishing.",
            "non_standard_ports": "Non-standard ports can be suspicious.",
            "external_favicon": "External favicons may indicate phishing.",
            "count_dots": "Many dots in the URL can indicate obfuscation.",
            "suspicious_chars": "Suspicious characters (?, %, &, =, +) are often used in phishing URLs.",
            "known_logo": "Checks for known brand logos (may be abused by phishing).",
            "use_script": "Use of scripts can be used for malicious purposes.",
            "count_third_party_domains": "Many third-party domains can be suspicious.",
            "use_meta": "Meta tags can be abused for phishing.",
            "script_external_ratio": "High ratio of external scripts may be suspicious.",
            "use_form": "Phishing sites often use forms to steal data.",
            "mailto": "'mailto:' links can be used for phishing.",
            "website_forwarding": "Forwarding can hide the real destination.",
            "status_bar_customization": "Custom status bars can hide true links.",
            "right_click_disabled": "Disabling right-click can prevent inspection.",
            "popups": "Popups are often used in phishing.",
            "iframes": "Iframes can be used to load malicious content.",
            "sensitive_forms": "Sensitive forms are a phishing indicator.",
            "domain_age": "Young domains are more likely to be phishing.",
            "dns_record_count": "Low DNS record count can indicate a suspicious site.",
            "website_traffic_rank": "Low traffic rank may indicate a fake site.",
            "page_ranking": "Low page rank can be suspicious.",
            "google_index": "Not indexed by Google may indicate a new/suspicious site.",
            "backlinks": "Few backlinks may indicate a fake site.",
            "blacklist": "Blacklisted domains are phishing.",
            "whois_suspicious_tokens": "Suspicious WHOIS info can indicate phishing."
        }
        
        # Get features list from model if available
        model_features = getattr(self, 'model_features', None)
        feats = out.get('features', {})
        # Get features from output
        feats = out.get('features', {})
        pred = out.get('prediction')
        prob = out.get('probability')
        explain = out.get('explain')

        # Use model features if available, otherwise use all features
        feature_list = model_features if model_features else sorted(feats.keys())
        feats_filtered = {k: feats.get(k, 0) for k in feature_list}

        # Debug: print extracted features and prediction details
        print("[DEBUG] Extracted features:", feats_filtered)
        print(f"[DEBUG] Prediction: {pred}, Probability: {prob}, Explain: {explain}")

        # Populate features table with filtered features and their explanations
        self.features_table.setRowCount(0)
        self.features_table.setColumnCount(3)  # Add column for explanations
        self.features_table.setHorizontalHeaderLabels(['Feature', 'Value', 'Explanation'])
        
        for k in feature_list:
            v = feats_filtered.get(k, 0)
            r = self.features_table.rowCount()
            self.features_table.insertRow(r)
            self.features_table.setItem(r, 0, QTableWidgetItem(str(k)))
            self.features_table.setItem(r, 1, QTableWidgetItem(str(v)))
            self.features_table.setItem(r, 2, QTableWidgetItem(feature_explanations.get(k, "")))

        # Handle case when no model is loaded
        if pred is None:
            self.icon_label.setText('?')
            self.prob_label.setText('No model loaded — install or train one to get predictions.')
            self.explain_text.setPlainText(str(out.get('explain')))
            self.phish_status.setText('No model loaded')
            return

        # -------------------- Verdict Logic --------------------
        # Determine balanced threshold using model class weights if available
        class_weight = getattr(self.loaded_model, 'class_weight', None)
        balanced_threshold = 0.5
        if class_weight and isinstance(class_weight, dict):
            try:
                w0 = float(class_weight.get(0, 1))
                w1 = float(class_weight.get(1, 1))
                if (w0 + w1) != 0:
                    balanced_threshold = w1 / (w0 + w1)
            except Exception:
                # fallback to default if unexpected structure
                balanced_threshold = 0.5

        print(f"[DEBUG] Probability: {prob}, Balanced Threshold: {balanced_threshold}")

        # Use probability when available, otherwise fall back to predicted class
        if prob is not None:
            if prob >= balanced_threshold:
                verdict = "PHISHING"
                verdict_text = "PHISHING"
                verdict_icon = "❌"
            else:
                verdict = "LEGITIMATE"
                verdict_text = "LEGITIMATE"
                verdict_icon = "✔️"
        else:
            if pred == 1:
                verdict = "PHISHING"
                verdict_text = "PHISHING"
                verdict_icon = "❌"
            else:
                verdict = "LEGITIMATE"
                verdict_text = "LEGITIMATE"
                verdict_icon = "✔️"

        # Update the verdict display using the calculated verdict
        if verdict == "PHISHING":
            self.icon_label.setText(f'{verdict_icon} {verdict_text}')
            self.icon_label.setStyleSheet('color: red; font-size: 48px; font-weight: bold;')
        else:
            self.icon_label.setText(f'{verdict_icon} {verdict_text}')
            self.icon_label.setStyleSheet('color: green; font-size: 48px; font-weight: bold;')

        # Display probability and verdict (same format as app.py response)
        if prob is not None:
            self.prob_label.setText(f'<span style="font-size:24px;">Phishing Probability: <b>{prob:.3f}</b></span>')
        else:
            self.prob_label.setText('')

        # -------------------- Feature Importance and Summary Report --------------------
        summary = ["Summary Report (Top 10 Features):\n"]
        # Sort features by importance if available
        if explain:
            importance_dict = {e['feature']: e['importance'] for e in explain}
            features_sorted = sorted(features_35, key=lambda x: importance_dict.get(x, 0), reverse=True)
        else:
            features_sorted = features_35

        # Only show top 10 features
        top_features = features_sorted[:10]
        for feature in top_features:
            value = feats.get(feature, 0)
            importance = importance_dict.get(feature, 0) if explain else 0
            explanation = feature_explanations.get(feature, "")
            feature_line = f"{feature}:"
            if explain:
                feature_line += f" (importance: {importance:.4f})"
            feature_line += f"\n  Value: {value}"
            feature_line += f"\n  Explanation: {explanation}\n"
            summary.append(feature_line)

        # Add prediction confidence
        if prob is not None:
            confidence = prob if verdict == "PHISHING" else (1 - prob)
            summary.append(f"\nVerdict Confidence: {confidence:.2%}")

        # Add high-risk indicators (from top 10 only)
        high_risk_features = [f for f in top_features if feats.get(f, 0) > 0][:5]
        if high_risk_features:
            summary.append("\nTop Risk Indicators:")
            for f in high_risk_features:
                summary.append(f"- {f}: {feature_explanations.get(f, '')}")

        self.explain_text.setPlainText('\n'.join(summary))

        # Update status
        self.phish_status.setText(f'Done - {verdict_text}')

# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # --- Add these methods to MainWindow ---
    def _phish_stop(self):
        # Stop the worker thread if running
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
            self.phish_status.setText("Stopped.")
            self.phish_progress.setValue(0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _phish_clear(self):
        self.url_input.clear()
        self.icon_label.clear()
        self.prob_label.clear()
        self.features_table.setRowCount(0)
        self.explain_text.clear()
        self.phish_status.clear()
        self.phish_progress.setValue(0)
        
    def _export_csv(self):
        if self.features_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "Run a prediction first to generate data for export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export CSV', '', 'CSV Files (*.csv);;All Files (*)')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8', newline='') as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(['Feature', 'Value', 'Explanation'])
                for r in range(self.features_table.rowCount()):
                    row = []
                    for c in range(self.features_table.columnCount()):
                        item = self.features_table.item(r, c)
                        row.append(item.text() if item else '')
                    writer.writerow(row)
            self.phish_status.setText(f'Exported CSV to: {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Export Error', f'Failed to export CSV: {e}')

    def _export_json(self):
        if self.features_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "Run a prediction first to generate data for export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export JSON', '', 'JSON Files (*.json);;All Files (*)')
        if not path:
            return
        try:
            data = {
                'url': self.url_input.text().strip(),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'features': {},
                'prediction': getattr(self, 'last_prediction', None),
                'probability': getattr(self, 'last_probability', None),
                'verdict': getattr(self, 'last_verdict', None),
                'explanation': self.explain_text.toPlainText()
            }
            for r in range(self.features_table.rowCount()):
                feat = self.features_table.item(r, 0)
                val = self.features_table.item(r, 1)
                exp = self.features_table.item(r, 2)
                if feat and val:
                    data['features'][feat.text()] = {
                        'value': val.text(),
                        'explanation': exp.text() if exp else ''
                    }
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            self.phish_status.setText(f'Exported JSON to: {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Export Error', f'Failed to export JSON: {e}')

    def _export_txt(self):
        if self.features_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "Run a prediction first to generate data for export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export Report', '', 'Text Files (*.txt);;All Files (*)')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("Phishing Detection Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"URL: {self.url_input.text().strip()}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                verdict = getattr(self, 'last_verdict', 'Unknown')
                prob = getattr(self, 'last_probability', None)
                f.write(f"VERDICT: {verdict}\n")
                if prob is not None:
                    f.write(f"Probability: {prob:.3f}\n")
                f.write("\nFeature Analysis:\n")
                f.write("-" * 50 + "\n\n")
                
                for r in range(self.features_table.rowCount()):
                    feat = self.features_table.item(r, 0)
                    val = self.features_table.item(r, 1)
                    exp = self.features_table.item(r, 2)
                    if feat and val:
                        f.write(f"{feat.text()}:\n")
                        f.write(f"  Value: {val.text()}\n")
                        if exp and exp.text():
                            f.write(f"  Explanation: {exp.text()}\n")
                        f.write("\n")
                
                f.write("\nDetailed Analysis:\n")
                f.write("-" * 50 + "\n")
                f.write(self.explain_text.toPlainText())
            
            self.phish_status.setText(f'Exported report to: {path}')
        except Exception as e:
            QMessageBox.critical(self, 'Export Error', f'Failed to export report: {e}')

    def _print_report(self):
        if self.features_table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "Run a prediction first to generate a report.")
            return
        try:
            from PySide6.QtPrintSupport import QPrinter, QPrintDialog
            printer = QPrinter()
            dialog = QPrintDialog(printer, self)
            if dialog.exec() != QPrintDialog.Accepted:
                return
            
            # Create HTML report
            html = f"""
            <html>
            <body>
                <h1>Phishing Detection Report</h1>
                <p><b>URL:</b> {self.url_input.text().strip()}</p>
                <p><b>Date:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><b>VERDICT:</b> {getattr(self, 'last_verdict', 'Unknown')}</p>
                <p><b>Probability:</b> {getattr(self, 'last_probability', 'N/A')}</p>
                
                <h2>Feature Analysis</h2>
                <table border="1" cellpadding="4">
                    <tr><th>Feature</th><th>Value</th><th>Explanation</th></tr>
            """
            
            for r in range(self.features_table.rowCount()):
                feat = self.features_table.item(r, 0)
                val = self.features_table.item(r, 1)
                exp = self.features_table.item(r, 2)
                if feat and val:
                    html += f"<tr><td>{feat.text()}</td><td>{val.text()}</td><td>{exp.text() if exp else ''}</td></tr>"
            
            html += f"""
                </table>
                <h2>Detailed Analysis</h2>
                <pre>{self.explain_text.toPlainText()}</pre>
            </body>
            </html>
            """
            
            # Print using QTextDocument
            from PySide6.QtGui import QTextDocument
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print_(printer)
            
            self.phish_status.setText('Report sent to printer')
        except Exception as e:
            QMessageBox.critical(self, 'Print Error', f'Failed to print report: {e}')
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def main():
    # Ensure only one QApplication instance is created
    if not QApplication.instance():
        app = QApplication(sys.argv)
    else:
        app = QApplication.instance()
        
    win = MainWindow()
    win.show()
    if not IMBLEARN_AVAILABLE:
        QMessageBox.warning(win, 'Optional dependency missing', 'imbalanced-learn not installed. SMOTE will be unavailable.\nInstall with: pip install imbalanced-learn')
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

# ------------------------------------------------------------------------------------------------------------------------------------------ #