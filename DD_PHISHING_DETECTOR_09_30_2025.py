# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva 
import os
import sys
import json
import re
import traceback
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin

#PYSIDE6 Libraries
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QProgressBar, QMessageBox,
    QTableWidget, QTableWidgetItem, QLineEdit, QStackedWidget, QGridLayout,
    QSizePolicy, QGroupBox, QSpacerItem
)
from PySide6.QtCore import Qt, Signal, QThread, QSize, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QPalette, QColor, QIcon
from PySide6.QtWidgets import QGraphicsDropShadowEffect
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
REQUESTS_TIMEOUT = 10                                       # This line of code was used to set a timeout value (in seconds) for network requests made using the requests library to prevent hanging requests.
LOGO_HASH_FILE = os.getenv('LOGO_HASH_FILE', 'logo_hashes.json')
TRANC0_LOCAL = os.getenv('TRANCO_CSV_PATH', 'tranco.csv')

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
            return ''   # this code
        try:
            headers = {'User-Agent': 'PhishFeatureBot/1.0'}
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
            return r.text or '' 
        except Exception:
            return '' 
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    # 1
    def ip_in_url(self) -> int:
        if not self.url:
            return 0
        return 1 if re.match(r'^https?://\d{1,3}(?:\.\d{1,3}){3}', self.url) else 0

    # 2
    def url_length(self) -> int:
        return len(self.url) if self.url else 0

    # 3
    def url_shortening(self) -> int:
        if not self.domain:
            return 0
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly', 'rb.gy'}
        return 1 if any(s in self.domain for s in shorteners) else 0
    
    # Le Page, S., Jourdan, G.-V., v. Bochmann, G., Flood, J., & Onut, I.-V. (2018). Using URL Shorteners to Compare Phishing and Malware Attacks 
    # (Paper presented at eCrime Research 2018). Retrieved from https://docs.apwg.org/ecrimeresearch/2018/5351273.pdf

    # 4
    def presence_at(self) -> int:
        return (self.url.count('@') if self.url else 0)

    # 5
    def redirection_symbol(self) -> int:
        if not self.url:
            return 0
        total = self.url.count('//')
        return max(0, total - 1)

    # 6
    def hyphen_in_domain(self) -> int:
        return self.domain.count('-') if self.domain else 0

    # 7
    def too_many_subdomains(self) -> int:
        sub = self.ext.subdomain if self.ext else ''
        if not sub:
            return 0
        return sub.count('.') + 1

    # 8
    def https_in_string(self) -> int:
        if not self.url:
            return 0
        path_and_query = (self.parsed.path or '') + (self.parsed.query or '')
        return path_and_query.lower().count('https') + (self.html.lower().count('https') if self.html else 0)

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

    # 11
    def non_standard_ports(self) -> int:
        if not self.parsed:
            return 0
        port = self.parsed.port
        if port is None:
            return 0
        return 1 if port not in (80, 443) else 0

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

    # 13
    def count_dots(self) -> int:
        return self.url.count('.') if self.url else 0

    # 14
    def suspicious_chars(self) -> int:
        if not self.url:
            return 0
        return sum(self.url.count(c) for c in ['?', '%', '&', '=', '+'])

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

    # 16
    def use_script(self) -> int:
        return len(self.soup.find_all('script')) if self.soup else 0

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

    # 18
    def use_meta(self) -> int:
        return len(self.soup.find_all('meta')) if self.soup else 0

    # 19
    def script_external_ratio(self) -> int:
        if not self.soup:
            return 0
        scripts = self.soup.find_all('script')
        if not scripts:
            return 0
        ext = sum(1 for s in scripts if s.get('src'))
        return int((ext / len(scripts)) * 100)

    # 20
    def use_form(self) -> int:
        return len(self.soup.find_all('form')) if self.soup else 0

    # 21
    def mailto(self) -> int:
        if not self.html:
            return 0
        return self.html.lower().count('mailto:')

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

    # 23
    def status_bar(self) -> int:
        txt = (self.html or '').lower()
        return int(bool(re.search(r'window\.status|history\.replaceState|pushState\(|onbeforeunload', txt)))

    # 24
    def right_click_disabled(self) -> int:
        txt = (self.html or '').lower()
        if 'oncontextmenu="return false"' in txt or re.search(r"addEventListener\(['\"]contextmenu['\"],", txt):
            return 1
        return 0

    # 25
    def popups(self) -> int:
        txt = (self.html or '').lower()
        return len(re.findall(r'window\.open\(', txt))

    # 26
    def iframes(self) -> int:
        return len(self.soup.find_all('iframe')) if self.soup else 0

    # 27
    def sensitive_forms(self) -> int:
        sensitive_keywords = ['password', 'pass', 'cardnumber', 'creditcard', 'card', 'cvv', 'cvc', 'ssn', 'socialsecurity']
        txt = (self.html or '').lower()
        return sum(txt.count(k) for k in sensitive_keywords)

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

    # 31
    def page_ranking(self) -> int:
        return self.backlinks()

    # 32
    def google_index(self) -> int:
        GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
        GOOGLE_CX = os.getenv('GOOGLE_CX')
        if not GOOGLE_API_KEY or not GOOGLE_CX or not self.domain:
            return 0
        try:
            params = {'key': GOOGLE_API_KEY, 'cx': GOOGLE_CX, 'q': f"site:{self.domain}", 'num': 1}
            r = requests.get('https://www.googleapis.com/customsearch/v1', params=params, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return 0
            data = r.json()
            total = data.get('searchInformation', {}).get('totalResults')
            if total is None:
                return 0
            return int(total)
        except Exception:
            return 0

    # 33
    def backlinks(self) -> int:
        BING_API_KEY = os.getenv('BING_API_KEY')
        if not BING_API_KEY or not self.domain:
            return 0
        try:
            headers = {'Ocp-Apim-Subscription-Key': BING_API_KEY}
            params = {'q': f"link:{self.domain}", 'count': 50}
            r = requests.get('https://api.bing.microsoft.com/v7.0/search', headers=headers, params=params, timeout=REQUESTS_TIMEOUT)
            if r.status_code != 200:
                return 0
            data = r.json()
            results = data.get('webPages', {}).get('value', [])
            return len(results)
        except Exception:
            return 0

    # 34
    def blacklist(self) -> int:
        total_flags = 0
        VT_API_KEY = os.getenv('VT_API_KEY')
        GSB_API_KEY = os.getenv('GSB_API_KEY')
        if VT_API_KEY and self.domain:
            try:
                headers = {'x-apikey': VT_API_KEY}
                r = requests.get(f"https://www.virustotal.com/api/v3/domains/{self.domain}", headers=headers, timeout=REQUESTS_TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    total_flags += int(stats.get('malicious', 0)) + int(stats.get('suspicious', 0))
            except Exception:
                pass
        if GSB_API_KEY and self.url:
            try:
                gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
                body = {
                    'client': {'clientId': 'phishbot', 'clientVersion': '1.0'},
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': self.url}]
                    }
                }
                r = requests.post(gsb_url, json=body, timeout=REQUESTS_TIMEOUT)
                if r.status_code == 200 and r.text.strip():
                    data = r.json()
                    if data and data.get('matches'):
                        total_flags += len(data.get('matches'))
            except Exception:
                pass
        return total_flags

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

    def __init__(self, url, model_path=None, parent=None):
        super().__init__(parent)
        self.url = url
        self.model_path = model_path
        self.model_features = None

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
            feature_list = self.model_features if self.model_features else bundle.get('features')

            X = [feats.get(f, 0) for f in feature_list]
            X_arr = np.array(X).reshape(1, -1)
            # Check feature count
            if hasattr(model, 'n_features_in_') and X_arr.shape[1] != model.n_features_in_:
                self.error.emit(f'Input has {X_arr.shape[1]} features, but model expects {model.n_features_in_} features.')
                return
            feed = X_arr
            if scaler is not None:
                try:
                    feed = scaler.transform(X_arr)
                except Exception:
                    feed = X_arr

            pred = int(model.predict(feed)[0])
            try:
                prob = float(model.predict_proba(feed)[0][1])       # this line is for Phishing probability Calculation Area occurs
            except Exception:
                prob = None

            explanation = []
            try:
                if hasattr(model, 'feature_importances_'):
                    importances = np.array(model.feature_importances_)
                    idxs = np.argsort(importances)[::-1][:8]
                    for i in idxs:
                        explanation.append({'feature': feature_list[i], 'importance': float(importances[i]), 'value': feats.get(feature_list[i])})
            except Exception:
                pass

            self.progress.emit(100)
            self.finished.emit({'features': feats, 'prediction': pred, 'probability': prob, 'explain': explanation})
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f'Extraction/prediction error: {e}\\n{tb}')
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class SingleURLWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)
    progress = Signal(int)

    def __init__(self, url, model_path=None, parent=None):
        super().__init__(parent)
        self.url = url
        self.model_path = model_path
# ------------------------------------------------------------------------------------------------------------------------------------------ #
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
            feature_list = bundle.get('features')

            X = [feats.get(f, 0) for f in feature_list]
            X_arr = np.array(X).reshape(1, -1)
            feed = X_arr
            if scaler is not None:
                try:
                    feed = scaler.transform(X_arr)
                except Exception:
                    feed = X_arr

            pred = int(model.predict(feed)[0])
            try:
                prob = float(model.predict_proba(feed)[0][1])               # Phishing probability Calculation Area
            except Exception:
                prob = None

            explanation = []
            try:
                if hasattr(model, 'feature_importances_'):
                    importances = np.array(model.feature_importances_)
                    idxs = np.argsort(importances)[::-1][:8]
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

    def __init__(self):
        super().__init__()
        self.custom_phishing_threshold = 0.65  # Set to 0.65 for less aggressive phishing detection
        self.setWindowTitle("Cybersecurity Suite - For Phishing, Malware and Ransomware - Designed by: Osias Nieva Jr.")
        self.resize(1400, 900)  # Increased window size
        self.model_path = None
        self._build_ui()
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
        version_label = QLabel("Version 1.0")
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
        w = QWidget()
        main_h = QHBoxLayout()
        w.setLayout(main_h)

        # --- Left: Sidebar for controls ---
        sidebar = QVBoxLayout()
        sidebar.setAlignment(Qt.AlignTop)

        sidebar_widget = QWidget()
        sidebar_widget.setLayout(sidebar)
        sidebar_widget.setStyleSheet("background-color: #e0f7fa; border-radius: 12px;")

        # MAPUA MALAYAN LOGO
        # mmdc_logo = QLabel()
        # mmdc_logo.setPixmap(QIcon("mmdc.png").pixmap(120, 40))
        #mmdc_logo.setScaledContents(True)
        #sidebar.addWidget(mmdc_logo, alignment=Qt.AlignLeft)

        # Phishing Detector text below logo, left aligned
        title = QLabel("Phishing Detector")
        title.setAlignment(Qt.AlignLeft)
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: #00796b; margin-top: 10px; margin-bottom: 18px;")
        sidebar.addWidget(title, alignment=Qt.AlignLeft)

        # Model Controls label
        controls_label = QLabel("Model Controls")
        controls_label.setFont(QFont("Arial", 13, QFont.Bold))
        controls_label.setStyleSheet("color: #00796b; margin-bottom: 10px; margin-top: 10px;")
        sidebar.addWidget(controls_label, alignment=Qt.AlignHCenter)

        # Centered model control buttons
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

        btn_load_csv = QPushButton('Load Features CSV')                             # load Feature button
        btn_load_csv.setStyleSheet(btn_style)
        btn_load_csv.clicked.connect(self._phish_load_csv)
        sidebar.addWidget(btn_load_csv, alignment=Qt.AlignHCenter)

        btn_train = QPushButton('Train Models')                                     # Train model button
        btn_train.setStyleSheet(btn_style)
        btn_train.clicked.connect(self._phish_train)
        sidebar.addWidget(btn_train, alignment=Qt.AlignHCenter)

        btn_load_model = QPushButton('Load Model')                                 # load Feature button     
        btn_load_model.setStyleSheet(btn_style)
        btn_load_model.clicked.connect(self._phish_load_model)
        sidebar.addWidget(btn_load_model, alignment=Qt.AlignHCenter)

        btn_predict_csv = QPushButton('Predict on CSV')
        btn_predict_csv.setStyleSheet(btn_style)
        btn_predict_csv.clicked.connect(self._phish_predict_csv)
        sidebar.addWidget(btn_predict_csv, alignment=Qt.AlignHCenter)

        sidebar.addStretch(1)  # Push Detection Output to bottom

        # Detection Output at lower part
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

        # --- Right: Main content, aligned left ---
        right_v = QVBoxLayout()
        right_v.setAlignment(Qt.AlignTop)

        # Back button top right of main content
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
        back_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        top_bar.addWidget(back_btn)
        right_v.addLayout(top_bar)

        # Single URL Prediction Group, aligned left, smaller buttons, white text
        single_group = QGroupBox('Single-URL Prediction')
        sg = QHBoxLayout()
        single_group.setLayout(sg)
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
        btn_extract.clicked.connect(self._phish_single_url)
        sg.addWidget(btn_extract)
        btn_stop = QPushButton('Stop')
        btn_stop.setStyleSheet(small_btn_style)
        btn_stop.clicked.connect(self._phish_stop)
        sg.addWidget(btn_stop)
        btn_clear = QPushButton('Clear')
        btn_clear.setStyleSheet(small_btn_style)
        btn_clear.clicked.connect(self._phish_clear)
        sg.addWidget(btn_clear)
        right_v.addWidget(single_group, alignment=Qt.AlignLeft)

        # Features Table and Explainability, aligned left, increased size
        result_h = QHBoxLayout()
        mid_box = QVBoxLayout()
        features_label = QLabel('Extracted features')
        features_label.setFont(QFont("Arial", 12, QFont.Bold))
        mid_box.addWidget(features_label, alignment=Qt.AlignLeft)
        self.features_table = QTableWidget(0, 2)
        self.features_table.setHorizontalHeaderLabels(['feature', 'value'])
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
            bundle = joblib.load(path)
            if not isinstance(bundle, dict) or 'model' not in bundle:
                QMessageBox.warning(self, 'Bad model', "Loaded file doesn't contain expected model bundle")
                return
            self.model_path = path
            self.model_features = bundle.get('features', None)
            self.loaded_model = bundle.get('model', None)  # Store the loaded model for verdict logic
            if self.model_features is None:
                QMessageBox.warning(self, 'Model missing features', 'Loaded model does not contain feature list. Please retrain and save model with feature list.')
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
        self.worker = SingleURLWorker(url, model_path=self.model_path)
        self.worker.model_features = self.model_features
        self.worker.progress.connect(lambda p: self.phish_progress.setValue(p))
        self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.worker.finished.connect(self._on_single_result)
        self.phish_status.setText("Extracting & predicting...")
        self.worker.start()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def _on_single_result(self, out: dict):
        feats = out.get('features', {})
        pred = out.get('prediction')
        prob = out.get('probability')
        explain = out.get('explain')
        # Debug: print extracted features and prediction details
        print("[DEBUG] Extracted features:", feats)
        print(f"[DEBUG] Prediction: {pred}, Probability: {prob}, Explain: {explain}")
        self.features_table.setRowCount(0)
        for k, v in sorted(feats.items()):
            r = self.features_table.rowCount()
            self.features_table.insertRow(r)
            self.features_table.setItem(r, 0, QTableWidgetItem(str(k)))
            self.features_table.setItem(r, 1, QTableWidgetItem(str(v)))
        if pred is None:
            self.icon_label.setText('?')
            self.prob_label.setText('No model loaded — install or train one to get predictions.')
            self.explain_text.setPlainText(str(out.get('explain')))
        else:
            # Use only the model's predicted class for verdict
            if pred == 1:
                self.icon_label.setText('❌ PHISHING')
                self.icon_label.setStyleSheet('color: red; font-size: 48px; font-weight: bold;')
            else:
                self.icon_label.setText('✅ LEGITIMATE')
                self.icon_label.setStyleSheet('color: green; font-size: 48px; font-weight: bold;')
            if prob is not None:
                self.prob_label.setText(f'<span style="font-size:24px;">Phishing Probability: <b>{prob:.3f}</b></span>')
            else:
                self.prob_label.setText('')
            if explain:
                tex = []
                for e in explain:
                    tex.append(f"{e['feature']}: value={e['value']} importance={e['importance']:.4f}")
                self.explain_text.setPlainText('\n'.join(tex))
            else:
                self.explain_text.setPlainText('(no feature importances available for the loaded model)')
        self.phish_status.setText('Done')
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    if not IMBLEARN_AVAILABLE:
        QMessageBox.warning(win, 'Optional dependency missing', 'imbalanced-learn not installed. SMOTE will be unavailable.\nInstall with: pip install imbalanced-learn')
    sys.exit(app.exec())

if __name__ == '__main__':
    main()

# ------------------------------------------------------------------------------------------------------------------------------------------ #