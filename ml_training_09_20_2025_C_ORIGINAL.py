#!/usr/bin/env python3
"""
phishing_multitool_gui_complete.py

Complete PySide6 GUI with full 35-feature phishing extractor integrated into
single-URL extraction and the training/prediction pipeline.

Dependencies:
 pip install PySide6 scikit-learn imbalanced-learn joblib pandas numpy requests beautifulsoup4 tldextract python-whois dnspython

Run: python phishing_multitool_gui_complete.py
"""

import os
import sys
import json
import re
import traceback
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QProgressBar, QMessageBox,
    QTableWidget, QTableWidgetItem, QLineEdit, QStackedWidget, QGridLayout,
    QSizePolicy, QGroupBox
)

from PySide6.QtGui import QFont, QPalette, QColor, QIcon

from PySide6.QtCore import Qt, Signal, QThread

# ML libs
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# optional SMOTE
try:
    from imblearn.over_sampling import SMOTE
    IMBLEARN_AVAILABLE = True
except Exception:
    IMBLEARN_AVAILABLE = False

# networking/parsing
import requests
import whois
import tldextract
import dns.resolver
import hashlib
from bs4 import BeautifulSoup


REQUESTS_TIMEOUT = 10
LOGO_HASH_FILE = os.getenv('LOGO_HASH_FILE', 'logo_hashes.json')
TRANC0_LOCAL = os.getenv('TRANCO_CSV_PATH', 'tranco.csv')

# -------------------------
# Full extractor functions and class (35 features)
# -------------------------

def safe_requests_get(url, **kwargs):
    try:
        return requests.get(url, timeout=REQUESTS_TIMEOUT, **kwargs)
    except Exception:
        return None


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def normalize_domain(hostname: str) -> str:
    if not hostname:
        return ''
    return hostname.lower().strip().lstrip('www.')


class PhishingFeatureExtractor:
    def __init__(self, url: str = None, html_content: str = None, file_mode: bool = False):
        self.url = url
        self.file_mode = file_mode
        self.html = html_content
        self.parsed = urlparse(url) if url else None
        self.scheme = self.parsed.scheme if self.parsed else 'http'
        self.domain = normalize_domain(self.parsed.hostname) if self.parsed else ''
        self.ext = tldextract.extract(url) if url else None                                 # tdlextract was used to parse the URL and extract its components such as subdomain, domain, and suffix.
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

    def fetch_html(self) -> str:
        if not self.url:
            return ''
        try:
            headers = {'User-Agent': 'PhishFeatureBot/1.0'}
            r = requests.get(self.url, timeout=REQUESTS_TIMEOUT, headers=headers, verify=False)
            return r.text or ''
        except Exception:
            return ''

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

# -------------------------
# Single URL worker using full extractor
# -------------------------
class SingleURLWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)
    progress = Signal(int)

    def __init__(self, url, model_path=None, parent=None):
        super().__init__(parent)
        self.url = url
        self.model_path = model_path

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
                prob = float(model.predict_proba(feed)[0][1])
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

# -------------------------
# GUI (hub + phishing page)
# -------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cybersecurity Suite - For Phishing, Malware and Ransomware - Designed by: Osias Nieva Jr.")
        self.resize(1200, 800)
        self.model_path = None
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        title = QLabel('<h1 align="center">Phishing Detector Hub</h1>')
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack, stretch=1)

        self.page_ransom = self._make_stub_page('Ransomware Detector', 'Ransomware detection not implemented yet.')
        self.page_phish = self._make_phishing_page()
        self.page_malware = self._make_stub_page('Malware Detector', 'Malware detection not implemented yet.')

        hub = QWidget()
        g = QGridLayout()
        hub.setLayout(g)
        btn_ransom = QPushButton('\n\n🛑\nRansomware Detector\n(coming)\n\n')
        btn_ransom.setFixedSize(240, 240)
        btn_ransom.clicked.connect(lambda: self.stack.setCurrentWidget(self.page_ransom))
        g.addWidget(btn_ransom, 0, 0, alignment=Qt.AlignCenter)

        btn_phish = QPushButton('\n\n🛡️\nPhishing Detector\nClick to open\n\n')
        btn_phish.setFixedSize(240, 240)
        btn_phish.clicked.connect(lambda: self.stack.setCurrentWidget(self.page_phish))
        g.addWidget(btn_phish, 0, 1, alignment=Qt.AlignCenter)

        btn_malware = QPushButton('\n\n⚠️\nMalware Detector\n(coming)\n\n')
        btn_malware.setFixedSize(240, 240)
        btn_malware.clicked.connect(lambda: self.stack.setCurrentWidget(self.page_malware))
        g.addWidget(btn_malware, 0, 2, alignment=Qt.AlignCenter)

        self.stack.addWidget(hub)
        self.stack.addWidget(self.page_phish)
        self.stack.addWidget(self.page_ransom)
        self.stack.addWidget(self.page_malware)

        self.status = QLabel('Ready')
        main_layout.addWidget(self.status)

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

    def _make_phishing_page(self):
        w = QWidget()
        v = QVBoxLayout()
        w.setLayout(v)

        header = QHBoxLayout()
        lbl = QLabel('<h2>Phishing Detector</h2>')
        header.addWidget(lbl)
        back = QPushButton('Back')
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        header.addWidget(back)
        v.addLayout(header)

        controls = QHBoxLayout()
        btn_load_csv = QPushButton('Load Features CSV')
        btn_load_csv.clicked.connect(self._phish_load_csv)
        controls.addWidget(btn_load_csv)

        btn_train = QPushButton('Train Models')
        btn_train.clicked.connect(self._phish_train)
        controls.addWidget(btn_train)

        btn_load_model = QPushButton('Load Model')
        btn_load_model.clicked.connect(self._phish_load_model)
        controls.addWidget(btn_load_model)

        btn_predict_csv = QPushButton('Predict on CSV')
        btn_predict_csv.clicked.connect(self._phish_predict_csv)
        controls.addWidget(btn_predict_csv)

        v.addLayout(controls)

        single_group = QGroupBox('Single-URL Prediction')
        sg = QHBoxLayout()
        single_group.setLayout(sg)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('Enter full URL, e.g. https://example.com/login')
        sg.addWidget(self.url_input)
        btn_extract = QPushButton('Extract & Predict')
        btn_extract.clicked.connect(self._phish_single_url)
        sg.addWidget(btn_extract)
        v.addWidget(single_group)

        result_h = QHBoxLayout()
        left_box = QVBoxLayout()
        self.icon_label = QLabel('')
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet('font-size: 48px;')
        left_box.addWidget(self.icon_label)
        self.prob_label = QLabel('')
        self.prob_label.setAlignment(Qt.AlignCenter)
        left_box.addWidget(self.prob_label)
        result_h.addLayout(left_box, 1)

        mid_box = QVBoxLayout()
        self.features_table = QTableWidget(0, 2)
        self.features_table.setHorizontalHeaderLabels(['feature', 'value'])
        mid_box.addWidget(QLabel('Extracted features'))
        mid_box.addWidget(self.features_table)
        result_h.addLayout(mid_box, 3)

        right_box = QVBoxLayout()
        right_box.addWidget(QLabel('Explainability (top features)'))
        self.explain_text = QTextEdit()
        self.explain_text.setReadOnly(True)
        right_box.addWidget(self.explain_text)
        result_h.addLayout(right_box, 2)

        v.addLayout(result_h)

        self.phish_progress = QProgressBar()
        v.addWidget(self.phish_progress)
        self.phish_status = QLabel('')
        v.addWidget(self.phish_status)

        return w

    # phishing callbacks (same behavior as earlier implementation)
    def _phish_load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open features CSV', '', 'CSV Files (*.csv);;All Files (*)')
        if not path:
            return
        self.phish_features_csv = path
        self.phish_status.setText(f'Loaded CSV: {os.path.basename(path)}')

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
            self.phish_status.setText(f'Loaded model: {os.path.basename(path)}')
        except Exception as e:
            QMessageBox.critical(self, 'Load error', f'Failed to load: {e}')

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

    """def _phish_single_url(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, 'No URL', 'Enter a URL first.')
            return
        worker = SingleURLWorker(url, model_path=self.model_path)
        worker.progress.connect(lambda p: self.phish_progress.setValue(p))
        worker.error.connect(lambda e: QMessageBox.critical(self, 'Error', e))
        worker.finished.connect(self._on_single_result)
        self.phish_status.setText('Extracting & predicting...')
        worker.start()"""

    def _phish_single_url(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, "No URL", "Enter a URL first.")
            return

        # keep a reference so it’s not GC’ed
        self.worker = SingleURLWorker(url, model_path=self.model_path)
        self.worker.progress.connect(lambda p: self.phish_progress.setValue(p))
        self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
        self.worker.finished.connect(self._on_single_result)

        self.phish_status.setText("Extracting & predicting...")
        self.worker.start()


    def _on_single_result(self, out: dict):
        feats = out.get('features', {})
        pred = out.get('prediction')
        prob = out.get('probability')
        explain = out.get('explain')
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
            if pred == 1:
                self.icon_label.setText('❌ Phishing')
                self.icon_label.setStyleSheet('color: red; font-size: 36px;')
            else:
                self.icon_label.setText('✅ Legitimate')
                self.icon_label.setStyleSheet('color: green; font-size: 36px;')
            if prob is not None:
                self.prob_label.setText(f'Probability(phishing): {prob:.3f}')
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

# -------------------------
# entrypoint
# -------------------------

def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    if not IMBLEARN_AVAILABLE:
        QMessageBox.warning(win, 'Optional dependency missing', 'imbalanced-learn not installed. SMOTE will be unavailable.\nInstall with: pip install imbalanced-learn')
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
