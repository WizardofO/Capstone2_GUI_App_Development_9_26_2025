# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva 

from flask import Flask, request, jsonify
import traceback
import os
import joblib
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor

app = Flask(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'best_phishing_model_08.pkl')

# Load the model using joblib
try:
    loaded = joblib.load(MODEL_PATH)
    # If loaded is a dict, get the model object
    if isinstance(loaded, dict) and 'model' in loaded:
        model = loaded['model']
    else:
        model = loaded
    app.logger.info(f"Loaded model from {MODEL_PATH}")
except Exception as e:
    model = None
    app.logger.error("Failed to load model: %s", e)
    traceback.print_exc()

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status':'ok', 'model_loaded': model is not None})

def extract_features(url, feature_keys):
    extractor = PhishingFeatureExtractor(url=url)
    features_dict = extractor.extract_all()
    return [[features_dict.get(k, 0) for k in feature_keys]]

# Example usage:
# For a model trained on 23 features
features_23 = [
    "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
    "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
    "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
    "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
    "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization"
]

# For a model trained on 35 features
features_35 = [
    "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
    "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
    "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
    "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
    "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization",
    "right_click_disabled", "popups", "iframes", "sensitive_forms", "domain_age", "dns_record_count",
    "website_traffic_rank", "page_ranking", "google_index", "backlinks", "blacklist", "whois_suspicious_tokens"
]

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not loaded on server.'}), 500
    data = request.get_json(force=True)
    url = data.get('url') if isinstance(data, dict) else None
    if not url:
        return jsonify({'error': 'No url provided.'}), 400
    try:
        X = extract_features(url, features_23)
        proba = None
        try:
            probs = model.predict_proba(X)
            score = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())
            proba = score
        except Exception:
            proba = None

        pred = model.predict(X)
        label = str(pred[0])

        # Threshold for verdict (adjust as needed, e.g., 0.5)
        threshold = 0.5
        if label == "1" or (proba is not None and proba >= threshold):
            verdict = "PHISHING"
            verdict_text = "PHISHING"
        else:
            verdict = "LEGITIMATE"
            verdict_text = "LEGITIMATE"

        resp = {
            'label': label,
            'score': proba,
            'verdict': verdict,
            'verdict_text': verdict_text
        }
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # CORS: it's simplest to allow everything locally
    from flask_cors import CORS
    CORS(app, origins=["http://localhost:*","http://127.0.0.1:*","chrome-extension://*"])
    app.run(host='0.0.0.0', port=5000)
