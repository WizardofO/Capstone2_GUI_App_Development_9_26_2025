# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva Jr.
# ------------------------------------------------------------------------------------------------------------------------------------------ #
from flask import Flask, request, jsonify                   # Flask web server was used to create a simple API for the phishing detection model.
import traceback                                            # For error handling and debugging.
import os                                                   # For file path manipulations.                  
import joblib                                               # For loading the pre-trained ML model.
import sys                                                  # For system-specific parameters and functions.  
import time                   
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor    # From ORIGINAL FEATURE EXTRACTOR using Custom feature extractor for phishing detection imported from a separate module.
# ------------------------------------------------------------------------------------------------------------------------------------------ #
app = Flask(__name__)                                       # Initialize the Flask application.

#MODEL_PATH = os.path.join(os.path.dirname(__file__), 'best_phishing_model_08.pkl')                    # Path to my old pre-trained model file.
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'best_phishing_model_14_Balanced Model.pkl')      # Path to the pre-trained model file.

# Load the latest .pkl model using joblib
try:
    loaded = joblib.load(MODEL_PATH)
    # If loaded is a dict, get the model object and feature list
    if isinstance(loaded, dict) and 'model' in loaded:
        model = loaded['model']
        model_features = loaded.get('features', None)
    else:
        model = loaded
        model_features = None
    app.logger.info(f"Loaded model from {MODEL_PATH}")
except Exception as e:
    model = None
    model_features = None
    app.logger.error("Failed to load model: %s", e)
    traceback.print_exc()
# ------------------------------------------------------------------------------------------------------------------------------------------ #

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status':'ok', 'Osias your model is loaded already': model is not None})
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def extract_features(url, feature_keys):
    extractor = PhishingFeatureExtractor(url=url)
    features_dict = extractor.extract_all()
    return [[features_dict.get(k, 0) for k in feature_keys]]
# ------------------------------------------------------------------------------------------------------------------------------------------ #
#  
# For a model trained on 23 features
features_23 = [
    "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
    "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
    "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
    "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
    "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization"
]
# ------------------------------------------------------------------------------------------------------------------------------------------ #
# For a model trained on 25 features

features_25 = [
        "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
        "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
        "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
        "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
        "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization",
        "right_click_disabled", "popups"
    ]
# ------------------------------------------------------------------------------------------------------------------------------------------ #
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
# ------------------------------------------------------------------------------------------------------------------------------------------ #
@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model not loaded on server.'}), 500
    data = request.get_json(force=True)
    url = data.get('url') if isinstance(data, dict) else None
    if not url:
        return jsonify({'error': 'No url provided.'}), 400
    # Always use the feature list from the loaded model bundle if available
    if model_features is None:
        return jsonify({'error': 'Model feature list not found. Retrain and save model with feature list.'}), 500
    try:
        X = extract_features(url, model_features)
        # Check feature count against model expectation
        expected_features = None
        if hasattr(model, 'n_features_in_'):
            expected_features = model.n_features_in_
        elif hasattr(model, 'estimators_') and hasattr(model.estimators_[0], 'n_features_in_'):
            expected_features = model.estimators_[0].n_features_in_
        if expected_features is not None and len(X[0]) != expected_features:
            return jsonify({'error': f'Input has {len(X[0])} features, but model expects {expected_features} features.'}), 400

        proba = None    # Default to None if probability prediction fails                                   
        try:
            probs = model.predict_proba(X)
            score = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())    # This is for Phishing probability Calculation Area occurs
            proba = score
        except Exception:
            proba = None

        pred = model.predict(X)
        label = str(pred[0])

        # Balanced prediction logic: use both probability and class_weight if available
        # old balanced_threshold used = 0.10 lean to legitimate to all sites
        balanced_threshold = 0.5            # (SOLUTION FOR THE ISSUE of imbalanced dataset) SMOTE Technique was used to balance the dataset
        class_weight = getattr(model, 'class_weight', None)
        if class_weight and isinstance(class_weight, dict):
            w0 = class_weight.get(0, 1)
            w1 = class_weight.get(1, 1)
            balanced_threshold = w1 / (w0 + w1)

        if proba is not None:
            if proba >= balanced_threshold:
                verdict = "PHISHING"
                verdict_text = "PHISHING"
                verdict_icon = "❌"
            else:
                verdict = "LEGITIMATE"
                verdict_text = "LEGITIMATE"
                verdict_icon = "✔️"
        else:
            if label == "1":
                verdict = "PHISHING"
                verdict_text = "PHISHING"
                verdict_icon = "❌"
            else:
                verdict = "LEGITIMATE"
                verdict_text = "LEGITIMATE"
                verdict_icon = "✔️"

        resp = {
            'label': label,
            'score': proba,
            'verdict': verdict,
            'verdict_text': verdict_text,
            'verdict_icon': verdict_icon
        }
        return jsonify(resp)
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/summary_report', methods=['POST'])
def summary_report():
    data = request.get_json(force=True)
    url = data.get('url') if isinstance(data, dict) else None
    if not url:
        return jsonify({'error': 'No url provided.'}), 400
    try:
        extractor = PhishingFeatureExtractor(url=url)
        features_dict = extractor.extract_all()
        # Explanations for each feature
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
        summary = []
        for k, v in features_dict.items():
            explanation = feature_explanations.get(k, "")
            summary.append({
                "feature": k,
                "value": v,
                "explanation": explanation
            })
        return jsonify({
            'summary_report': summary,
            'features': features_dict
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/report_issue', methods=['POST'])
def report_issue():
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        screenshot = request.files.get('screenshot')
        # Save report to disk or send via email (example: save to disk)
        report_dir = 'reports'
        os.makedirs(report_dir, exist_ok=True)
        report_id = f"{int(time.time())}_{name.replace(' ', '_')}"
        report_path = os.path.join(report_dir, f"{report_id}.txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"Name: {name}\nEmail: {email}\nMessage: {message}\n")
        if screenshot:
            screenshot.save(os.path.join(report_dir, f"{report_id}_screenshot.png"))
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

if __name__ == '__main__':
    # CORS: it's simplest to allow everything locally
    from flask_cors import CORS
    CORS(app, origins=["http://localhost:*","http://127.0.0.1:*","chrome-extension://*"])
    app.run(host='0.0.0.0', port=5000)
