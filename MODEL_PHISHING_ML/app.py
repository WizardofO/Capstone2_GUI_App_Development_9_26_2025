# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva Jr.
# ------------------------------------------------------------------------------------------------------------------------------------------ #
from flask import Flask, request, jsonify                   # Flask web server was used to create a simple API for the phishing detection model.
import traceback                                            # For error handling and debugging.
import os                                                   # For file path manipulations.                  
import joblib                                               # For loading the pre-trained ML model.
import sys                                                  # For system-specific parameters and functions.                     
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor    # From ORIGINAL FEATURE EXTRACTOR using Custom feature extractor for phishing detection imported from a separate module.
# ------------------------------------------------------------------------------------------------------------------------------------------ #
app = Flask(__name__)                                       # Initialize the Flask application.

#MODEL_PATH = os.path.join(os.path.dirname(__file__), 'best_phishing_model_08.pkl')                    # Path to my old pre-trained model file.
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'best_phishing_model_14_Balanced Model.pkl')      # Path to the pre-trained model file.

# Load the model using joblib
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
# Example usage:
# For a model trained on 23 features
features_23 = [
    "ip_in_url", "url_length", "url_shortening", "presence_at", "redirection_symbol",
    "hyphen_in_domain", "too_many_subdomains", "https_in_string", "ssl_tls_validity",
    "domain_registration_length", "non_standard_ports", "external_favicon", "count_dots",
    "suspicious_chars", "known_logo", "use_script", "count_third_party_domains", "use_meta",
    "script_external_ratio", "use_form", "mailto", "website_forwarding", "status_bar_customization"
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

        proba = None
        try:
            probs = model.predict_proba(X)
            score = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())
            proba = score
        except Exception:
            proba = None

        pred = model.predict(X)
        label = str(pred[0])

        # Balanced prediction logic: use both probability and class_weight if available
        # balanced_threshold = 0.10 
        balanced_threshold = 0.5            # (SOLUTION FOR THE ISSUE of imbalanced dataset)
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

if __name__ == '__main__':
    # CORS: it's simplest to allow everything locally
    from flask_cors import CORS
    CORS(app, origins=["http://localhost:*","http://127.0.0.1:*","chrome-extension://*"])
    app.run(host='0.0.0.0', port=5000)
