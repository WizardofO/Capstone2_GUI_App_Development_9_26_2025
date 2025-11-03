import os
import sys
import json
import joblib
# Ensure project root is on sys.path so imports work when running from tests/
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor

# Adjust if your model path differs
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MODEL_PHISHING_ML', 'best_phishing_model_14_Balanced Model.pkl')
TEST_URL = 'https://www.roblox.com/login'

print('Using model path:', MODEL_PATH)
if not os.path.exists(MODEL_PATH):
    print('Model file not found. Please check path and place the model at the expected location.')
    sys.exit(1)

bundle = joblib.load(MODEL_PATH)
if not isinstance(bundle, dict) or 'model' not in bundle:
    print('Loaded object is not a model bundle with key "model".')
    sys.exit(1)

model = bundle['model']
model_features = bundle.get('features')
scaler = bundle.get('scaler')

print('\nModel type:', type(model).__name__)
print('Model features (len):', len(model_features) if model_features else None)
print('Model features list:', model_features)

# Extract features
ext = PhishingFeatureExtractor(url=TEST_URL)
features_dict = ext.extract_all()

print('\nExtracted feature dict (sample):')
for k in list(features_dict.keys())[:20]:
    print(f'  {k}: {features_dict[k]}')

# Build input vector in model order
if not model_features:
    print('\nModel bundle has no feature list. Cannot build input vector reliably.')
    sys.exit(1)

X = [features_dict.get(k, 0) for k in model_features]
print('\nInput vector (feature order = model_features):')
for k, v in zip(model_features, X):
    print(f'  {k}: {v}')

import numpy as np
X_arr = np.array(X).reshape(1, -1)
if scaler is not None:
    try:
        Xs = scaler.transform(X_arr)
        print('\nScaler applied to input vector.')
        feed = Xs
    except Exception as e:
        print('Scaler transform failed:', e)
        feed = X_arr
else:
    feed = X_arr

# Predict probability and class
proba = None
try:
    probs = model.predict_proba(feed)
    proba = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())
    print('\nPredict_proba:', probs)
except Exception as e:
    print('\npredict_proba not available:', e)

pred = None
try:
    pred = int(model.predict(feed)[0])
    print('Predict:', pred)
except Exception as e:
    print('Predict failed:', e)

# Balanced threshold logic
balanced_threshold = 0.5
class_weight = getattr(model, 'class_weight', None)
if class_weight and isinstance(class_weight, dict):
    try:
        w0 = float(class_weight.get(0, 1))
        w1 = float(class_weight.get(1, 1))
        if (w0 + w1) != 0:
            balanced_threshold = w1 / (w0 + w1)
    except Exception:
        balanced_threshold = 0.5

print('\nBalanced threshold:', balanced_threshold)

if proba is not None:
    verdict = 'PHISHING' if proba >= balanced_threshold else 'LEGITIMATE'
else:
    verdict = 'PHISHING' if pred == 1 else 'LEGITIMATE'

print('\nFinal verdict:', verdict)
print('Probability (if available):', proba)

# Dump JSON for easy copy/paste comparison
out = {'url': TEST_URL, 'features_dict': features_dict, 'model_features': model_features, 'input_vector': X, 'probability': proba, 'prediction': pred, 'threshold': balanced_threshold, 'verdict': verdict}
print('\n-- JSON OUTPUT --')
print(json.dumps(out, indent=2))
