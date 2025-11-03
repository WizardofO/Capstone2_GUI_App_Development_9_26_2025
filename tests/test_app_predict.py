import os
import sys
import json

# Ensure project root on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import the Flask app module (it loads model at import)
from MODEL_PHISHING_ML import app as flask_app_module

TEST_URL = 'https://www.roblox.com/login'

print('Using Flask app model path and settings from MODEL_PHISHING_ML/app.py')
model = getattr(flask_app_module, 'model', None)
model_features = getattr(flask_app_module, 'model_features', None)

print('Model loaded:', model is not None)
print('Model features (len):', len(model_features) if model_features else None)
print('Model features list:', model_features)

if model is None or not model_features:
    print('Model or model_features missing in app module; aborting test')
    sys.exit(1)

# Use app.extract_features to build X
X = flask_app_module.extract_features(TEST_URL, model_features)
print('\nBuilt input vector X:')
for k, v in zip(model_features, X[0]):
    print(f'  {k}: {v}')

# Follow app.py predict logic
proba = None
try:
    probs = model.predict_proba(X)
    score = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())
    proba = score
    print('\npredict_proba:', probs)
except Exception as e:
    print('\npredict_proba failed:', e)

pred = None
try:
    pred = model.predict(X)[0]
    print('predict:', pred)
except Exception as e:
    print('predict failed:', e)

balanced_threshold = 0.5
class_weight = getattr(model, 'class_weight', None)
if class_weight and isinstance(class_weight, dict):
    try:
        w0 = class_weight.get(0, 1)
        w1 = class_weight.get(1, 1)
        balanced_threshold = w1 / (w0 + w1)
    except Exception:
        balanced_threshold = 0.5

print('\nBalanced threshold:', balanced_threshold)

if proba is not None:
    verdict = 'PHISHING' if proba >= balanced_threshold else 'LEGITIMATE'
else:
    verdict = 'PHISHING' if str(pred) == '1' else 'LEGITIMATE'

print('\nFinal verdict (Flask logic):', verdict)
print('Probability:', proba)

# Dump JSON
out = {'url': TEST_URL, 'model_features': model_features, 'input_vector': X[0], 'probability': proba, 'prediction': int(pred) if pred is not None else None, 'threshold': balanced_threshold, 'verdict': verdict}
print('\nJSON OUTPUT:\n', json.dumps(out, indent=2))
