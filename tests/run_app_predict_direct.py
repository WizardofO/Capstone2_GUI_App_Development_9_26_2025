import json
import app
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor

url = 'https://www.roblox.com/login'
print('Model loaded in app:', app.model is not None)
print('Model features (from app):', app.model_features)

feats = PhishingFeatureExtractor(url=url).extract_all()
print('Extracted feature keys count:', len(feats))

feature_list = app.model_features
X = [[feats.get(k,0) for k in feature_list]]
print('Input vector:', X[0])

model = app.model
try:
    probs = model.predict_proba(X)
    score = float(probs[0][1]) if probs.shape[1]==2 else float(probs[0].max())
except Exception as e:
    probs = None
    score = None
pred = model.predict(X)
print('predict_proba:', probs)
print('score:', score)
print('predict:', pred)
print('balanced threshold calc:')
class_weight = getattr(model,'class_weight',None)
thr = 0.5
if class_weight and isinstance(class_weight, dict):
    try:
        w0 = float(class_weight.get(0,1)); w1 = float(class_weight.get(1,1))
        if (w0+w1)!=0: thr = w1/(w0+w1)
    except Exception:
        thr = 0.5
print('threshold:', thr)
verdict = None
if score is not None:
    verdict = 'PHISHING' if score>=thr else 'LEGITIMATE'
else:
    verdict = 'PHISHING' if str(pred[0])=='1' else 'LEGITIMATE'
print('verdict:', verdict)
print(json.dumps({'features':feats,'input':X[0],'score':score,'pred':int(pred[0]),'verdict':verdict}, indent=2, default=str))
