#!/usr/bin/env python3
"""
Compact Phishing Detector GUI that mirrors app.py prediction logic.

Usage:
  - GUI mode: python phishing_detector_gui_app.py
  - Test mode (headless): python phishing_detector_gui_app.py --test --model <model_path> --url <url>

This uses the PhishingFeatureExtractor defined in `DD_FEATURE_EXTRACTOR_09_21_2025.py`.
"""
import sys
import os
import json
import argparse
import joblib
import numpy as np

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QTextEdit, QFileDialog, QTableWidget, QTableWidgetItem
)

try:
    from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor
except Exception as e:
    # Best-effort: try importing from same-directory module without extension
    raise


def normalize_features_list(raw):
    if raw is None:
        return []
    try:
        if hasattr(raw, 'tolist') and not isinstance(raw, list):
            lst = raw.tolist()
        else:
            lst = list(raw) if not isinstance(raw, list) else raw
    except Exception:
        lst = [raw]
    # deduplicate while preserving order
    seen = set()
    cleaned = []
    for f in lst:
        if f not in seen:
            cleaned.append(f)
            seen.add(f)
    return cleaned


def balanced_threshold_from_model(model):
    class_weight = getattr(model, 'class_weight', None)
    balanced = 0.5
    if class_weight and isinstance(class_weight, dict):
        try:
            w0 = float(class_weight.get(0, 1))
            w1 = float(class_weight.get(1, 1))
            if (w0 + w1) != 0:
                balanced = w1 / (w0 + w1)
        except Exception:
            balanced = 0.5
    return balanced


class PhishGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Phishing Detector (app.py logic)')
        self.resize(800, 500)
        self.model_bundle = None
        self.model_features = []
        self.model = None
        self.scaler = None

        self._build_ui()

    def _build_ui(self):
        w = QWidget()
        v = QVBoxLayout()
        w.setLayout(v)

        h = QHBoxLayout()
        self.model_label = QLabel('No model loaded')
        h.addWidget(self.model_label)
        btn_load = QPushButton('Load Model')
        btn_load.clicked.connect(self.load_model)
        h.addWidget(btn_load)
        v.addLayout(h)

        url_h = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText('Enter URL (e.g. https://example.com/login)')
        url_h.addWidget(self.url_input)
        btn_pred = QPushButton('Predict')
        btn_pred.clicked.connect(self.on_predict)
        url_h.addWidget(btn_pred)
        v.addLayout(url_h)

        self.out_label = QLabel('Result:')
        v.addWidget(self.out_label)

        self.features_table = QTableWidget(0, 2)
        self.features_table.setHorizontalHeaderLabels(['feature', 'value'])
        v.addWidget(self.features_table)

        self.explain = QTextEdit()
        self.explain.setReadOnly(True)
        v.addWidget(self.explain)

        self.setCentralWidget(w)

    def load_model(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Load model', '', 'Pickle Files (*.pkl *.joblib);;All Files (*)')
        if not path:
            return
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or 'model' not in bundle:
            self.model_label.setText('Bad model bundle')
            return
        self.model_bundle = bundle
        self.model = bundle.get('model')
        self.scaler = bundle.get('scaler')
        self.model_features = normalize_features_list(bundle.get('features', []))
        self.model_label.setText(f'Loaded: {os.path.basename(path)} (features: {len(self.model_features)})')

    def on_predict(self):
        url = self.url_input.text().strip()
        if not url:
            self.out_label.setText('Enter a URL first')
            return
        if not self.model:
            self.out_label.setText('No model loaded')
            return

        ext = PhishingFeatureExtractor(url=url)
        feats = ext.extract_all()

        # Build X using model_features order
        feature_list = self.model_features if self.model_features else sorted(feats.keys())
        X = [feats.get(f, 0) for f in feature_list]
        X_arr = np.array(X).reshape(1, -1)

        # Apply scaler only if model needs it (mirror app.py behavior)
        name = type(self.model).__name__.lower()
        feed = X_arr
        if self.scaler is not None and 'gaussiannb' in name:
            try:
                feed = self.scaler.transform(X_arr)
            except Exception:
                feed = X_arr

        # Predict
        try:
            probs = None
            try:
                probs = self.model.predict_proba(feed)
            except Exception:
                pass
            pred = int(self.model.predict(feed)[0])
            prob = None
            if probs is not None:
                prob = float(probs[0][1]) if probs.shape[1] == 2 else float(probs[0].max())

            thr = balanced_threshold_from_model(self.model)
            # Decide verdict using probability when available
            if prob is not None:
                verdict = 'PHISHING' if prob >= thr else 'LEGITIMATE'
            else:
                verdict = 'PHISHING' if pred == 1 else 'LEGITIMATE'

            # Populate UI
            self.out_label.setText(f'Verdict: {verdict}  (prob={prob})')

            self.features_table.setRowCount(0)
            for i, f in enumerate(feature_list):
                r = self.features_table.rowCount()
                self.features_table.insertRow(r)
                self.features_table.setItem(r, 0, QTableWidgetItem(str(f)))
                self.features_table.setItem(r, 1, QTableWidgetItem(str(feats.get(f, 0))))

            explain_lines = [f'Verdict: {verdict}', f'Probability: {prob}', f'Balanced threshold: {thr}', '\nTop features:']
            # try to show feature importances if present
            try:
                if hasattr(self.model, 'feature_importances_') and len(self.model.feature_importances_) == len(feature_list):
                    importances = np.array(self.model.feature_importances_)
                    idxs = np.argsort(importances)[::-1][:10]
                    for i in idxs:
                        explain_lines.append(f"{feature_list[i]}: importance={importances[i]:.4f} value={feats.get(feature_list[i],0)}")
            except Exception:
                pass

            self.explain.setPlainText('\n'.join(explain_lines))

            # return a structured response for programmatic use
            return {'features': feats, 'feature_list': feature_list, 'input_vector': X, 'probability': prob, 'prediction': pred, 'verdict': verdict}
        except Exception as e:
            self.out_label.setText(f'Error: {e}')
            raise


def run_headless_test(model_path, url):
    if not os.path.exists(model_path):
        print('Model not found:', model_path)
        return 2
    bundle = joblib.load(model_path)
    model = bundle.get('model')
    scaler = bundle.get('scaler')
    model_features = normalize_features_list(bundle.get('features', []))
    ext = PhishingFeatureExtractor(url=url)
    feats = ext.extract_all()
    feature_list = model_features if model_features else sorted(feats.keys())
    X = [feats.get(f, 0) for f in feature_list]
    X_arr = np.array(X).reshape(1, -1)
    feed = X_arr
    if scaler is not None:
        try:
            feed = scaler.transform(X_arr)
        except Exception as e:
            print('Scaler transform failed:', e)
            feed = X_arr
    probs = None
    try:
        probs = model.predict_proba(feed)
    except Exception:
        pass
    pred = int(model.predict(feed)[0])
    prob = float(probs[0][1]) if (probs is not None and probs.shape[1] == 2) else (float(probs[0].max()) if probs is not None else None)
    thr = balanced_threshold_from_model(model)
    verdict = 'PHISHING' if (prob is not None and prob >= thr) else ('PHISHING' if pred == 1 and prob is None else 'LEGITIMATE')

    out = {
        'model_path': model_path,
        'model_features': feature_list,
        'features': feats,
        'input_vector': X,
        'probability': prob,
        'prediction': pred,
        'threshold': thr,
        'verdict': verdict
    }
    print(json.dumps(out, indent=2, default=str))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true', help='Run headless test')
    parser.add_argument('--model', type=str, help='Model path for test')
    parser.add_argument('--url', type=str, help='URL for test')
    args = parser.parse_args()

    if args.test:
        model_path = args.model or os.path.join('MODEL_PHISHING_ML', 'best_phishing_model_14_Balanced Model.pkl')
        url = args.url or 'https://www.roblox.com/login'
        return run_headless_test(model_path, url)

    app = QApplication(sys.argv)
    win = PhishGUI()
    win.show()
    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
