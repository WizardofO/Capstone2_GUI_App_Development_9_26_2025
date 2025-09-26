#!/usr/bin/env python3
"""
analyze_features.py

Quick analysis of phishing-feature CSV using:
  1) RandomForest
  2) DecisionTree
  3) Gaussian Naive Bayes
  4) Voting ensemble of tree models

Outputs accuracy, precision, recall, F1, ROC AUC, confusion matrix, classification report.

This script is intentionally lightweight (small forest sizes, no expensive CV) so it runs quickly.
For a more thorough run (CV, stacking, feature importance plotting), see the comments below.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

CSV_PATH = "features_output_09_20_2025.csv"  # change if needed

def load_and_prepare(csv_path):
    df = pd.read_csv(csv_path, encoding="utf-8")
    # find label column
    label_col = next((c for c in ["label", "Label", "y"] if c in df.columns), None)
    if label_col is None:
        raise ValueError("No 'label' column found in CSV.")
    # coerce label to numeric and drop NaNs
    df[label_col] = pd.to_numeric(df[label_col], errors="coerce")
    df = df.dropna(subset=[label_col])
    df[label_col] = df[label_col].astype(int)

    # keep only numeric columns (features) + label
    numeric = df.select_dtypes(include=[np.number]).copy()
    if label_col not in numeric.columns:
        numeric[label_col] = df[label_col]

    # drop constant columns (no variance)
    numeric = numeric.loc[:, numeric.nunique() > 1]

    # split
    X = numeric.drop(columns=[label_col])
    y = numeric[label_col]

    # simple fillna with median
    X = X.fillna(X.median())

    return X, y

def main():
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"{CSV_PATH} not found. Put your CSV in the same folder or edit CSV_PATH.")

    X, y = load_and_prepare(CSV_PATH)

    print("Dataset shape:", X.shape)
    print("Label distribution:\n", y.value_counts())

    # train/test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    # scaled copy for Naive Bayes
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # lightweight models (small forests to keep runtime low)
    rf = RandomForestClassifier(n_estimators=30, random_state=42, class_weight="balanced", n_jobs=1)
    dt = DecisionTreeClassifier(random_state=42, class_weight="balanced")
    nb = GaussianNB()

    # Voting ensemble of tree models (simple combination)
    voting = VotingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(n_estimators=20, random_state=42, class_weight="balanced")),
            ("dt", DecisionTreeClassifier(random_state=42, class_weight="balanced"))
        ],
        voting="hard", n_jobs=1
    )

    models = {
        "RandomForest": (rf, X_train, X_test),
        "DecisionTree": (dt, X_train, X_test),
        "NaiveBayes": (nb, X_train_s, X_test_s),  # NB uses scaled inputs
        "VotingTrees": (voting, X_train, X_test)
    }

    results = {}
    for name, (model, Xt_train, Xt_test) in models.items():
        print("\nTraining:", name)
        model.fit(Xt_train, y_train)
        y_pred = model.predict(Xt_test)
        try:
            y_proba = model.predict_proba(Xt_test)[:, 1]
        except Exception:
            y_proba = None

        results[name] = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1": f1_score(y_test, y_pred, zero_division=0),
            "roc_auc": roc_auc_score(y_test, y_proba) if y_proba is not None else None,
            "confusion_matrix": confusion_matrix(y_test, y_pred),
            "classification_report": classification_report(y_test, y_pred, zero_division=0)
        }

    # print summary
    print("\n=== Summary metrics (test set) ===")
    for name, r in results.items():
        print(f"\n-- {name} --")
        print(f"Accuracy: {r['accuracy']:.4f}")
        print(f"Precision: {r['precision']:.4f}")
        print(f"Recall: {r['recall']:.4f}")
        print(f"F1: {r['f1']:.4f}")
        print(f"ROC_AUC: {r['roc_auc']}")
        print("Confusion Matrix:\n", r["confusion_matrix"])
        print("Classification Report:\n", r["classification_report"])

if __name__ == "__main__":
    main()
