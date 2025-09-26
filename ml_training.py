# Make sure to install required packages:
# pip install pandas scikit-learn xgboost imbalanced-learn shap joblib

import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit, StratifiedKFold, RandomizedSearchCV, StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score, confusion_matrix, classification_report
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
import xgboost as xgb

import joblib
import shap

# 1) Load data
df = pd.read_csv("C:\Users\Osias\OneDrive\Documents\Capstone2_UX_UI_Design\features_test7b.csv")   # adapt filename
# required: df['label'] with 1 for phishing, 0 for legit
# required: df['host'] or df['domain'] column to avoid leakage across train/test

# 2) Columns split (adapt to your dataset)
drop_cols = ['url', 'host', 'label', 'labels']  # remove both label columns if present
target_col = 'labels'

# choose numeric and categorical columns from your data
all_cols = [c for c in df.columns if c not in drop_cols + [target_col]]
numeric_cols = df[all_cols].select_dtypes(include=[np.number]).columns.tolist()
cat_cols = [c for c in all_cols if c not in numeric_cols]

print("Numeric cols:", numeric_cols)
print("Cat cols:", cat_cols)

X = df[all_cols].copy()
y = df[target_col].values
groups = df['host'].values  # use domain as group

# 3) Train/test split by domain (GroupShuffleSplit avoids domain leakage)
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=groups))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(sss.split(X, y))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

# 4) Preprocessing pipelines
num_pipeline = Pipeline([
    ('imputer', SimpleImputer(strategy='median')),
    ('scaler', StandardScaler())
])

cat_pipeline = Pipeline([
    ('imputer', SimpleImputer(strategy='constant', fill_value='MISSING')),
    ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
])

preprocessor = ColumnTransformer([
    ('num', num_pipeline, numeric_cols),
    ('cat', cat_pipeline, cat_cols)
])

# 5) Model + imbalance handling (SMOTE). For very large data, consider class_weight instead.
model = xgb.XGBClassifier(
    tree_method='hist',
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    n_jobs=8
)

pipeline = ImbPipeline(steps=[
    ('preproc', preprocessor),
    ('smote', SMOTE(random_state=42)),  # removed n_jobs
    ('clf', model)
])

# 6) Quick baseline fit
pipeline.fit(X_train, y_train)

# 7) Evaluate
y_pred = pipeline.predict(X_test)
y_proba = pipeline.predict_proba(X_test)[:,1]

print("ROC-AUC:", roc_auc_score(y_test, y_proba))
print("PR-AUC (average precision):", average_precision_score(y_test, y_proba))
print("F1:", f1_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
print("Train class distribution:", np.bincount(y_train))
print("Test class distribution:", np.bincount(y_test))

# 8) Feature importance (SHAP)
# We need the transformed features for SHAP; get transformed train set:
X_train_trans = pipeline.named_steps['preproc'].transform(X_train)
# SHAP with XGBoost expects array; get booster
booster = pipeline.named_steps['clf'].get_booster()
explainer = shap.Explainer(pipeline.named_steps['clf'])
# compute shap values on a sample (avoid huge compute)
sample = X_test.sample(n=min(200, len(X_test)), random_state=42)
sample_trans = pipeline.named_steps['preproc'].transform(sample)
shap_values = explainer(sample_trans)
shap.summary_plot(shap_values, sample_trans)  # opens a matplotlib plot

# 9) Save model
joblib.dump(pipeline, "phish_detector_pipeline.joblib")

# 10) Example: compute feature importances for transformed columns
# get onehot feature names:
ohe = pipeline.named_steps['preproc'].named_transformers_['cat'].named_steps['onehot']
ohe_features = []
if cat_cols:
    cat_names = ohe.get_feature_names_out(cat_cols).tolist()
    feature_names = numeric_cols + cat_names
else:
    feature_names = numeric_cols
fi = pipeline.named_steps['clf'].feature_importances_
feat_imp = pd.DataFrame({'feature': feature_names, 'importance': fi})
print(feat_imp.sort_values('importance', ascending=False).head(30))