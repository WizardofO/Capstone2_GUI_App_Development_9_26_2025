# MOIT-200 CAPSTONE2_TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits for Machine Learning-Based Detection "A Case Study Using BlackEye and Zphisher and other sites"
# Author: Osias Nieva 
"""
PySide6 GUI for training / saving / using a phishing detection pipeline.

Features:
- Load feature CSV (expects a numeric features + 'label' column)
- Train models (RandomForest, DecisionTree, GaussianNB, Voting of trees)
- Handle class imbalance with SMOTE (on training data)
- Evaluate on a hold-out test set and show metrics
- Save best model to disk, load saved model
- Predict on a new CSV and save results
"""

import os                                               # os is for file path handling
import sys                                              # sys is for system functions like exiting the app         
import traceback                                        # traceback is for error handling and debugging
import joblib                                           # joblib is for saving and loading ML models            
import pandas as pd                                     # pandas is for data manipulation and analysis
import numpy as np                                      # numpy is for numerical operations

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTextEdit, QProgressBar, QMessageBox,
    QTableWidget, QTableWidgetItem, QSizePolicy
)
from PySide6.QtCore import Qt, Signal, QThread

# ML imports
from sklearn.ensemble import RandomForestClassifier, VotingClassifier                               # Selected Methods ensemble methods for classification
from sklearn.tree import DecisionTreeClassifier                                                     # 
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler        
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)                                                                                                   # sklearn is for machine learning algorithms and evaluation metrics
# ------------------------------------------------------------------------------------------------------------------------------------------ #                                                                                                   
# imbalanced-learn (SMOTE)
try:
    from imblearn.over_sampling import SMOTE
    IMBLEARN_AVAILABLE = True
except Exception:
    IMBLEARN_AVAILABLE = False
""" SMOTE (Synthetic Minority Over-sampling Technique)
Benefits of Using SMOTE:
Addresses Class Imbalance: SMOTE directly tackles the issue of imbalanced datasets, preventing models from being overly biased towards the majority class.
Improves Model Performance: By providing more representative data for the minority class, SMOTE can lead to improved predictive performance, especially in terms of recall and F1-score for the minority class.
Reduces Overfitting: Unlike simple oversampling techniques that just duplicate existing samples, SMOTE creates synthetic samples, which can help reduce overfitting to the original minority class instances.
Applicable to Various Data Types: SMOTE can be applied to datasets with both continuous and categorical features, although variations like SMOTE-NC 
(for nominal and continuous features) exist for handling mixed data types more effectively.
"""

# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Worker thread for training
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class Model_Training_for_PHISHINGDETECTOR(QThread):   
    progress = Signal(int)  # percent
    finished = Signal(dict, object)  # metrics dict, saved_model_path or None
    error = Signal(str)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    #def __init__(self, csv_path, model_out_path="best_phishing_model.pkl", random_state=42, parent=None):   # default output path (add name for changes and updates) 42 is set because it's a common convention for reproducibility
    def __init__(self, csv_path, model_out_path="best_phishing_model.pkl", random_state=17, parent=None):    # Osias Random state changed to 17
        super().__init__(parent)
        self.csv_path = csv_path
        self.model_out_path = model_out_path
        self.random_state = random_state
        self._stop = False
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def run(self):
        try:
            self.progress.emit(5)                                                                       # This code block is for loading the CSV file and preparing the data for training
            df = pd.read_csv(self.csv_path, encoding="utf-8")
            # find label column
            label_col = next((c for c in ["label", "Label", "y"] if c in df.columns), None)             # look for common label column names
            if label_col is None:
                self.error.emit("No label column found in CSV (expected 'label').")                     # if not found, emit error and
                return
            # coerce label                                                                              
            df[label_col] = pd.to_numeric(df[label_col], errors="make it invalid")                      # convert label to numeric, invalids to NaN
            df = df.dropna(subset=[label_col])                                                          # drop rows with NaN labels
            df[label_col] = df[label_col].astype(int)                                                   # convert label to int                    
            self.progress.emit(10)                                                                      # This code block is for preprocessing the data, handling missing values, and preparing it for model training

            # keep numeric ready of Machine learning only
            numeric = df.select_dtypes(include=[np.number]).copy()                                      # select only numeric columns      
            if label_col not in numeric.columns:                                                        # ensure label column is present                                        
                numeric[label_col] = df[label_col]                                                      # if not, add it from original df      

            # drop constant columns
            numeric = numeric.loc[:, numeric.nunique() > 1]                                             # this code is for dropping constant columns

            X = numeric.drop(columns=[label_col])                                                            
            y = numeric[label_col]
            X = X.fillna(X.median())
            self.progress.emit(20)

            # train/test split (stratified)
            from sklearn.model_selection import train_test_split                    # test_size=0.2 means 20% of data is for testing, 80% for training. 
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, stratify=y, random_state=self.random_state
            )
            self.progress.emit(30)

            # to handle imbalance with SMOTE if available  
            imbalance_ratio = y_train.value_counts(normalize=True)
            min_class = imbalance_ratio.idxmin()            # idxmax means the class with the highest count
            max_class = imbalance_ratio.idxmax()            # idxmin means the class with the lowest count   
            ratio = imbalance_ratio[min_class] / imbalance_ratio[max_class] if imbalance_ratio[max_class] > 0 else 0
            warn_imbalance = False
            if IMBLEARN_AVAILABLE:
                smote = SMOTE(random_state=self.random_state)
                X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
            else:
                # fallback: use original training set but we warn the user if imbalance is severe
                X_train_bal, y_train_bal = X_train, y_train
                if ratio < 0.5:
                    warn_imbalance = True  

            self.progress.emit(45)     # this code emit(45) 45 can be replaced with any number between 0-100 depending on the progress of the training process
                                       # 45 was use to indicate that the training process is almost halfway done
            # scaler for NB
            scaler = StandardScaler()
            X_train_s = scaler.fit_transform(X_train_bal)
            X_test_s = scaler.transform(X_test)

            # prepare models with class_weight for supported classifiers
            rf = RandomForestClassifier(n_estimators=100, random_state=self.random_state, class_weight="balanced")
            dt = DecisionTreeClassifier(random_state=self.random_state, class_weight="balanced")
            nb = GaussianNB()
            voting = VotingClassifier(
                estimators=[("rf", rf), ("dt", dt)],
                voting="hard", n_jobs=1
            )

            models = {
                "RandomForest": (rf, X_train_bal, X_test),      # RandomForest uses balanced data without scaling meaning it can handle raw numeric data 
                "DecisionTree": (dt, X_train_bal, X_test),      # DecisionTree uses balanced data without scaling
                "NaiveBayes": (nb, X_train_s, X_test_s),        # NaiveBayes uses scaled data meaning it needs standardized input and
                "VotingTrees": (voting, X_train_bal, X_test)    # Voting of trees uses balanced data without scaling
            }

            results = {}
            total = len(models)
            i = 0
            for name, (model, Xt_train, Xt_test) in models.items():
                if self._stop: break
                i += 1
                self.progress.emit(45 + int(40 * (i/total)))
                # fit and evaluate
                model.fit(Xt_train, y_train_bal if name != "NaiveBayes" else y_train_bal)
                y_pred = model.predict(Xt_test)
                try:
                    y_proba = model.predict_proba(Xt_test)[:, 1]
                except Exception:
                    y_proba = None

                metrics = {
                    "accuracy": float(accuracy_score(y_test, y_pred)),
                    "precision": float(precision_score(y_test, y_pred, zero_division=0)),
                    "recall": float(recall_score(y_test, y_pred, zero_division=0)),
                    "f1": float(f1_score(y_test, y_pred, zero_division=0)),
                    "roc_auc": float(roc_auc_score(y_test, y_proba)) if y_proba is not None else None,
                    "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                    "classification_report": classification_report(y_test, y_pred, zero_division=0)
                }
                results[name] = metrics

            self.progress.emit(90)

            # pick best by F1
            best_name = max(results.keys(), key=lambda k: results[k]["f1"])
            best_model_obj = models[best_name][0]

            # Save model and scaler (we save scaler even though NB needs it; store both)
            to_save = {
                "model": best_model_obj,
                "scaler": scaler,
                "features": list(X.columns),
                "label_col": label_col
            }
            joblib.dump(to_save, self.model_out_path)

            self.progress.emit(100)

            # Warn user if imbalance is detected and SMOTE is not available
            if warn_imbalance:
                self.error.emit("Warning: Severe class imbalance detected and SMOTE is not available. Results may be biased. Install imbalanced-learn for better balancing.")
            self.finished.emit(results, os.path.abspath(self.model_out_path))

        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"Training error: {e}\n{tb}")

    def stop(self):
        self._stop = True

# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Main Window
# ------------------------------------------------------------------------------------------------------------------------------------------ #
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Model Pipeline Training GUI - Capstione2 by Osias Nieva Jr")
        self.resize(1000, 700)

        self.csv_path = None
        self.model_path = None
        self.trainer = None

        self._build_ui()

    def _build_ui(self):
        w = QWidget()
        self.setCentralWidget(w)
        v = QVBoxLayout()
        w.setLayout(v)

        # top controls
        top = QHBoxLayout()
        self.btn_load_csv = QPushButton("Load Features CSV")
        self.btn_load_csv.clicked.connect(self.on_load_csv)
        top.addWidget(self.btn_load_csv)

        self.lbl_csv = QLabel("No CSV loaded")
        top.addWidget(self.lbl_csv)

        self.btn_train = QPushButton("Train Models")
        self.btn_train.clicked.connect(self.on_train)
        self.btn_train.setEnabled(False)
        top.addWidget(self.btn_train)

        self.btn_save_model = QPushButton("Save Loaded Model")
        self.btn_save_model.clicked.connect(self.on_save_model)
        self.btn_save_model.setEnabled(False)
        top.addWidget(self.btn_save_model)

        self.btn_load_model = QPushButton("Load Model (joblib)")
        self.btn_load_model.clicked.connect(self.on_load_model)
        top.addWidget(self.btn_load_model)

        self.btn_predict_csv = QPushButton("Predict on CSV")
        self.btn_predict_csv.clicked.connect(self.on_predict_csv)
        self.btn_predict_csv.setEnabled(False)
        top.addWidget(self.btn_predict_csv)

        v.addLayout(top)

        # progress and status
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        v.addWidget(self.progress)

        self.status = QLabel("Ready")
        v.addWidget(self.status)

        # metrics text
        self.metrics_text = QTextEdit()
        self.metrics_text.setReadOnly(True)
        self.metrics_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        v.addWidget(self.metrics_text)

        # small table for summary
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Model", "Accuracy", "Precision", "Recall", "F1", "ROC_AUC"])
        v.addWidget(self.table)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open features CSV", "", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        self.csv_path = path
        self.lbl_csv.setText(os.path.basename(path))
        self.status.setText("CSV loaded")
        self.btn_train.setEnabled(True)
        self.metrics_text.clear()
        self.table.setRowCount(0)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_train(self):
        if not self.csv_path:
            QMessageBox.warning(self, "No CSV", "Load a features CSV first.")
            return
        # ask where to save model
        out_path, _ = QFileDialog.getSaveFileName(self, "Save best model as", "best_phishing_model.pkl", "Pickle Files (*.pkl);;All Files (*)")
        if not out_path:
            return
        self.model_path = out_path
        # start trainer thread
        self.trainer = Model_Training_for_PHISHINGDETECTOR(self.csv_path, model_out_path=self.model_path)
        self.trainer.progress.connect(self.on_progress)
        self.trainer.finished.connect(self.on_train_finished)
        self.trainer.error.connect(self.on_train_error)
        self.btn_train.setEnabled(False)
        self.status.setText("Training started...")
        self.progress.setValue(0)
        self.trainer.start()
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_progress(self, percent):
        self.progress.setValue(percent)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_train_finished(self, results: dict, saved_model_path):
        self.status.setText(f"Training finished. Best model saved to {saved_model_path}")
        self.btn_train.setEnabled(True)
        self.btn_save_model.setEnabled(True)
        self.btn_predict_csv.setEnabled(True)
        self.model_path = saved_model_path

        # display results in text and table
        self.metrics_text.clear()
        self.table.setRowCount(0)
        for name, m in results.items():
            self.metrics_text.append(f"====================== {name} ======================")
            for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
                self.metrics_text.append(f"{k}: {m.get(k)}")
            self.metrics_text.append("confusion_matrix:")
            self.metrics_text.append(str(m.get("confusion_matrix")))
            self.metrics_text.append("classification_report:")
            self.metrics_text.append(m.get("classification_report"))
            self.metrics_text.append("")

            # add to table
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(name))
            self.table.setItem(r, 1, QTableWidgetItem(f"{m.get('accuracy'):.4f}"))
            self.table.setItem(r, 2, QTableWidgetItem(f"{m.get('precision'):.4f}"))
            self.table.setItem(r, 3, QTableWidgetItem(f"{m.get('recall'):.4f}"))
            self.table.setItem(r, 4, QTableWidgetItem(f"{m.get('f1'):.4f}"))
            roc = m.get("roc_auc")
            self.table.setItem(r, 5, QTableWidgetItem(f"{roc:.4f}" if roc is not None else "N/A"))
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_train_error(self, msg):
        self.status.setText("Training failed")
        QMessageBox.critical(self, "Training error", msg)
        self.btn_train.setEnabled(True)
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_save_model(self):
        # Save the model to another location (copy)
        if not self.model_path or not os.path.exists(self.model_path):
            QMessageBox.warning(self, "No model", "No saved model available. Train first or load one.")
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save model copy", os.path.basename(self.model_path), "Pickle Files (*.pkl);;All Files (*)")
        if not dest:
            return
        try:
            import shutil
            shutil.copyfile(self.model_path, dest)
            QMessageBox.information(self, "Saved", f"Model copied to {dest}")
        except Exception as e:
            QMessageBox.critical(self, "Failed", f"Could not copy model: {e}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_load_model(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load model (joblib .pkl)", "", "Pickle Files (*.pkl *.joblib);;All Files (*)")
        if not path:
            return
        # verify load
        try:
            obj = joblib.load(path)
            # Expecting dict with keys model, scaler, features
            if not isinstance(obj, dict) or "model" not in obj:
                QMessageBox.warning(self, "Unexpected file", "Loaded file doesn't look like a saved pipeline (expected dict with 'model').")
                return
            self.model_path = path
            QMessageBox.information(self, "Model loaded", f"Model loaded from {path}")
            self.btn_predict_csv.setEnabled(True)
            self.status.setText(f"Model loaded: {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Load error", f"Failed to load model: {e}")
# ------------------------------------------------------------------------------------------------------------------------------------------ #
    def on_predict_csv(self):
        if not self.model_path or not os.path.exists(self.model_path):
            QMessageBox.warning(self, "No model", "No saved model available. Train first or load one.")
            return
        inpath, _ = QFileDialog.getOpenFileName(self, "Load features CSV to predict", "", "CSV Files (*.csv);;All Files (*)")
        if not inpath:
            return
        outpath, _ = QFileDialog.getSaveFileName(self, "Save predictions to CSV", "predictions.csv", "CSV Files (*.csv);;All Files (*)")
        if not outpath:
            return
        try:
            model_bundle = joblib.load(self.model_path)
            model = model_bundle.get("model")
            scaler = model_bundle.get("scaler")
            expected_features = model_bundle.get("features")
            df_new = pd.read_csv(inpath, encoding="utf-8")
            # keep numeric columns and align features
            new_numeric = df_new.select_dtypes(include=[np.number]).copy()
            # ensure columns order
            for col in expected_features:
                if col not in new_numeric.columns:
                    # fill missing with median
                    new_numeric[col] = np.nan
            new_numeric = new_numeric[expected_features]
            new_numeric = new_numeric.fillna(new_numeric.median())

            # if model is GaussianNB (or scaler exists), transform
            try:
                X_for_pred = new_numeric.values
                if scaler is not None:
                    X_for_pred_scaled = scaler.transform(X_for_pred)
                else:
                    X_for_pred_scaled = X_for_pred
            except Exception:
                X_for_pred_scaled = new_numeric.values

            # choose which to feed model: if model is NB and scaler present, use scaled.
            model_class_name = model.__class__.__name__.lower()
            if "gaussiannb" in model_class_name and scaler is not None:
                feed = X_for_pred_scaled
            else:
                feed = new_numeric.values

            preds = model.predict(feed)
            df_out = df_new.copy()
            df_out["predicted_label"] = preds
            df_out.to_csv(outpath, index=False)
            QMessageBox.information(self, "Predictions saved", f"Saved predictions to {outpath}")
        except Exception as e:
            QMessageBox.critical(self, "Prediction error", f"Error during prediction: {e}\n{traceback.format_exc()}")

# ------------------------------------------------------------------------------------------------------------------------------------------ #
# Run
# ------------------------------------------------------------------------------------------------------------------------------------------ #
def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    if not IMBLEARN_AVAILABLE:          # imbalanced-learn (SMOTE) not available is used for handling class imbalance during training and if not present, we warn the user to install it.
        QMessageBox.warning(win, "imblearn not found",
                            "imbalanced-learn (SMOTE) not found. Install with:\n\npip install imbalanced-learn\n\nTraining will still run but without SMOTE balancing.")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
# ------------------------------------------------------------------------------------------------------------------------------------------ #