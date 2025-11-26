import sys
import os
import time
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
    QPushButton, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QHBoxLayout
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QThread, pyqtSignal

# Add parent directory to sys.path
try:
    CURRENT_DIR = os.path.dirname(__file__)
except NameError:
    CURRENT_DIR = os.getcwd()

PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

# Import your PhishingFeatureExtractor
from DD_FEATURE_EXTRACTOR_09_21_2025 import PhishingFeatureExtractor


class LatencyWorker(QThread):
    result_signal = pyqtSignal(int, str, float, str)  # row, url, latency_ms, status
    finished_signal = pyqtSignal(list)  # full results

    def __init__(self, urls):
        super().__init__()
        self.urls = urls

    def run(self):
        results = []
        for i, url in enumerate(self.urls):
            try:
                start = time.perf_counter()
                extractor = PhishingFeatureExtractor(url=url)
                _ = extractor.extract_all()
                end = time.perf_counter()
                latency_ms = (end - start) * 1000
                latency_s = end - start
                status = "OK"
            except Exception as e:
                latency_ms = 0
                latency_s = 0
                status = f"Error: {str(e)}"

            results.append({
                "url": url,
                "latency_ms": latency_ms,
                "latency_s": latency_s,
                "status": status
            })

            # Emit signal to update table row
            self.result_signal.emit(i, url, latency_ms, status)

        self.finished_signal.emit(results)


class LatencyTester(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phish Latency Tester_GUI_NIEVA OSIAS")
        self.setGeometry(200, 200, 950, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Title
        title = QLabel("Phishing Detection Latency Tester_CAPSTONE2_NIEVA OSIAS")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        self.layout.addWidget(title)

        # Buttons
        button_layout = QHBoxLayout()
        self.load_button = QPushButton("Load CSV")
        self.load_button.clicked.connect(self.load_csv)
        self.load_button.setStyleSheet("background-color: #1E90FF; color: white; font-weight: bold;")
        button_layout.addWidget(self.load_button)

        self.test_button = QPushButton("Run Latency Test")
        self.test_button.clicked.connect(self.run_latency_test)
        self.test_button.setEnabled(False)
        self.test_button.setStyleSheet("background-color: #1E90FF; color: white; font-weight: bold;")
        button_layout.addWidget(self.test_button)

        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)
        self.save_button.setStyleSheet("background-color: #1E90FF; color: white; font-weight: bold;")
        button_layout.addWidget(self.save_button)

        self.layout.addLayout(button_layout)

        # Table for displaying CSV and results
        self.latency_table = QTableWidget()
        self.latency_table.setColumnCount(4)
        self.latency_table.setHorizontalHeaderLabels(["URL", "Latency (ms)", "Latency (s)", "Status"])
        self.latency_table.horizontalHeader().setStretchLastSection(True)
        self.latency_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.layout.addWidget(self.latency_table)

        self.urls = []
        self.results = []

    def load_csv(self):
        inpath, _ = QFileDialog.getOpenFileName(
            self,
            "Select CSV containing URLs",
            "",
            "CSV Files (*.csv);;All Files (*)"
        )
        if not inpath:
            return

        try:
            df = pd.read_csv(inpath)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Cannot read CSV:\n{e}")
            return

        # Find URL column
        url_col = None
        for c in df.columns:
            if c.lower() in ["url", "link", "address", "site"]:
                url_col = c
                break
        if not url_col:
            QMessageBox.warning(self, "Missing Column", "CSV must contain a column named 'URL'")
            return

        self.urls = df[url_col].dropna().tolist()
        self.latency_table.setRowCount(len(self.urls))
        for i, url in enumerate(self.urls):
            self.latency_table.setItem(i, 0, QTableWidgetItem(str(url)))
            self.latency_table.setItem(i, 1, QTableWidgetItem(""))
            self.latency_table.setItem(i, 2, QTableWidgetItem(""))
            self.latency_table.setItem(i, 3, QTableWidgetItem(""))

        self.test_button.setEnabled(True)

    def run_latency_test(self):
        if not self.urls:
            QMessageBox.warning(self, "No URLs", "Please load a CSV first.")
            return

        self.test_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.worker = LatencyWorker(self.urls)
        self.worker.result_signal.connect(self.update_table_row)
        self.worker.finished_signal.connect(self.latency_finished)
        self.worker.start()

    def update_table_row(self, row, url, latency_ms, status):
        self.latency_table.setItem(row, 1, QTableWidgetItem(f"{latency_ms:.2f}"))
        self.latency_table.setItem(row, 2, QTableWidgetItem(f"{latency_ms/1000:.3f}"))  # seconds
        self.latency_table.setItem(row, 3, QTableWidgetItem(status))

    def latency_finished(self, results):
        self.results = results
        self.test_button.setEnabled(True)
        self.save_button.setEnabled(True)

    def save_results(self):
        if not self.results:
            QMessageBox.warning(self, "No Results", "No results to save. Run the latency test first.")
            return

        outpath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Latency Results As",
            "latency_results.csv",
            "CSV Files (*.csv)"
        )
        if outpath:
            pd.DataFrame(self.results).to_csv(outpath, index=False)
            QMessageBox.information(self, "Saved", f"Latency results saved to: {outpath}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LatencyTester()
    window.show()
    sys.exit(app.exec_())
