from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QHBoxLayout,
    QSpacerItem, QSizePolicy, QPushButton
)
from PySide6.QtGui import QFont, QPalette, QColor, QIcon
from PySide6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve
import sys
from PySide6.QtWidgets import QGraphicsDropShadowEffect

class AnimatedButton(QPushButton):
    def __init__(self, icon_file, parent=None):
        super().__init__(parent)
        self.setIcon(QIcon(icon_file))
        self.setIconSize(QSize(220, 220))   # Default size
        self.setFixedSize(260, 260)         # Keeps space fixed
        self.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: transparent;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 30);
                border-radius: 20px;
            }
        """)

        # Zoom animation
        self.anim = QPropertyAnimation(self, b"iconSize")
        self.anim.setDuration(200)
        self.anim.setEasingCurve(QEasingCurve.OutQuad)

    def enterEvent(self, event):
        """Zoom in"""
        self.anim.stop()
        self.anim.setStartValue(self.iconSize())
        self.anim.setEndValue(QSize(240, 240))
        self.anim.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """Zoom out"""
        self.anim.stop()
        self.anim.setStartValue(self.iconSize())
        self.anim.setEndValue(QSize(220, 220))
        self.anim.start()
        super().leaveEvent(event)


class SecuritySuite(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cybersecurity Suite - For Phishing, Malware and Ransomware - Designed by: Osias Nieva Jr.")
        self.setGeometry(200, 100, 1000, 650)
    
        # Dark background
        palette = QPalette()
        # palette.setColor(QPalette.Window, QColor(10, 25, 47))  # darkblue color
        palette.setColor(QPalette.Window, QColor(0, 150, 175)) 
        self.setAutoFillBackground(True)
        self.setPalette(palette)

        main_layout = QVBoxLayout()
        # ------------------------------------------------------------------------------
        top_bar = QHBoxLayout()

        # MMDC rectangular logo (top-left)
        mmdc_logo = QLabel()
        mmdc_logo.setPixmap(QIcon("mmdc.png").pixmap(250, 80))  # Adjust size as needed
        mmdc_logo.setScaledContents(True)

        top_bar.addWidget(mmdc_logo, alignment=Qt.AlignLeft)

        top_bar.addStretch(1)  # push version to the right # addStretch means 

        # Right-side layout (Version + ODS logo stacked vertically)
        right_layout = QVBoxLayout()

        version_label = QLabel("Version 1.0")
        version_label.setFont(QFont("Arial", 10, QFont.Bold))
        version_label.setStyleSheet("color: white; margin: 10px;")
        version_label.setAlignment(Qt.AlignRight)

        logo_row = QHBoxLayout()
        logo_row.addStretch(1)
        my_logo = QLabel()
        my_logo.setPixmap(QIcon("ods.png").pixmap(50, 50))  # small square logo
        my_logo.setScaledContents(True)
        logo_row.addWidget(my_logo, alignment=Qt.AlignCenter)
        logo_row.addStretch(1)

        version_label = QLabel("Version 1.0")
        version_label.setFont(QFont("Arial", 10, QFont.Bold))
        version_label.setStyleSheet("color: white; margin: 10px;")
        version_label.setAlignment(Qt.AlignRight)

        right_layout.addLayout(logo_row)
        right_layout.addWidget(version_label)

        top_bar.addLayout(right_layout)
        main_layout.addLayout(top_bar)
        # ------------------------------------------------------------------------------
        # Horizontal layout for icons
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(25)  # Even spacing between cards
        cards_layout.addStretch(2)
        cards_layout.addLayout(self.create_app_card("malware.png", "Signature Based Malware Detector \n (Future App)"))
        cards_layout.addLayout(self.create_app_card("phish.png", "Signature-Based Phishing Detector \n (ACTUAL CAPSTONE APP)"))
        cards_layout.addLayout(self.create_app_card("ransom.png", "Signature-Based Ransomware Detector \n (Future App)"))
        cards_layout.addStretch(2)

        # Split title into 3 lines
        bottom_text = QLabel(
            "TITLE: Signature-Based Analysis of Open-Source Phishing Toolkits\n"
            "for Machine Learning-Based Detection\n"
            "A Case Study Using BlackEye, Hiddeneye and Zphisher\n"
        )
        bottom_text.setFont(QFont("Arial", 13, QFont.Bold))
        bottom_text.setAlignment(Qt.AlignCenter)
        bottom_text.setStyleSheet("color: white; margin-top: 30px;")
        

        bottom_text2 = QLabel(
            "Application Designed by: Osias Nieva Jr. for MMDC-Capstone 2 2025-2026\n email: lr.onieva@mmdc.mcl.edu.ph"
        )
        bottom_text2.setFont(QFont("Arial", 9))
        bottom_text2.setAlignment(Qt.AlignCenter)
        bottom_text2.setStyleSheet("color: white; margin-top: 30px;")

        # Add everything
        main_layout.addLayout(cards_layout)
        main_layout.addWidget(bottom_text)
        main_layout.addWidget(bottom_text2)

        # 🔹 Disclaimer text (lower center)
        disclaimer = QLabel(
            ("This application is an exclusive property of Mapua-Malayan Digital College and is protected under Republic Act No. 8293,"
                "otherwise known as the Intellectual Property Code of the Philippines. Unauthorized reproduction,\n"
                "distribution, or use of this software, in whole or in part, is strictly prohibited and may result in civil and criminal liabilities."
                "For permissions or inquiries, please contact MMDC-ISD at isd@mmdc.mcl.edu.ph."))
        
        disclaimer.setFont(QFont("Arial", 8))
        disclaimer.setAlignment(Qt.AlignCenter)
        disclaimer.setStyleSheet("color: white; margin-top: 10px; margin-bottom: 5px;")

        main_layout.addWidget(disclaimer, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)

    def create_app_card(self, icon_file, tagline):
        card = QVBoxLayout()
        card.setSpacing(4)

        # Spacer
        card.addSpacerItem(QSpacerItem(150, 150, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Animated button
        button = AnimatedButton(icon_file)

        # 🔹 Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)                    # how soft the shadow looks
        shadow.setXOffset(3)                        # horizontal shift
        shadow.setYOffset(3)                        # vertical shift
        shadow.setColor(QColor(0, 0, 0, 160))       # semi-transparent black
        button.setGraphicsEffect(shadow)

        # Tagline under icon
        tagline_label = QLabel(tagline)
        tagline_label.setFont(QFont("Arial", 11, QFont.Bold))
        tagline_label.setAlignment(Qt.AlignCenter)
        tagline_label.setStyleSheet("color: white;")

        card.addWidget(button, alignment=Qt.AlignCenter)
        card.addWidget(tagline_label)

        # Spacer
        card.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

        return card


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecuritySuite()
    window.show()
    sys.exit(app.exec())