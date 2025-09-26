import sys
import requests
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton,
    QTextEdit, QLabel, QMessageBox
)
from PySide6.QtCore import Qt


class GitHubFileLister(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GitHub File Link Extractor")
        self.setGeometry(400, 200, 600, 400)

        layout = QVBoxLayout()

        self.info_label = QLabel("Enter GitHub Repository URL:")
        layout.addWidget(self.info_label)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("e.g. https://github.com/user/repo")
        layout.addWidget(self.url_input)

        self.fetch_button = QPushButton("Get File Links")
        self.fetch_button.clicked.connect(self.get_file_links)
        layout.addWidget(self.fetch_button)

        # Add Copy and Clear buttons
        self.copy_button = QPushButton("Copy URLs")
        self.copy_button.clicked.connect(self.copy_urls)
        layout.addWidget(self.copy_button)

        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_fields)
        layout.addWidget(self.clear_button)

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        layout.addWidget(self.result_box)

        self.setLayout(layout)

    def get_file_links(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Please enter a valid GitHub repository URL.")
            return

        try:
            # Extract user/repo from URL
            parts = url.replace("https://github.com/", "").split("/")
            if len(parts) < 2:
                QMessageBox.critical(self, "Error", "Invalid GitHub URL format.")
                return

            user, repo = parts[0], parts[1]

            # Get default branch
            repo_api = f"https://api.github.com/repos/{user}/{repo}"
            response = requests.get(repo_api)
            repo_info = response.json()
            print("Repo API response:", repo_info)  # Debug print

            if "default_branch" not in repo_info:
                QMessageBox.critical(self, "Error", f"Repository not found: {repo}\nAPI response: {repo_info}")
                return
            default_branch = repo_info["default_branch"]

            # Get branch info to find commit SHA
            branch_api = f"https://api.github.com/repos/{user}/{repo}/branches/{default_branch}"
            branch_info = requests.get(branch_api).json()
            if "commit" not in branch_info or "sha" not in branch_info["commit"]:
                QMessageBox.critical(self, "Error", "Could not retrieve branch info.")
                return
            sha = branch_info["commit"]["sha"]

            # Get file tree from GitHub API using SHA
            tree_api = f"https://api.github.com/repos/{user}/{repo}/git/trees/{sha}?recursive=1"
            tree_info = requests.get(tree_api).json()

            if "tree" not in tree_info:
                QMessageBox.critical(self, "Error", "Could not retrieve file list.")
                return

            # Extensions to include (add more as needed)
            include_exts = {'.html', '.htm', '.php', '.py', '.js', '.ts', '.css', '.java', '.c', '.cpp', '.cs', '.rb', '.go', '.rs', '.swift', '.kt', '.m', '.sh', '.pl', '.xml', '.json', '.yml', '.yaml'}
            # Extensions to exclude (common image types)
            exclude_exts = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.bmp', '.ico', '.webp', '.tiff'}

            file_links = []
            for item in tree_info["tree"]:
                if item["type"] == "blob":
                    ext = '.' + item['path'].split('.')[-1].lower() if '.' in item['path'] else ''
                    if ext in include_exts and ext not in exclude_exts:
                        github_url = f"https://github.com/{user}/{repo}/blob/{default_branch}/{item['path']}"
                        file_links.append(github_url)

            # Display results
            if file_links:
                self.result_box.setPlainText("\n".join(file_links))
            else:
                self.result_box.setPlainText("No files found in repository.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")

    def copy_urls(self):
        urls = self.result_box.toPlainText()
        if urls:
            clipboard = QApplication.clipboard()
            clipboard.setText(urls)

    def clear_fields(self):
        self.url_input.clear()
        self.result_box.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GitHubFileLister()
    window.show()
    sys.exit(app.exec())