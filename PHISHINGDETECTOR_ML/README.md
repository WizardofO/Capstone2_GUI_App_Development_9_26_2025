# Phishing Detector Chrome Extension

## Overview
The Phishing Detector is a Chrome extension that allows users to check if a URL is potentially a phishing site. It interacts with a Flask application to perform the detection and provides feedback to the user through a simple popup interface.

## Project Structure
```
PHISHINGDETECTOR_ML
├── background.js
├── content.js
├── manifest.json
├── popup.html
├── popup.js
├── styles
│   └── popup.css
├── utils
│   └── api.js
└── README.md
```

## Files Description
- **background.js**: Background script for managing events and long-running tasks.
- **content.js**: Content script that can interact with web pages.
- **manifest.json**: Configuration file for the Chrome extension, defining metadata and permissions.
- **popup.html**: HTML for the popup interface, including an input field for the URL and a detection button.
- **popup.js**: JavaScript logic for handling user interactions and communicating with the Flask application.
- **styles/popup.css**: CSS styles for the popup interface.
- **utils/api.js**: Utility functions for making API calls to the Flask application.

## Installation
1. Clone or download the repository to your local machine.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable "Developer mode" by toggling the switch in the top right corner.
4. Click on "Load unpacked" and select the `PHISHINGDETECTOR_ML` folder.
5. The extension should now be loaded and visible in your extensions list.

## Usage
1. Click on the Phishing Detector icon in the Chrome toolbar to open the popup.
2. Enter a URL in the input field.
3. Click the "Detect" button to check if the URL is a phishing site.
4. The result will be displayed below the button, showing either an error message or the detection result with a label and score.

## Notes
- Ensure that the Flask application is running on `http://localhost:5000` for the extension to function correctly.
- You may need to adjust CORS settings in the Flask app if you encounter any issues with requests from the extension.

## License
This project is licensed under the MMDC License 2025.
