# APK Obfuscan

Introduction
APK Obfuscan is a static analysis tool for detecting string obfuscation and hardcoded secrets

## Installation

### 1. Clone the Repository
First, download the project from GitHub:
git clone https://github.com/Allan-J0hn/apk-obfuscan.git
cd apk-obfuscan

### 2. Set Up a Virtual Environment
To avoid dependency conflicts, create and activate a virtual environment:

For Linux/macOS:
python3 -m venv obfuscan-env
source obfuscan-env/bin/activate

For Windows (PowerShell):
python -m venv obfuscan-env
obfuscan-env\Scripts\activate

### 3. Install Dependencies
Once inside the virtual environment, install the required dependencies:
pip install -r requirements.txt

## How to Use APK Obfuscan

Analyze a Single APK
To analyze a single APK file:
python3 src/static_analyzer.py
You will be prompted to enter the APK file path.

Analyze Multiple APKs
To scan a directory containing multiple APKs:
python src/static_analyzer.py
When prompted, enter the folder path containing the APK files.

Understanding the Output
The script generates a CSV report (apk_analysis_results.csv) with the following details:
- Extracted Strings: All readable strings from the APK.
- Detected Secrets: API keys, JWT tokens, passwords, etc.
- Obfuscation Indicators: Detects ProGuard/R8 obfuscation.

This output helps determine whether further dynamic analysis (Frida) is necessary.

## Troubleshooting

### 1. Error: ModuleNotFoundError
If you see an error like:
ModuleNotFoundError: No module named 'androguard'

Ensure the virtual environment is activated:
source obfuscan-env/bin/activate  (Linux/macOS)
obfuscan-env\Scripts\activate     (Windows)

Reinstall dependencies:
pip install -r requirements.txt

### Need Help?
If you encounter issues, open a GitHub issue here: https://github.com/Allan-J0hn/apk-obfuscan>

