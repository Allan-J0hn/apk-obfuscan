# APK Obfuscan

## Introduction
APK Obfuscan is a static analysis tool designed to extract and analyze artifacts from Android APK files. It performs a two-stage analysis:

    Stage 1: Extracts metadata, dex strings, resource strings, and preliminary secrets (such as API keys and tokens).
    Stage 2: Deeply analyzes the extracted data, including categorizing strings, decoding Base64, flagging potentially obfuscated strings, and scanning for credentials and secrets.

For very large outputs, the tool automatically breaks results into manageable chunks (e.g., "Potentially Obfuscated 1", "Potentially Obfuscated 2", etc.) so that each JSON file remains readable.

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

To analyze a single APK file:
python3 src/static_analyzer.py
You will be prompted to enter the APK file path.

To analyze multiple APKs
To scan a directory containing multiple APKs:
python src/static_analyzer.py
When prompted, enter the folder path containing the APK files.

## Understanding the output
The tool produces JSON output files for each processed APK:

Artifacts JSON (<apk_name>_artifacts.json):
 Contains:
 
  Extracted metadata (package name, version)
  Dex and resource strings
  Preliminary secrets detected using regex patterns

Stage 2 Analysis JSON (<apk_name>_stage2.json):
 Contains:
 
  Categorized Strings: Strings are grouped (e.g., short, alphanumeric, general).
  Decoded Base64 Strings: Successfully decoded Base64 strings.
  Potentially Obfuscated Strings: High-entropy strings flagged as suspicious, split into chunks (e.g., "Potentially Obfuscated 1", "Potentially Obfuscated 2", etc.) if the list is large.
  Detected Credentials and Secrets: API keys, JWT tokens, passwords, and similar items, also chunked when needed.

This breakdown allows you to review the output without being overwhelmed by excessively large files. It also helps to decide if further dynamic analysis (e.g., using Frida) is required.

## Disclaimer

This tool is intended for educational and research purposes only. The author does not endorse or support any illegal activities, and this tool should only be used on applications you have explicit permission to analyze. 

By using this tool, you agree that the author is not responsible for any misuse, damages, or legal consequences resulting from its usage. Ensure you comply with all applicable laws and regulations before using this software.


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
If you encounter issues, open a GitHub issue here: https://github.com/Allan-J0hn/apk-obfuscan> or send an email to destiny.sagger4p@icloud.com

