#!/usr/bin/env python3

import os
import glob
import json
import re
import math
import base64
import multiprocessing
import string

from androguard.misc import AnalyzeAPK

##################################################
# STAGE 1: APK EXTRACTION
##################################################

def extract_artifacts(apk_path):
    """
    Extract minimal artifacts from the given APK:
    1. Metadata (package_name, version)
    2. Dex strings
    3. Resource strings (if available)
    4. Preliminary secrets (AWS, Google, JWT, etc.)
    Returns a dict representing the data or an error.
    """
    try:
        print(f"[INFO] Processing (Stage 1): {apk_path}")
        apk, dvm, dx = AnalyzeAPK(apk_path)
        if not apk or not dvm:
            return {
                "apk_path": apk_path,
                "error": "Failed to parse with Androguard"
            }
        
        package_name = apk.get_package()
        version_name = apk.get_androidversion_name() or ""
        version_code = apk.get_androidversion_code() or ""

        # Dex strings
        dvm_objects = dvm if isinstance(dvm, list) else [dvm]
        dex_strings = []
        for dvm_obj in dvm_objects:
            if hasattr(dvm_obj, "get_strings"):
                dex_strings.extend(dvm_obj.get_strings())

        # Resource strings (best effort)
        resource_strings = []
        try:
            res_parser = apk.get_android_resources()
            if res_parser:
                resolved_strings = res_parser.get_resolved_strings()
                if resolved_strings:
                    for _, val in resolved_strings.items():
                        resource_strings.append(str(val))
        except Exception as e:
            print(f"[WARN] Resource parsing failed for {apk_path}: {e}")

        # Preliminary secrets with simple regex patterns:
        secrets_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]*",
            "Generic Password": r"password=['\"]?(\w{6,})['\"]?"
        }
        found_secrets = {
            "AWS Access Key": [],
            "Google API Key": [],
            "JWT Token": [],
            "Generic Password": []
        }

        combined_strings = dex_strings + resource_strings
        for s in combined_strings:
            for secret_type, pattern in secrets_patterns.items():
                if re.search(pattern, s):
                    found_secrets[secret_type].append(s)
        
        return {
            "apk_path": apk_path,
            "package_name": package_name,
            "version_name": version_name,
            "version_code": version_code,
            "dex_strings": dex_strings,
            "resource_strings": resource_strings,
            "found_secrets_stage1": found_secrets
        }

    except Exception as e:
        return {
            "apk_path": apk_path,
            "error": str(e)
        }

def process_apk_stage1(apk_path):
    """
    Worker function for Stage 1.
    Extracts artifacts and writes JSON <apk_name>_artifacts.json
    """
    result = extract_artifacts(apk_path)
    base_name = os.path.basename(apk_path)
    apk_name, _ = os.path.splitext(base_name)
    output_file = f"{apk_name}_artifacts.json"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)
        print(f"[INFO] Stage 1 JSON saved to {output_file}")
    except Exception as e:
        print(f"[ERROR] Failed writing Stage 1 JSON for {apk_path}: {e}")

def run_stage_one(folder_path, pool_size=4):
    """
    Finds .apk files in folder_path, processes them in parallel for Stage 1.
    """
    apk_files = glob.glob(os.path.join(folder_path, "*.apk"))
    if not apk_files:
        print("[ERROR] No .apk files found.")
        return
    print(f"[INFO] Found {len(apk_files)} APK(s). Running Stage 1 with pool={pool_size}...")

    with multiprocessing.Pool(pool_size) as pool:
        pool.map(process_apk_stage1, apk_files)

    print("[INFO] Stage 1 Extraction Complete.\n")

##################################################
# STAGE 2: DEEPER ANALYSIS ON EXTRACTED ARTIFACTS
##################################################

def is_definite_noise(s):
    """
    Filter out strings likely to be noise:
    - length < 3
    - containing '.java'
    """
    if len(s) < 3:
        return True
    if ".java" in s.lower():
        return True
    return False

def is_potential_base64(s):
    # Minimal check: must be at least 24 chars, matches base64 chars/padding
    base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if len(s) < 24:
        return False
    return bool(re.match(base64_pattern, s))

def single_pass_base64_decode(s):
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        return {
            "original": s,
            "decoded": decoded_str,
            "valid_decode": True
        }
    except Exception:
        return {
            "original": s,
            "decoded": None,
            "valid_decode": False
        }

def calculate_entropy(s):
    if not s:
        return 0.0
    prob = [s.count(ch) / len(s) for ch in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def categorize_string(s):
    """
    A simple categorization for the string.
    You can expand this function to have more detailed categorization.
    """
    # Example categorization logic: classify as 'short', 'long', or 'suspicious'
    if len(s) < 20:
        return "short"
    elif any(char.isdigit() for char in s) and any(char.isalpha() for char in s):
        return "alphanumeric"
    else:
        return "general"

def stage_two_analyze(artifact_data):
    """
    Analyze Stage 1 artifact data, apply:
    - noise filtering
    - string categorization
    - single-pass base64 decoding
    - credential/key scanning
    - high-entropy (obfuscation) flagging
    - confidence classification (HIGH, MEDIUM, LOW)
    """

    # Patterns for secrets scanning
    secrets_patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]*",
        "Generic Password": r"password=['\"]?(\w{6,})['\"]?"
    }
    user_pass_pattern = r"(user(name)?|login)\s*=\s*(\S+).*(pass(word)?|pwd)\s*=\s*(\S+)"
    basic_email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

    stage2_results = {
        "noise_filtered_out": [],
        "categorized_strings": {},
        "decoded_base64_strings": [],
        "credentials_found": [],
        "keys_tokens": [],
        "suspected_obfuscated": []
    }

    dex_strings = artifact_data.get("dex_strings", [])
    resource_strings = artifact_data.get("resource_strings", [])
    all_strings = dex_strings + resource_strings

    for s in all_strings:
        s = s.strip()

        # 1. Noise check
        if is_definite_noise(s):
            stage2_results["noise_filtered_out"].append(s)
            continue

        # 2. Categorize
        category = categorize_string(s)
        if category not in stage2_results["categorized_strings"]:
            stage2_results["categorized_strings"][category] = []
        stage2_results["categorized_strings"][category].append(s)

        # 3. Base64 decode check
        decoded_info = None
        if is_potential_base64(s):
            decoded_info = single_pass_base64_decode(s)
            if decoded_info["valid_decode"]:
                stage2_results["decoded_base64_strings"].append(decoded_info)

        text_to_scan = decoded_info["decoded"] if (decoded_info and decoded_info["valid_decode"]) else s

        # 4. Credential / Key scanning
        found_matches = []
        for secret_type, pattern in secrets_patterns.items():
            if re.search(pattern, text_to_scan):
                found_matches.append({
                    "type": secret_type,
                    "value": text_to_scan,
                    "reason": f"Matches {secret_type} pattern"
                })

        if re.search(user_pass_pattern, text_to_scan, re.IGNORECASE):
            found_matches.append({
                "type": "UserPassCombo",
                "value": text_to_scan,
                "reason": "Detected user/pass pattern"
            })

        if re.search(basic_email_pattern, text_to_scan):
            found_matches.append({
                "type": "EmailDetected",
                "value": text_to_scan,
                "reason": "Found email pattern in string"
            })

        # 5. Assign confidence + categorize
        for match_item in found_matches:
            secret_type = match_item["type"]
            if secret_type in ["AWS Access Key", "Google API Key", "JWT Token"]:
                confidence = "HIGH"
                match_category = "keys_tokens"
            elif secret_type in ["UserPassCombo", "Generic Password"]:
                confidence = "HIGH"
                match_category = "credentials_found"
            elif secret_type in ["EmailDetected"]:
                confidence = "MEDIUM"
                match_category = "credentials_found"
            else:
                confidence = "LOW"
                match_category = "credentials_found"

            match_item["confidence"] = confidence
            stage2_results[match_category].append(match_item)

        # 6. High entropy => suspicious
        if not found_matches:
            ent = calculate_entropy(text_to_scan)
            if ent > 4.0:
                stage2_results["suspected_obfuscated"].append({
                    "value": text_to_scan,
                    "reason": f"High entropy ~ {ent:.2f}",
                    "confidence": "LOW"
                })

    artifact_data["stage2_analysis"] = stage2_results
    return artifact_data

def run_stage_two(artifact_folder):
    """
    Finds all *_artifacts.json in artifact_folder from Stage 1,
    loads them, runs stage_two_analyze, and writes <apk_name>_stage2.json.
    """
    json_files = glob.glob(os.path.join(artifact_folder, "*_artifacts.json"))
    if not json_files:
        print("[ERROR] No *_artifacts.json files found for Stage 2.")
        return

    for jf in json_files:
        print(f"[INFO] Processing (Stage 2): {jf}")
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)

        updated_data = stage_two_analyze(data)

        out_name = jf.replace("_artifacts.json", "_stage2.json")
        try:
            with open(out_name, "w", encoding="utf-8") as out_f:
                json.dump(updated_data, out_f, indent=4)
            print(f"[INFO] Stage 2 analysis saved to {out_name}")
        except Exception as e:
            print(f"[ERROR] Writing Stage 2 JSON {out_name}: {e}")

    print("[INFO] Stage 2 Analysis Complete.\n")

##################################################
# HELPER FUNCTION FOR SINGLE APK PROCESSING
##################################################

def process_single_apk(apk_path):
    """
    Process a single APK file: runs Stage 1 extraction and then Stage 2 analysis.
    """
    # Run Stage 1 for the APK
    process_apk_stage1(apk_path)
    
    # Construct artifacts filename
    base_name = os.path.basename(apk_path)
    apk_name, _ = os.path.splitext(base_name)
    artifact_file = f"{apk_name}_artifacts.json"
    
    if not os.path.isfile(artifact_file):
        print(f"[ERROR] Artifacts file {artifact_file} not found. Stage 1 might have failed.")
        return
    
    # Load the artifacts data
    try:
        with open(artifact_file, "r", encoding="utf-8") as f:
            artifact_data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load {artifact_file}: {e}")
        return
    
    # Run Stage 2 analysis on the artifact data
    updated_data = stage_two_analyze(artifact_data)
    
    # Write Stage 2 JSON output
    stage2_file = f"{apk_name}_stage2.json"
    try:
        with open(stage2_file, "w", encoding="utf-8") as out_f:
            json.dump(updated_data, out_f, indent=4)
        print(f"[INFO] Stage 2 analysis saved to {stage2_file}")
    except Exception as e:
        print(f"[ERROR] Writing Stage 2 JSON {stage2_file}: {e}")

##################################################
# MAIN: CLI / MENU
##################################################

def main():
    while True:
        print("===========================================")
        print("                APK Secret Decoder         ")
        print("===========================================")
        print("Please choose an option:")
        print("1) Analyze a single APK file")
        print("2) Analyze multiple APK files (directory)")
        print("0) Exit")
        print("======================================")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            file_path = input("Enter the full path to the APK file: ").strip()
            if os.path.isfile(file_path):
                process_single_apk(file_path)
                print("[INFO] Processing complete for the single APK.\n")
            else:
                print("[ERROR] The file does not exist. Please try again.\n")
        elif choice == "2":
            folder = input("Enter the folder path containing APK files: ").strip()
            if os.path.isdir(folder):
                run_stage_one(folder, pool_size=4)
                run_stage_two(folder)
            else:
                print("[ERROR] The folder does not exist. Please try again.\n")
        elif choice == "0":
            print("[INFO] Exiting.")
            break
        else:
            print("[ERROR] Invalid choice. Please try again.\n")

if __name__ == "__main__":
    main()
