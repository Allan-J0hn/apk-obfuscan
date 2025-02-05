import os
import re
import csv
from androguard.misc import AnalyzeAPK

# Regex patterns for detecting hardcoded secrets
secrets_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.?[a-zA-Z0-9-_]*",
    "Base64 String": r"[A-Za-z0-9+/=]{16,}",
    "Generic Password": r"password=['\"]?(\w{6,})['\"]?",
}

def analyze_apk(apk_path):
    """ Perform static analysis on a single APK file """
    try:
        print(f"\n[INFO] Analyzing APK: {apk_path}")
        apk, dvm, dx = AnalyzeAPK(apk_path)
        
        if apk is None or dvm is None or dx is None:
            print(f"[ERROR] Failed to analyze {apk_path}: Invalid APK structure.")
            return None

        package_name = apk.get_package()

        # Handle case where get_strings() might not exist or return unexpected types
        extracted_strings = []
        if hasattr(dvm, "get_strings"):
            extracted_strings = dvm.get_strings()
        elif isinstance(dvm, list):
            for item in dvm:
                if hasattr(item, "get_strings"):
                    extracted_strings = item.get_strings()
                    break  # Use first valid item
        if not isinstance(extracted_strings, list):
            extracted_strings = []

        # Detect hardcoded secrets
        found_secrets = []
        for string in extracted_strings:
            for secret_type, pattern in secrets_patterns.items():
                if re.match(pattern, string):
                    found_secrets.append(f"{secret_type}: {string}")

        # Detect obfuscation
        obfuscated_methods = []
        if hasattr(dvm, "get_methods"):
            obfuscated_methods = [method.name for method in dvm.get_methods() if len(method.name) == 1]

        is_obfuscated = "Yes" if obfuscated_methods else "No"

        # Output results
        result = {
            "APK Name": os.path.basename(apk_path),
            "Package Name": package_name,
            "Potential Secrets": found_secrets if found_secrets else "None",
            "Obfuscated": is_obfuscated
        }

        return result

    except Exception as e:
        print(f"[ERROR] Failed to analyze {apk_path}: {e}")
        return None

def main():
    """ Main function to handle user input and run analysis in a loop """
    while True:
        choice = input("Are you analyzing a single APK or multiple APKs? (single/multiple): ").strip().lower()
        results = []
        
        if choice == "single":
            apk_path = input("Enter the APK file path: ").strip()
            if not os.path.exists(apk_path):
                print("[ERROR] File does not exist. Try again.")
                continue
            result = analyze_apk(apk_path)
            if result:
                results.append(result)
        
        elif choice == "multiple":
            folder_path = input("Enter the folder path containing APKs: ").strip()
            if not os.path.exists(folder_path):
                print("[ERROR] Folder does not exist. Try again.")
                continue

            for apk_file in os.listdir(folder_path):
                if apk_file.endswith(".apk"):
                    apk_path = os.path.join(folder_path, apk_file)
                    analysis_result = analyze_apk(apk_path)
                    if analysis_result:
                        results.append(analysis_result)

        else:
            print("[ERROR] Invalid choice. Try again.")
            continue

        if not results:
            print("\n[INFO] No valid APKs were analyzed.")
        else:
            # Save results to CSV
            output_file = "apk_analysis_results.csv"
            with open(output_file, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=["APK Name", "Package Name", "Potential Secrets", "Obfuscated"])
                writer.writeheader()
                for row in results:
                    if row:  # Ensure row is not None
                        writer.writerow(row)

            print(f"\n[INFO] Analysis completed. Results saved in: {output_file}")

        # Ask user if they want to analyze another APK or exit
        again = input("\nWould you like to analyze another APK? (yes/no): ").strip().lower()
        if again != "yes":
            print("\n[INFO] Exiting the script.")
            break

if __name__ == "__main__":
    main()
