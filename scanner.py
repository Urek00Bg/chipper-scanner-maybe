import os
import re
import time

# Directory to scan for files
scan_directory = '/path/to/your/directory'

# Patterns based on provided malicious code
malware_patterns = [
    r"random_char\s?=\s?\{.*?\}",  # Hexadecimal character codes for URLs
    r"Enchanced_Tabs\s?=\s?\{.*?\}",  # Array setup with obfuscated functions
    r"PerformHttpRequest\(",  # Detects external HTTP request functions
    r"assert\(load",  # Dynamic code loading function
    r"GetResourcePath\(",  # Resource path access in file manipulation
    r"io\.open\(.*(/server/|/client/|fxmanifest\.lua)",  # File operations to sensitive paths
    r"_G\['(PerformHttpRequest|assert|load|tonumber)'\]",  # Global access with obfuscated functions
]

# Function to scan a single file for specific malware patterns
def scan_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as file:
            content = file.read()
            for pattern in malware_patterns:
                if re.search(pattern, content):
                    return True, pattern
        return False, None
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return False, None

# Function to scan all files in the directory and log suspicious ones
def scan_and_log_suspicious_files(directory):
    suspicious_files = {}
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            is_suspicious, matched_pattern = scan_file(file_path)
            if is_suspicious:
                suspicious_files[file_path] = matched_pattern
                print(f"Suspicious file found: {file_path} - Pattern: {matched_pattern}")
    return suspicious_files

# Continuous scanning loop
while True:
    print("Starting malware scan and log process...")
    suspicious_files = scan_and_log_suspicious_files(scan_directory)
    
    if suspicious_files:
        print("\nReview the following suspicious files:")
        for file, pattern in suspicious_files.items():
            print(f"{file} - Detected pattern: {pattern}")
    else:
        print("No suspicious files detected.")

    # Wait before the next scan
    time.sleep(300)  # 5 minutes between scans