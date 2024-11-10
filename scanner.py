import os
import re
import time

# Directory to scan for files
scan_directory = r'FILE LOC'

# Patterns based on provided malicious code
malware_patterns = [
        r"random_char\s?=\s?\{.*?\}",  # Array with obfuscated data
        r"Enchanced_Tabs\s?=\s?\{.*?\}",  # Array with function obfuscation
        r"assert\(load",  # Dynamic code loading
        r"GetResourcePath\(",  # Resource path in file manipulation
        r"io\.open\(.*(/server/|/client/|fxmanifest\.lua)",  # File operations in sensitive paths
        r'\\x[0-9a-fA-F]{2}',  # Hexadecimal character codes
        r'assert\(load',  # Redundant dynamic code loading pattern
        r'io\.open',  # General file manipulation
        r'_G\[.*\]',  # General global manipulation
        r'dhttps://gettingabsence.com',
]

# Function to scan and clean a single file by deleting entire lines containing suspicious patterns
def clean_file(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as file:
            lines = file.readlines()
            original_lines = lines[:]  # Copy of original lines for comparison

        # Track patterns found in this file
        found_patterns = []

        # Iterate over patterns and remove lines containing any suspicious patterns
        for pattern in malware_patterns:
            new_lines = []
            for line in lines:
                if re.search(pattern, line):
                    found_patterns.append(pattern)
                else:
                    new_lines.append(line)
            lines = new_lines  # Update lines to exclude the deleted lines

        # If any lines were removed, overwrite the file with cleaned content
        if lines != original_lines:
            with open(filepath, 'w') as file:
                file.writelines(lines)
            return found_patterns
        return None
    except Exception as e:
        print(f"Error cleaning file {filepath}: {e}")
        return None

# Function to scan and clean suspicious files
def scan_and_clean_suspicious_files(directory):
    cleaned_files = {}
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            found_patterns = clean_file(file_path)
            if found_patterns:
                cleaned_files[file_path] = found_patterns
                print(f"Cleaned file: {file_path}")
                for pattern in found_patterns:
                    print(f"  - Removed lines containing pattern: {pattern}")
    return cleaned_files

# Continuous scanning loop
while True:
    print("Starting malware scan and clean process...")
    cleaned_files = scan_and_clean_suspicious_files(scan_directory)
    
    if cleaned_files:
        print("\nSummary of cleaned files:")
        for file, patterns in cleaned_files.items():
            print(f"{file} - Removed lines containing patterns:")
            for pattern in patterns:
                print(f"  - {pattern}")
    else:
        print("No suspicious files detected.")
    
    # Wait before the next scan (e.g., 5 minutes)
    time.sleep(300)  # 300 seconds = 5 minutes
