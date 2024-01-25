# Canary Token Scanner

## Detecting Canary Tokens and Suspicious URLs in Microsoft Office, Acrobat Reader PDF and Zip Files

### Introduction

In the dynamic realm of cybersecurity, vigilance and proactive defense are key. Malicious actors often leverage Microsoft Office files and Zip archives, embedding covert URLs or macros to initiate harmful actions. This Python script is crafted to detect potential threats by scrutinizing the contents of Microsoft Office documents, Acrobat Reader PDF documents and Zip files, reducing the risk of inadvertently triggering malicious code.

### Understanding the Script

#### Identification
The script smartly identifies Microsoft Office documents (.docx, .xlsx, .pptx), Acrobat Reader PDF documents (.pdf) and Zip files. These file types, including Office documents, are zip archives that can be examined programmatically.

#### Decompression and Scanning
For both Office and Zip files, the script decompresses the contents into a temporary directory. It then scans these contents for URLs using regular expressions, searching for potential signs of compromise.

#### Ignoring Certain URLs
To minimize false positives, the script includes a list of domains to ignore, filtering out common URLs typically found in Office documents. This ensures focused analysis on unusual or potentially harmful URLs.

#### Flagging Suspicious Files
Files with URLs not on the ignored list are marked as suspicious. This heuristic method allows for adaptability based on your specific security context and threat landscape.

#### Cleanup and Restoration
Post-scanning, the script cleans up by erasing temporary decompressed files, leaving no traces.

### Usage

To effectively utilize the script:

1. **Setup**
   - Ensure Python is installed on your system.
   - Position the script in an accessible location.
   - Execute the script with the command: `python CanaryTokenScanner.py FILE_OR_DIRECTORY_PATH` (Replace `FILE_OR_DIRECTORY_PATH` with the actual file or directory path.)

2. **Interpretation**
   - Examine the output. Remember, this script is a starting point; flagged documents might not be harmful, and not all malicious documents will be flagged. Manual examination and additional security measures are advisable.

### Script Showcase

![Canary Token Scanner in Action](https://raw.githubusercontent.com/0xNslabs/CanaryTokenDetector/main/demo.png)
*An example of the Canary Token Scanner script in action, demonstrating its capability to detect suspicious URLs.*

### Disclaimer

This script is intended for educational and security testing purposes only. Utilize it responsibly and in compliance with applicable laws and regulations.
