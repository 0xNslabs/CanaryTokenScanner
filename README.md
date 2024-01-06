# Canary Token Scanner

## Detecting Canary Tokens and Suspicious URLs in Microsoft Office Files

### Introduction:

In the ever-evolving landscape of cybersecurity, awareness and proactive measures are crucial. Malicious actors often exploit seemingly innocuous Microsoft Office files, embedding hidden URLs or macros to execute harmful actions. This Python script is designed to detect potential threats by examining the contents of Microsoft Office documents without directly opening them, minimizing the risk of triggering malicious code unintentionally.

### Understanding the Script:

#### Identification:
The script intelligently identifies Microsoft Office documents by their file extensions (.docx, .xlsx, or .pptx). These file types are essentially zip archives that can be programmatically explored.

#### Decompression and Scanning:
Upon identification, the script renames the file to a .zip extension and decompresses it into a temporary directory. It then scans the contents for URLs using regular expressions, seeking potential indicators of compromise.

#### Ignoring Certain URLs:
To avoid false positives, the script includes a list of ignored domains, filtering out benign URLs commonly found in Office documents. This ensures a focused analysis on unexpected or potentially harmful URLs.

#### Flagging Suspicious Files:
If the script identifies URLs not on the ignored list, it marks the file as suspicious. This heuristic approach allows customization based on the specific security context and threat model of your environment.

#### Cleanup and Restoration:
After scanning, the script cleans up by deleting temporary decompressed files and restoring the original file name, leaving no residual clutter.

### Usage:

To utilize the script effectively:

1. **Setup:**
   - Ensure Python is installed on your system.
   - Place the script in a convenient location.
   - Run the script using the command: `python CanaryTokenScanner.py OFFICE_FILE_PATH` (Replace OFFICE_FILE_PATH with the actual file or directory path.)

2. **Interpretation:**
   - Review the output. Keep in mind that this script is a starting point; flagged documents may not be malicious, and malicious documents may not always be flagged. Manual review and additional security measures are recommended.

### Disclaimer:

This script is meant for educational and security testing purposes only. Use responsibly and ensure compliance with applicable laws and regulations.

