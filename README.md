# CanaryToken / HoneyToken Scanner

Detect suspicious URLs (including CanaryTokens) inside **Microsoft Office documents** and **PDFs**.

Supported formats:
- Office Open XML: **.docx, .xlsx, .pptx**
- **.pdf**
- **.zip** (generic archives)

## Why this exists

CanaryTokens an HoneyTokens (and other tracking or malicious URLs) are often embedded in documents to signal when a file is opened or when an external resource is fetched. This tool performs **static inspection only**: it reads file contents and looks for embedded URLs **without opening the document in Office/Acrobat** and without making any network requests.

## How it works

### Office / Zip scanning (DOCX/XLSX/PPTX/ZIP)
- Office documents are ZIP containers under the hood.
- The scanner reads ZIP members **directly** and searches for `http://` and `https://` URLs.
- Common, expected schema domains are ignored to reduce noise:
  - `schemas.openxmlformats.org`
  - `schemas.microsoft.com`
  - `purl.org`
  - `w3.org`

### PDF scanning
The scanner searches for URLs in:
- Raw PDF bytes (many PDFs store URLs plainly in `/URI(...)`)
- Compressed PDF streams (`stream ... endstream`) by attempting Flate/deflate decompression

### Output
- If suspicious URLs are found, the script prints them and reports the file as suspicious.
- If nothing interesting is found, the file is reported as normal.

## Usage

Run against a single file:

```bash
python CanaryTokenScanner.py /path/to/document.pdf
```

Run against a directory (recursive):

```bash
python CanaryTokenScanner.py /path/to/folder
```

Example output:

```text
URL Found in /path/to/file.docx:
https://example.com/track/abc123

The file /path/to/file.docx is suspicious.
```

## V2: What changed (performance + improvements)

- **No more extraction to disk**: Office/ZIP files are scanned in-memory instead of being extracted to a temporary directory.
- **Faster scans**: avoids filesystem overhead and repeated reads.
- **Better PDF coverage**: detects URLs in both raw PDF content and Flate/deflate-compressed streams.
- **Cleaner results**: still filters common schema domains to reduce false positives.

## Notes / limitations

- This is a heuristic URL detector. A URL being present does not automatically mean it is malicious.
- Some PDFs use compression/filter combinations not covered by simple Flate/deflate decompression.
- Encrypted or heavily obfuscated files may reduce detection accuracy.

## Script showcase

![Canary Token Scanner in Action](https://raw.githubusercontent.com/0xNslabs/CanaryTokenDetector/main/demo.png)

## Disclaimer

This script is intended for educational and security testing purposes only. Use it responsibly and in compliance with applicable laws and organizational policies. The author(s) assume no liability for misuse or for actions taken based on the output of this tool.
