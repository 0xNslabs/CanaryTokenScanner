import os
import zipfile
import re
import sys
import zlib

if len(sys.argv) != 2:
    print("Usage: python script.py FILE_OR_DIRECTORY_PATH")
    sys.exit(1)

FILE_OR_DIRECTORY_PATH = sys.argv[1]

URL_BYTES_RE = re.compile(rb'https?://[^\s<>"\'{}|\\^`]+')
PDF_STREAM_RE = re.compile(rb'stream[\r\n\s]+(.*?)[\r\n\s]+endstream', re.DOTALL)

IGNORED_DOMAINS = (
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "w3.org",
)

MAX_ZIP_MEMBER_SIZE = 20 * 1024 * 1024


def _is_ignored_url(url: str) -> bool:
    u = url.lower()
    return any(d in u for d in IGNORED_DOMAINS)


def _clean_url_text(url: str) -> str:
    return url.replace("/QXUGUTAENT)", "").strip().strip(")").strip(">").strip("<").strip('"').strip("'")


def extract_urls_from_stream(stream_bytes: bytes):
    urls = []

    try:
        decompressed = zlib.decompress(stream_bytes)
        urls.extend(URL_BYTES_RE.findall(decompressed))
        return urls
    except zlib.error:
        pass

    try:
        decompressed = zlib.decompress(stream_bytes, -zlib.MAX_WBITS)
        urls.extend(URL_BYTES_RE.findall(decompressed))
    except zlib.error:
        pass

    return urls


def process_pdf_file(pdf_path: str):
    with open(pdf_path, "rb") as f:
        pdf_content = f.read()

    found = set(URL_BYTES_RE.findall(pdf_content))

    for m in PDF_STREAM_RE.finditer(pdf_content):
        stream = m.group(1)
        for u in extract_urls_from_stream(stream):
            found.add(u)

    return list(found)


def scan_zip_for_urls(file_path: str):
    is_suspicious = False
    seen = set()

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_ZIP_MEMBER_SIZE:
                    continue

                try:
                    with zf.open(info, "r") as fp:
                        data = fp.read()
                except Exception:
                    continue

                for u in URL_BYTES_RE.findall(data):
                    if u in seen:
                        continue
                    seen.add(u)

                    url_text = _clean_url_text(u.decode("utf-8", "ignore"))
                    if not url_text or _is_ignored_url(url_text):
                        continue

                    print(f"URL Found in {file_path}:\n{url_text}")
                    is_suspicious = True

    except zipfile.BadZipFile:
        return False
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return False

    return is_suspicious


def is_suspicious_file(file_path: str):
    lower = file_path.lower()

    if lower.endswith((".zip", ".docx", ".xlsx", ".pptx")):
        return scan_zip_for_urls(file_path)

    if lower.endswith(".pdf"):
        urls = process_pdf_file(file_path)
        printed_any = False
        if urls:
            for url_bytes in urls:
                url_text = _clean_url_text(url_bytes.decode("utf-8", "ignore"))
                if not url_text or _is_ignored_url(url_text):
                    continue
                if not printed_any:
                    print(f"The file {file_path} is suspicious. URLs found:")
                    printed_any = True
                print(url_text)
            return printed_any

    return False


def main():
    if os.path.exists(FILE_OR_DIRECTORY_PATH):
        if os.path.isfile(FILE_OR_DIRECTORY_PATH):
            if is_suspicious_file(FILE_OR_DIRECTORY_PATH):
                print(f"The file {FILE_OR_DIRECTORY_PATH} is suspicious.")
            else:
                print(f"The file {FILE_OR_DIRECTORY_PATH} seems normal.")
        elif os.path.isdir(FILE_OR_DIRECTORY_PATH):
            for root, dirs, files in os.walk(FILE_OR_DIRECTORY_PATH):
                for file_name in files:
                    current_file_path = os.path.join(root, file_name)
                    if is_suspicious_file(current_file_path):
                        print(f"The file {current_file_path} is suspicious.")
                    else:
                        print(f"The file {current_file_path} seems normal.")
    else:
        print(f"The path {FILE_OR_DIRECTORY_PATH} does not exist.")


if __name__ == "__main__":
    main()
