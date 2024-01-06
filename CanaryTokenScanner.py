import os
import zipfile
import re
import shutil
import sys

if len(sys.argv) != 2:
    print("Usage: python script.py FILE_OR_DIRECTORY_PATH")
    sys.exit(1)

FILE_OR_DIRECTORY_PATH = sys.argv[1]

def decompress_and_scan(file_path):
    is_suspicious = False
    temp_dir = "temp_extracted"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # If it's a zip file or an Office file (which is technically a zip), extract it
        if file_path.endswith('.zip') or file_path.endswith(('.docx', '.xlsx', '.pptx')):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

        url_pattern = re.compile(r'https?://\S+')
        ignored_domains = ['schemas.openxmlformats.org', 'schemas.microsoft.com', 'purl.org', 'w3.org']

        for root, dirs, files in os.walk(temp_dir):
            for file_name in files:
                extracted_file_path = os.path.join(root, file_name)
                with open(extracted_file_path, 'r', errors='ignore') as extracted_file:
                    contents = extracted_file.read()
                    urls = url_pattern.findall(contents)
                    for url in urls:
                        if not any(domain in url for domain in ignored_domains):
                            print(f"URL Found: {url}")
                            is_suspicious = True

    except Exception as e:
        print(f"Error processing file {file_path}: {e}")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return is_suspicious

def is_suspicious_file(file_path):
    if file_path.endswith(('.zip', '.docx', '.xlsx', '.pptx')):
        return decompress_and_scan(file_path)

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
