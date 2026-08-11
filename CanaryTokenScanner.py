from __future__ import annotations

import argparse
import base64
import binascii
import bz2
import collections
import email
import email.policy
import email.parser
import gzip
import hashlib
import html
import io
import json
import lzma
import math
import os
import posixpath
import re
import struct
import sys
import tarfile
import urllib.parse
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import BinaryIO, Iterator, Sequence

try:
    import olefile
except ImportError:
    olefile = None

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
except ImportError:
    x509 = None
    pkcs7 = None
    pkcs12 = None

try:
    import rarfile
except ImportError:
    rarfile = None


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

IGNORED_HOST_SUFFIXES = (
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "purl.org",
    "w3.org",
    "www.w3.org",
)

KNOWN_CALLBACK_HOST_SUFFIXES = (
    "ssl-secure-srv.org",
    "honeypdfs.com",
    "syruppdfs.com",
    "o3n.io",
    "canarytokens.com",
    "canarytokens.net",
    "interact.sh",
    "interactsh.com",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
    "oastify.com",
    "burpcollaborator.net",
    "dnslog.cn",
    "webhook.site",
    "requestbin.net",
    "requestcatcher.com",
    "beeceptor.com",
    "pipedream.net",
)

NETWORK_SCHEMES = (
    "http",
    "https",
    "ftp",
    "ftps",
    "smb",
    "file",
    "ldap",
    "ldaps",
    "nfs",
    "dav",
    "webdav",
    "ssh",
    "git",
    "svn",
    "gopher",
    "dict",
)

URL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])(?:"
    + "|".join(re.escape(s) for s in NETWORK_SCHEMES)
    + r")://[^\s<>\"'{}|\\^`\x00-\x1f]+"
)

PROTOCOL_RELATIVE_URL_RE = re.compile(
    r"(?i)(?<![:/])//(?:"
    r"localhost|"
    r"\[[0-9A-Fa-f:.]+\]|"
    r"(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r")(?::\d{1,5})?(?:/[^\s<>\"'{}|\\^`\x00-\x1f]*)?"
)

UNC_RE = re.compile(
    r"(?i)(?<!\\)\\\\[A-Za-z0-9][A-Za-z0-9._-]{0,252}(?:\\[^\s<>\"'|?*\x00-\x1f]+)+"
)

FQDN_RE = re.compile(
    r"(?i)(?<![@A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63})(?![A-Za-z0-9_-])"
)

EMAIL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)

THINKST_TOKEN_LABEL_RE = re.compile(r"^[0-9a-z]{25}$")
HIGH_ENTROPY_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{16,63}$")

DATA_URI_RE = re.compile(
    r"(?is)data:([A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+)?(?:;charset=[^;,\s]+)?(;base64)?,([^\s\"'<>]{8,})"
)

BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{80,}={0,2}|[A-Za-z0-9_-]{80,}={0,2})(?![A-Za-z0-9+/=_-])"
)

HEX_BLOB_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}(?:[\s:,-]?)){32,}(?![0-9a-f])"
)

CSS_URL_RE = re.compile(
    r"(?is)url\(\s*([\"']?)(.*?)\1\s*\)"
)

CSS_IMPORT_RE = re.compile(
    r"(?is)@import\s+(?:url\(\s*)?[\"']?([^\"'\s;)]+)"
)

XML_EXTERNAL_ENTITY_RE = re.compile(
    r"(?is)<!ENTITY\s+[^>]+\s+(?:SYSTEM|PUBLIC)\s+[\"']([^\"']+)[\"']"
)

XML_XINCLUDE_RE = re.compile(
    r"(?is)<(?:[A-Za-z_][\w.-]*:)?include\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"']"
)

RTF_FIELD_RE = re.compile(
    r"(?is)\\fldinst(?:\s+|\{[^{}]*\})*(INCLUDEPICTURE|INCLUDETEXT|DDEAUTO|DDE|HYPERLINK|LINK)\s+(?:\\[^\s]+\s+)*[\"']?([^\s\"'}]+)"
)

RTF_OBJDATA_RE = re.compile(
    r"(?is)\\objdata\s+((?:[0-9a-f]{2}[\s\r\n]*){32,})"
)

JNDI_RE = re.compile(
    r"(?is)\$\{(?:[^{}]{0,256})?jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|corba|nis|nds|http|https)\s*:[^}]{1,2048}\}"
)

AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
AWS_SECRET_KEY_RE = re.compile(
    r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"
)
AWS_ACCESS_FIELD_RE = re.compile(
    r"(?i)aws_access_key_id\s*[:=]\s*[\"']?((?:AKIA|ASIA)[A-Z0-9]{16})"
)

GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})(?![A-Za-z0-9_])"
)

GOOGLE_API_KEY_RE = re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])")
SLACK_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9-])xox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,200}(?![A-Za-z0-9-])")
STRIPE_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}(?![A-Za-z0-9_])")
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
JWE_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){4}(?![A-Za-z0-9_-])")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
AZURE_STORAGE_RE = re.compile(
    r"(?is)DefaultEndpointsProtocol\s*=\s*https?\s*;[^\r\n]{0,2048}?AccountName\s*=\s*([^;\r\n]+)\s*;[^\r\n]{0,2048}?AccountKey\s*=\s*([^;\r\n]+)"
)
DATABASE_URI_RE = re.compile(
    r"(?i)(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://([^\s:@/]+):([^\s@/]+)@([^\s/]+)"
)

CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
CARD_CONTEXT_RE = re.compile(r"(?i)\b(?:credit\s*card|card\s*(?:number|no)|pan|cvv|cvc|expiry|expiration|payment)\b")

PDF_STREAM_RE = re.compile(
    rb"(?P<dict><<(?:(?!>>).){0,131072}>>)[\x00\x09\x0a\x0c\x0d\x20]*stream(?:\r\n|\n|\r)(?P<data>.*?)(?:\r\n|\n|\r)endstream",
    re.DOTALL,
)

PDF_FILTER_RE = re.compile(
    rb"/Filter\s*(?:\[(?P<array>[^\]]{1,4096})\]|/(?P<single>[A-Za-z0-9]+))",
    re.DOTALL,
)

PDF_FILTER_NAME_RE = re.compile(rb"/([A-Za-z0-9]+)")
PDF_LITERAL_URI_RE = re.compile(
    rb"/(URI|F|UF|JS)\s*(\((?:\\.|[^\\()]+|\((?:\\.|[^\\()])*\))*\)|<[0-9A-Fa-f\s]+>)",
    re.DOTALL,
)

PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}


@dataclass(slots=True)
class Limits:
    max_file_size: int = 256 * 1024 * 1024
    max_member_size: int = 64 * 1024 * 1024
    max_total_expanded: int = 512 * 1024 * 1024
    max_members: int = 10000
    max_depth: int = 5
    max_findings: int = 2000
    max_encoded_candidates: int = 64
    max_pdf_streams: int = 5000
    max_compression_ratio: float = 1000.0
    max_qr_image_size: int = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Finding:
    severity: str
    confidence: str
    category: str
    location: str
    value: str
    evidence: str


@dataclass(slots=True)
class FileReport:
    path: str
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    partial: bool = False

    @property
    def suspicious(self) -> bool:
        return bool(self.findings)


@dataclass(slots=True)
class ScanBudget:
    expanded_bytes: int = 0
    members: int = 0
    encoded_candidates: int = 0
    pdf_streams: int = 0


@dataclass(frozen=True, slots=True)
class ExternalReference:
    value: str
    kind: str
    auto_load: bool
    hidden: bool
    evidence: str


class TrackingHTMLParser(HTMLParser):
    AUTOLOAD_ATTRIBUTES = {
        "img": ("src", "srcset"),
        "script": ("src",),
        "iframe": ("src",),
        "frame": ("src",),
        "embed": ("src",),
        "object": ("data",),
        "source": ("src", "srcset"),
        "video": ("src", "poster"),
        "audio": ("src",),
        "track": ("src",),
        "input": ("src",),
        "body": ("background",),
        "image": ("href", "xlink:href"),
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[ExternalReference] = []
        self._style_depth = 0
        self._style_data: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_tag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "style" and self._style_depth:
            self._style_depth -= 1
            if self._style_depth == 0 and self._style_data:
                css = "".join(self._style_data)
                self._collect_css(css, "style element")
                self._style_data.clear()

    def handle_data(self, data: str) -> None:
        if self._style_depth:
            self._style_data.append(data)

    def _handle_tag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        values = {k.lower(): v or "" for k, v in attrs}
        if name == "style":
            self._style_depth += 1
        style = values.get("style", "")
        hidden = self._is_hidden(values, style)
        if style:
            self._collect_css(style, f"{name} style", hidden)
        for attr in self.AUTOLOAD_ATTRIBUTES.get(name, ()):
            value = values.get(attr)
            if not value:
                continue
            for candidate in self._split_srcset(value) if attr == "srcset" else (value,):
                self.references.append(
                    ExternalReference(candidate, f"HTML {name} {attr}", True, hidden, self.get_starttag_text() or "")
                )
        if name == "link":
            href = values.get("href", "")
            rel = {part.lower() for part in values.get("rel", "").split()}
            autoload = bool(rel & {"stylesheet", "preload", "prefetch", "dns-prefetch", "preconnect", "icon", "manifest", "modulepreload"})
            if href:
                self.references.append(
                    ExternalReference(href, "HTML link", autoload, hidden, self.get_starttag_text() or "")
                )
        if name == "meta" and values.get("http-equiv", "").lower() == "refresh":
            content = values.get("content", "")
            match = re.search(r"(?i)\burl\s*=\s*([^;]+)", content)
            if match:
                self.references.append(
                    ExternalReference(match.group(1).strip(" \t\r\n\"'"), "HTML meta refresh", True, hidden, self.get_starttag_text() or "")
                )
        if name == "form" and values.get("action"):
            self.references.append(
                ExternalReference(values["action"], "HTML form action", False, hidden, self.get_starttag_text() or "")
            )

    def _collect_css(self, css: str, source: str, hidden: bool = False) -> None:
        import_matches = list(CSS_IMPORT_RE.finditer(css))
        import_spans = [(match.start(), match.end()) for match in import_matches]
        for match in import_matches:
            self.references.append(ExternalReference(match.group(1).strip(), f"CSS import in {source}", True, hidden, match.group(0)))
        for match in CSS_URL_RE.finditer(css):
            if any(match.start() < end and match.end() > start for start, end in import_spans):
                continue
            self.references.append(ExternalReference(match.group(2).strip(), f"CSS url in {source}", True, hidden, match.group(0)))

    @staticmethod
    def _split_srcset(value: str) -> Iterator[str]:
        for item in value.split(","):
            candidate = item.strip().split()[0] if item.strip() else ""
            if candidate:
                yield candidate

    @staticmethod
    def _is_hidden(attrs: dict[str, str], style: str) -> bool:
        if "hidden" in attrs:
            return True
        width = TrackingHTMLParser._numeric_dimension(attrs.get("width", ""))
        height = TrackingHTMLParser._numeric_dimension(attrs.get("height", ""))
        if width is not None and height is not None and width <= 1 and height <= 1:
            return True
        normalized = re.sub(r"\s+", "", style.lower())
        return any(
            token in normalized
            for token in (
                "display:none",
                "visibility:hidden",
                "opacity:0",
                "width:0",
                "height:0",
                "width:1px",
                "height:1px",
                "position:absolute;left:-",
                "position:fixed;left:-",
            )
        )

    @staticmethod
    def _numeric_dimension(value: str) -> float | None:
        match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", value)
        if not match:
            return None
        try:
            return float(match.group(1))
        except ValueError:
            return None


class CanaryTokenScanner:
    def __init__(
        self,
        limits: Limits,
        minimum_severity: str = "low",
        enable_qr: bool = True,
        callback_domains: Sequence[str] = (),
    ) -> None:
        self.limits = limits
        self.minimum_severity = minimum_severity
        self.enable_qr = enable_qr
        configured_domains = tuple(
            domain
            for domain in (self._normalize_host(item) for item in callback_domains)
            if domain
        )
        self.callback_host_suffixes = tuple(dict.fromkeys(KNOWN_CALLBACK_HOST_SUFFIXES + configured_domains))
        self.report: FileReport | None = None
        self.budget = ScanBudget()
        self._seen: set[tuple[str, str, str]] = set()
        self._contextual_indicators: set[tuple[str, str]] = set()

    def scan_file(self, file_path: str) -> FileReport:
        self.report = FileReport(path=file_path)
        self.budget = ScanBudget()
        self._seen.clear()
        self._contextual_indicators.clear()
        try:
            stat = os.stat(file_path, follow_symlinks=False)
        except OSError as exc:
            self.report.errors.append(str(exc))
            return self.report
        if not os.path.isfile(file_path):
            self.report.errors.append("Not a regular file")
            return self.report
        if stat.st_size > self.limits.max_file_size:
            self.report.partial = True
            self.report.warnings.append(
                f"File is {stat.st_size} bytes and exceeds the full-scan limit of {self.limits.max_file_size} bytes; scanning bounded chunks only"
            )
            self._scan_large_file_chunks(file_path)
            self._sort_findings()
            return self.report
        try:
            with open(file_path, "rb") as handle:
                data = handle.read(self.limits.max_file_size + 1)
        except OSError as exc:
            self.report.errors.append(str(exc))
            return self.report
        if len(data) > self.limits.max_file_size:
            self.report.partial = True
            data = data[: self.limits.max_file_size]
        self._scan_bytes(data, os.path.basename(file_path), 0, charge_budget=False)
        self._sort_findings()
        return self.report

    def _sort_findings(self) -> None:
        if self.report is None:
            return
        self.report.findings.sort(
            key=lambda item: (
                -SEVERITY_ORDER[item.severity],
                item.location.lower(),
                item.category.lower(),
                item.value.lower(),
            )
        )

    def _scan_large_file_chunks(self, file_path: str) -> None:
        chunk_size = 8 * 1024 * 1024
        overlap = 64 * 1024
        offset = 0
        tail = b""
        try:
            with open(file_path, "rb") as handle:
                while True:
                    chunk = handle.read(chunk_size)
                    if not chunk:
                        break
                    combined = tail + chunk
                    location = f"{os.path.basename(file_path)}@0x{max(0, offset - len(tail)):x}"
                    self._scan_generic_bytes(combined, location, 0, allow_encoded=False)
                    tail = combined[-overlap:]
                    offset += len(chunk)
        except OSError as exc:
            if self.report is not None:
                self.report.errors.append(str(exc))

    def _scan_bytes(self, data: bytes, location: str, depth: int, charge_budget: bool = True) -> None:
        if self.report is None:
            return
        if depth > self.limits.max_depth:
            self.report.partial = True
            self.report.warnings.append(f"Maximum nesting depth reached at {location}")
            return
        if charge_budget:
            if not self._charge_expanded(len(data), location):
                return
        kind = self._detect_kind(data, location)
        if kind == "zip":
            self._scan_zip(data, location, depth)
            return
        if kind == "pdf":
            self._scan_pdf(data, location, depth)
            return
        if kind == "gzip":
            self._scan_compressed(data, location, depth, "gzip")
            return
        if kind == "bzip2":
            self._scan_compressed(data, location, depth, "bzip2")
            return
        if kind == "xz":
            self._scan_compressed(data, location, depth, "xz")
            return
        if kind == "tar":
            self._scan_tar(data, location, depth)
            return
        if kind == "ole":
            self._scan_ole(data, location, depth)
            return
        if kind == "rar":
            self._scan_rar(data, location, depth)
            return
        if kind == "pe":
            self._scan_pe(data, location, depth)
            return
        if kind == "certificate":
            self._scan_certificate_container(data, location, depth)
            return
        if kind == "png":
            self._scan_png(data, location, depth)
            self._scan_qr(data, location)
            return
        if kind in {"jpeg", "gif", "webp", "bmp", "tiff"}:
            self._scan_generic_bytes(data, location, depth)
            self._scan_qr(data, location)
            return
        if kind == "rtf":
            self._scan_rtf(data, location, depth)
            return
        if kind == "mime":
            self._scan_mime(data, location, depth)
            return
        self._scan_generic_bytes(data, location, depth)

    def _scan_generic_bytes(self, data: bytes, location: str, depth: int, allow_encoded: bool = True) -> None:
        views = self._text_views(data)
        if not views:
            ascii_strings = self._extract_ascii_strings(data)
            if ascii_strings:
                self._analyze_text(ascii_strings, f"{location}[strings]", depth, allow_encoded=False)
            return
        seen_text_hashes: set[str] = set()
        for label, text in views:
            digest = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()
            if digest in seen_text_hashes:
                continue
            seen_text_hashes.add(digest)
            self._analyze_text(text, f"{location}[{label}]", depth, allow_encoded=allow_encoded)

    def _analyze_text(self, text: str, location: str, depth: int, allow_encoded: bool = True) -> None:
        if not text:
            return
        variants: list[tuple[str, str]] = [(location, text)]
        transformed = html.unescape(text)
        if transformed != text:
            variants.append((f"{location}[html-unescaped]", transformed))
        slash_unescaped = transformed.replace("\\/", "/")
        if slash_unescaped != transformed:
            variants.append((f"{location}[slash-unescaped]", slash_unescaped))
        if re.search(r"%(?:[0-9A-Fa-f]{2})", slash_unescaped):
            percent_decoded = urllib.parse.unquote(slash_unescaped)
            if percent_decoded != slash_unescaped:
                variants.append((f"{location}[percent-decoded]", percent_decoded))
        escaped = self._decode_backslash_escapes(slash_unescaped)
        if escaped != slash_unescaped:
            variants.append((f"{location}[escape-decoded]", escaped))
        seen: set[str] = set()
        for variant_location, variant in variants:
            digest = hashlib.sha256(variant.encode("utf-8", "ignore")).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            self._detect_exact_signatures(variant, variant_location)
            self._detect_html_and_svg(variant, variant_location)
            self._detect_xml(variant, variant_location)
            self._detect_css(variant, variant_location)
            self._detect_office_text(variant, variant_location)
            self._detect_pdf_text(variant, variant_location)
            self._detect_rtf_text(variant, variant_location)
            self._detect_credentials(variant, variant_location)
            self._detect_credit_card_candidates(variant, variant_location)
            self._scan_network_indicators(variant, variant_location)
        if allow_encoded and depth < self.limits.max_depth:
            self._scan_embedded_encoded_data(text, location, depth)

    def _detect_exact_signatures(self, text: str, location: str) -> None:
        lower = text.lower()
        if "sensitive command token generated by thinkst canary" in lower:
            self._add_finding(
                "critical",
                "high",
                "Thinkst Sensitive Command Canarytoken",
                location,
                "Thinkst Sensitive Command marker",
                self._evidence_around(text, lower.index("sensitive command token generated by thinkst canary")),
            )
        if "silentprocessexit" in lower and "monitorprocess" in lower and "resolve-dnsname" in lower:
            self._add_finding(
                "high",
                "high",
                "Sensitive command DNS honeytoken candidate",
                location,
                "SilentProcessExit + MonitorProcess + Resolve-DnsName",
                self._evidence_around(text, lower.index("silentprocessexit")),
            )
        if re.search(r"(?i)\.UN\.[^.\s]{1,128}\.CMD\.", text):
            self._add_finding(
                "high",
                "high",
                "Thinkst Sensitive Command hostname pattern",
                location,
                ".UN.<user>.CMD. hostname marker",
                self._evidence_around(text, re.search(r"(?i)\.UN\.", text).start()),
            )
        for match in JNDI_RE.finditer(text):
            self._add_finding(
                "critical",
                "high",
                "Log4Shell JNDI honeytoken candidate",
                location,
                self._truncate(match.group(0), 240),
                self._evidence_around(text, match.start()),
            )
            for indicator in URL_RE.findall(match.group(0)) + FQDN_RE.findall(match.group(0)):
                self._mark_contextual(location, indicator)
        if re.search(r"(?i)\.L4J\.", text):
            match = re.search(r"(?i)\.L4J\.", text)
            self._add_finding(
                "high",
                "high",
                "Thinkst Log4Shell hostname pattern",
                location,
                ".L4J. hostname marker",
                self._evidence_around(text, match.start()),
            )
        self._detect_mysql_dump(text, location)
        self._detect_sql_server(text, location)
        self._detect_windows_directory(text, location)
        self._detect_webdav_network_folder(text, location)
        self._detect_crowdstrike_credentials(text, location)
        self._detect_svn_metadata(text, location)
        self._detect_wireguard(text, location)
        self._detect_mcp(text, location)
        self._detect_kubeconfig(text, location)

    def _detect_mysql_dump(self, text: str, location: str) -> None:
        pattern = re.compile(
            r"(?is)CHANGE\s+REPLICATION\s+(?:SOURCE|MASTER)\s+TO\s+(.{1,8192}?)(?:;|\Z)"
        )
        for match in pattern.finditer(text):
            block = match.group(1)
            host_match = re.search(r"(?i)(?:SOURCE|MASTER)_HOST\s*=\s*[\"']([^\"']+)", block)
            user_match = re.search(r"(?i)(?:SOURCE|MASTER)_USER\s*=\s*[\"']([^\"']+)", block)
            if not host_match:
                continue
            host = self._clean_indicator(host_match.group(1))
            severity = "high" if user_match and THINKST_TOKEN_LABEL_RE.fullmatch(user_match.group(1).lower()) else "medium"
            confidence = "high" if severity == "high" else "medium"
            self._add_finding(
                severity,
                confidence,
                "MySQL replication honeytoken candidate",
                location,
                self._mask_hostname(host),
                self._evidence_around(text, match.start()),
            )
            self._mark_contextual(location, host)

    def _detect_sql_server(self, text: str, location: str) -> None:
        lower = text.lower()
        marker_count = sum(
            marker in lower
            for marker in (
                "xp_dirtree",
                "@tokendomain",
                "@token_domain",
                "xs:base64binary",
                "xs:hexbinary",
                "sql:column",
                "concat('//",
            )
        )
        if "xp_dirtree" not in lower or marker_count < 3:
            return
        domain_match = re.search(
            r'''(?is)(?:declare\s+)?@token_?domain\b(?:\s+(?:n?varchar|n?char)\s*\([^)]*\))?\s*=\s*N?["']([^"']+)''',
            text,
        )
        if domain_match is None:
            domain_match = re.search(
                r'''(?is)set\s+@token_?domain\s*=\s*N?["']([^"']+)''',
                text,
            )
        value = self._clean_indicator(domain_match.group(1)) if domain_match else "xp_dirtree DNS callback construction"
        callback = bool(domain_match and self._contains_callback_indicator(value))
        self._add_finding(
            "critical" if callback else "high",
            "high" if marker_count >= 5 else "medium",
            "SQL Server DNS honeytoken candidate",
            location,
            self._mask_url(value),
            self._evidence_around(text, lower.index("xp_dirtree"), 420),
        )
        if domain_match:
            self._mark_contextual(location, value)

    def _detect_windows_directory(self, text: str, location: str) -> None:
        lower = text.lower()
        if "[.shellclassinfo]" not in lower:
            return
        remote_icon = re.search(
            r'''(?im)^\s*(IconResource|IconFile)\s*=\s*((?:\\\\|//|(?:https?|smb|file|webdav)://)[^\r\n,]+)''',
            text,
        )
        if not remote_icon:
            return
        value = self._clean_indicator(remote_icon.group(2))
        thinkst_marker = bool(re.search(r"(?i)\.INI\.", value))
        callback = self._contains_callback_indicator(value) or thinkst_marker
        self._add_network_finding(
            value,
            location,
            "Windows directory desktop.ini remote icon honeytoken candidate",
            True,
            True,
            self._evidence_around(text, remote_icon.start(), 320),
            "critical" if callback else "high",
            "high" if callback else "medium",
        )

    def _detect_webdav_network_folder(self, text: str, location: str) -> None:
        lower = text.lower()
        if not any(marker in lower for marker in ("webdav", "davwwwroot", "net use", "mount.davfs", "webclient")):
            return
        references = URL_RE.findall(text) + UNC_RE.findall(text)
        if not references:
            return
        credential_context = bool(
            re.search(
                r"(?i)\b(?:username|user|login|password|passwd|credential|/user:)\b\s*(?:[:=]|\s)",
                text,
            )
        )
        for reference in dict.fromkeys(self._clean_indicator(item) for item in references):
            if not reference or not self._is_external_reference(reference):
                continue
            callback = self._contains_callback_indicator(reference)
            if not credential_context and not callback:
                continue
            reference_offset = text.find(reference)
            self._add_network_finding(
                reference,
                location,
                "WebDAV network-folder honeytoken candidate",
                True,
                False,
                self._evidence_around(text, max(0, reference_offset), 360),
                "high" if callback else "medium",
                "high" if callback else "low",
            )

    def _detect_crowdstrike_credentials(self, text: str, location: str) -> None:
        lower = text.lower()
        if "crowdstrike" not in lower and "falcon" not in lower:
            return
        key_value_re = re.compile(
            r'''(?im)["']?(?:crowdstrike[_-]?)?(client[_-]?id|client[_-]?secret|base[_-]?url)["']?\s*[:=]\s*["']?([^"'\s,;}]+)'''
        )
        values: dict[str, tuple[str, int]] = {}
        for match in key_value_re.finditer(text):
            key = match.group(1).lower().replace("-", "_")
            value = match.group(2).strip()
            if self._is_placeholder_value(value):
                continue
            values[key] = (value, match.start())
        if not {"client_id", "client_secret", "base_url"}.issubset(values):
            return
        base_url = self._clean_indicator(values["base_url"][0])
        secret = values["client_secret"][0]
        client_id = values["client_id"][0]
        evidence_offset = min(offset for _, offset in values.values())
        self._add_finding(
            "high",
            "medium",
            "CrowdStrike client credential honeytoken candidate",
            location,
            f"client_id={self._mask_secret(client_id)} base_url={self._mask_url(base_url)} client_secret={self._mask_secret(secret)}",
            self._evidence_around(text, evidence_offset, 420),
        )
        if self._is_external_reference(base_url):
            self._mark_contextual(location, base_url)

    def _detect_svn_metadata(self, text: str, location: str) -> None:
        report_path = self.report.path if self.report is not None else ""
        lower_location = f"{report_path} {location}".lower().replace("\\", "/")
        lower = text.lower()
        if "/.svn/" not in lower_location and not lower_location.endswith("/.svn") and "svn:special" not in lower:
            return
        for match in URL_RE.finditer(text):
            value = self._clean_indicator(match.group(0))
            if not self._contains_callback_indicator(value):
                continue
            self._add_network_finding(
                value,
                location,
                "SVN metadata honeytoken candidate",
                False,
                False,
                self._evidence_around(text, match.start()),
                "high",
                "high",
            )

    def _detect_wireguard(self, text: str, location: str) -> None:
        required = (
            "[interface]",
            "privatekey",
            "[peer]",
            "publickey",
            "allowedips",
            "endpoint",
            "persistentkeepalive",
        )
        lower = text.lower()
        if all(item in lower for item in required):
            endpoint = re.search(r"(?im)^\s*Endpoint\s*=\s*([^\r\n#;]+)", text)
            keepalive = re.search(r"(?im)^\s*PersistentKeepalive\s*=\s*(\d+)", text)
            if endpoint and keepalive and keepalive.group(1) != "0":
                value = self._clean_indicator(endpoint.group(1).strip())
                self._add_finding(
                    "medium",
                    "medium",
                    "WireGuard configuration honeytoken candidate",
                    location,
                    value,
                    self._evidence_around(text, endpoint.start()),
                )
                self._mark_contextual(location, value)

    def _detect_mcp(self, text: str, location: str) -> None:
        if "mcpservers" not in text.lower():
            return
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("mcpServers"), dict):
            for name, config in parsed["mcpServers"].items():
                if not isinstance(config, dict):
                    continue
                url = config.get("url")
                headers = config.get("headers")
                authorization = headers.get("Authorization") if isinstance(headers, dict) else None
                if isinstance(url, str) and isinstance(authorization, str) and authorization.lower().startswith("bearer "):
                    token = authorization[7:].strip()
                    if JWE_RE.fullmatch(token):
                        self._add_finding(
                            "high",
                            "high",
                            "MCP server honeytoken candidate",
                            location,
                            f"{name}: {self._mask_url(url)}",
                            "mcpServers entry with remote URL and Bearer JWE",
                        )
                        self._mark_contextual(location, url)
            return
        if re.search(r"(?is)[\"']mcpServers[\"']\s*:", text) and re.search(r"(?is)[\"']Authorization[\"']\s*:\s*[\"']Bearer\s+[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){4}", text):
            self._add_finding(
                "high",
                "medium",
                "MCP server honeytoken candidate",
                location,
                "mcpServers with Bearer JWE",
                self._evidence_around(text, re.search(r"(?i)mcpServers", text).start()),
            )

    def _detect_kubeconfig(self, text: str, location: str) -> None:
        lower = text.lower()
        markers = (
            "apiversion:",
            "kind: config",
            "clusters:",
            "certificate-authority-data:",
            "client-certificate-data:",
            "client-key-data:",
        )
        if all(marker in lower for marker in markers):
            server = re.search(r"(?im)^\s*server\s*:\s*([^\s#]+)", text)
            if server:
                value = self._clean_indicator(server.group(1))
                self._add_finding(
                    "high",
                    "medium",
                    "Kubeconfig credential honeytoken candidate",
                    location,
                    self._mask_url(value),
                    self._evidence_around(text, server.start()),
                )
                self._mark_contextual(location, value)

    def _detect_html_and_svg(self, text: str, location: str) -> None:
        lower = text.lower()
        if "<svg" in lower:
            self._detect_svg(text, location)
        if any(marker in lower for marker in ("<html", "<img", "<script", "<iframe", "<link", "<meta", "<object", "<embed")):
            parser = TrackingHTMLParser()
            try:
                parser.feed(text)
                parser.close()
            except Exception:
                return
            for reference in parser.references:
                value = self._clean_indicator(reference.value)
                if not self._is_external_reference(value):
                    continue
                if reference.auto_load and reference.hidden:
                    severity = "high"
                    confidence = "high"
                    category = "Hidden HTML tracking resource"
                elif reference.auto_load:
                    severity = "medium"
                    confidence = "medium"
                    category = "HTML auto-loading external resource"
                else:
                    severity = "low"
                    confidence = "low"
                    category = "HTML external reference"
                self._add_network_finding(value, location, f"{category}: {reference.kind}", reference.auto_load, reference.hidden, reference.evidence, severity, confidence)

    def _detect_svg(self, text: str, location: str) -> None:
        tag_re = re.compile(r"(?is)<(?:[A-Za-z_][\w.-]*:)?(image|feImage|use|script|foreignObject)\b([^>]*)>")
        attr_re = re.compile(r"(?is)(?:xlink:)?(?:href|src)\s*=\s*([\"'])(.*?)\1")
        for tag_match in tag_re.finditer(text):
            tag = tag_match.group(1).lower()
            attrs = tag_match.group(2)
            hidden = self._svg_hidden(attrs, text)
            for attr_match in attr_re.finditer(attrs):
                value = self._clean_indicator(attr_match.group(2))
                if not self._is_external_reference(value):
                    continue
                auto_load = tag in {"image", "feimage", "use", "script"}
                if tag in {"image", "feimage"} and hidden:
                    severity = "critical"
                    confidence = "high"
                    category = "Hidden SVG external image honeytoken"
                elif auto_load:
                    severity = "high"
                    confidence = "high"
                    category = "SVG auto-loading external resource"
                else:
                    severity = "medium"
                    confidence = "medium"
                    category = "SVG external resource"
                self._add_network_finding(value, location, f"{category}: {tag}", auto_load, hidden, tag_match.group(0), severity, confidence)
        for match in CSS_URL_RE.finditer(text):
            value = self._clean_indicator(match.group(2))
            if self._is_external_reference(value):
                self._add_network_finding(value, location, "SVG CSS external resource", True, self._svg_hidden("", text), match.group(0), "high", "medium")

    def _detect_xml(self, text: str, location: str) -> None:
        for match in XML_EXTERNAL_ENTITY_RE.finditer(text):
            value = self._clean_indicator(match.group(1))
            if self._is_external_reference(value):
                self._add_network_finding(value, location, "XML external entity honeytoken candidate", True, False, match.group(0), "high", "high")
        for match in XML_XINCLUDE_RE.finditer(text):
            value = self._clean_indicator(match.group(1))
            if self._is_external_reference(value):
                self._add_network_finding(value, location, "XML XInclude external resource", True, False, match.group(0), "high", "medium")

    def _detect_css(self, text: str, location: str) -> None:
        if "url(" not in text.lower() and "@import" not in text.lower():
            return
        import_matches = list(CSS_IMPORT_RE.finditer(text))
        import_spans = [(match.start(), match.end()) for match in import_matches]
        for match in import_matches:
            value = self._clean_indicator(match.group(1))
            if self._is_external_reference(value):
                self._add_network_finding(value, location, "CSS imported external resource", True, False, match.group(0), "medium", "medium")
        for match in CSS_URL_RE.finditer(text):
            if self._overlaps(match.start(), match.end(), import_spans):
                continue
            value = self._clean_indicator(match.group(2))
            if self._is_external_reference(value):
                self._add_network_finding(value, location, "CSS auto-loading external resource", True, False, match.group(0), "medium", "medium")

    def _detect_office_text(self, text: str, location: str) -> None:
        lower_location = location.lower()
        if lower_location.endswith(".rels[utf-8]") or ".rels[" in lower_location or "<relationship" in text.lower():
            relationship_re = re.compile(r"(?is)<Relationship\b([^>]+?)(?:/?>)")
            attr_re = re.compile(r"(?is)([A-Za-z_:][\w:.-]*)\s*=\s*([\"'])(.*?)\2")
            for match in relationship_re.finditer(text):
                attrs = {name.lower(): value for name, _, value in attr_re.findall(match.group(1))}
                target = self._clean_indicator(attrs.get("target", ""))
                rel_type = attrs.get("type", "")
                external = attrs.get("targetmode", "").lower() == "external" or self._is_external_reference(target)
                if not external or not target:
                    continue
                rel_tail = rel_type.rsplit("/", 1)[-1].lower()
                if rel_tail in {"attachedtemplate", "oleobject", "externallink", "image", "package"}:
                    severity = "high"
                    confidence = "high"
                elif rel_tail == "hyperlink":
                    severity = "low"
                    confidence = "low"
                else:
                    severity = "medium"
                    confidence = "medium"
                self._add_network_finding(
                    target,
                    location,
                    f"OOXML external relationship: {rel_tail or 'unknown'}",
                    rel_tail != "hyperlink",
                    False,
                    match.group(0),
                    severity,
                    confidence,
                )
        formula_patterns = (
            (r"(?i)\bWEBSERVICE\s*\(", "Excel WEBSERVICE honeytoken candidate", "high", "high"),
            (r"(?i)\bIMAGE\s*\(", "Excel IMAGE external resource candidate", "medium", "medium"),
            (r"(?i)\bFILTERXML\s*\(", "Excel FILTERXML external data candidate", "medium", "medium"),
            (r"(?i)\bHYPERLINK\s*\(", "Excel HYPERLINK external reference", "low", "low"),
        )
        for pattern, category, severity, confidence in formula_patterns:
            for match in re.finditer(pattern, text):
                context = self._evidence_around(text, match.start(), 300)
                external = next(iter(URL_RE.findall(context)), "")
                value = self._clean_indicator(external) if external else self._truncate(context, 240)
                self._add_finding(severity, confidence, category, location, value, context)
                if external:
                    self._mark_contextual(location, external)
        if "\\rtf" not in text[:128].lower():
            field_pattern = re.compile(r"(?is)\b(INCLUDEPICTURE|INCLUDETEXT|DDEAUTO|DDE|LINK)\b.{0,256}?((?:https?|ftp|smb|file|ldap|ldaps)://[^\s\"'<>]+|\\\\[^\s\"'<>]+)")
            for match in field_pattern.finditer(text):
                value = self._clean_indicator(match.group(2))
                category = f"Office field external reference: {match.group(1).upper()}"
                severity = "high" if match.group(1).upper() in {"INCLUDEPICTURE", "INCLUDETEXT", "DDEAUTO", "DDE"} else "medium"
                self._add_network_finding(value, location, category, True, False, match.group(0), severity, "high")

    def _detect_pdf_text(self, text: str, location: str) -> None:
        lower_location = location.lower()
        if "[pdf-" not in lower_location:
            return
        lower = text.lower()
        actions = {
            "/openaction": ("PDF OpenAction", "high", "high"),
            "/aa": ("PDF additional action", "high", "medium"),
            "/submitform": ("PDF SubmitForm action", "high", "high"),
            "/importdata": ("PDF ImportData action", "high", "medium"),
            "/launch": ("PDF Launch action", "high", "high"),
            "/gotor": ("PDF remote GoTo action", "medium", "medium"),
            "/javascript": ("PDF JavaScript action", "high", "medium"),
            "/js": ("PDF JavaScript action", "high", "medium"),
        }
        for marker, (category, severity, confidence) in actions.items():
            start = 0
            while True:
                index = lower.find(marker, start)
                if index < 0:
                    break
                context = self._evidence_around(text, index, 400)
                values = URL_RE.findall(context) + UNC_RE.findall(context) + FQDN_RE.findall(context)
                value = self._clean_indicator(values[0]) if values else marker
                self._add_finding(severity, confidence, category, location, value, context)
                if values:
                    self._mark_contextual(location, value)
                start = index + len(marker)
        if "[pdf-raw]" not in location:
            for match in re.finditer(r"(?is)/URI\s*\((.*?)\)", text):
                value = self._clean_indicator(match.group(1))
                if self._is_external_reference(value):
                    self._add_network_finding(value, location, "PDF URI action", False, False, match.group(0))

    def _detect_rtf_text(self, text: str, location: str) -> None:
        if "\\rtf" not in text[:64].lower() and "\\fldinst" not in text.lower():
            return
        for match in RTF_FIELD_RE.finditer(text):
            value = self._clean_indicator(match.group(2))
            if not self._is_external_reference(value):
                continue
            operation = match.group(1).upper()
            severity = "high" if operation in {"INCLUDEPICTURE", "INCLUDETEXT", "DDEAUTO", "DDE"} else "low"
            confidence = "high" if severity == "high" else "low"
            self._add_network_finding(value, location, f"RTF {operation} external field", severity == "high", False, match.group(0), severity, confidence)

    def _detect_credentials(self, text: str, location: str) -> None:
        access_fields = list(AWS_ACCESS_FIELD_RE.finditer(text))
        secrets = list(AWS_SECRET_KEY_RE.finditer(text))
        access_keys = list(AWS_ACCESS_KEY_RE.finditer(text))
        for match in access_fields or access_keys:
            value = match.group(1) if match.lastindex else match.group(0)
            paired = bool(secrets)
            self._add_finding(
                "high" if paired else "medium",
                "medium" if paired else "low",
                "AWS credential honeytoken candidate",
                location,
                self._mask_secret(value),
                self._evidence_around(text, match.start()),
            )
        patterns = (
            (GITHUB_TOKEN_RE, "GitHub credential honeytoken candidate"),
            (GOOGLE_API_KEY_RE, "Google API credential honeytoken candidate"),
            (SLACK_TOKEN_RE, "Slack credential honeytoken candidate"),
            (STRIPE_KEY_RE, "Stripe credential honeytoken candidate"),
            (JWT_RE, "JWT honeytoken candidate"),
        )
        for pattern, category in patterns:
            for match in pattern.finditer(text):
                self._add_finding(
                    "medium",
                    "low",
                    category,
                    location,
                    self._mask_secret(match.group(0)),
                    self._evidence_around(text, match.start()),
                )
        for match in PRIVATE_KEY_RE.finditer(text):
            self._add_finding(
                "high",
                "low",
                "Private key honeycredential candidate",
                location,
                match.group(0),
                self._evidence_around(text, match.start()),
            )
        for match in AZURE_STORAGE_RE.finditer(text):
            self._add_finding(
                "high",
                "low",
                "Azure Storage credential honeytoken candidate",
                location,
                f"AccountName={self._mask_secret(match.group(1).strip())}",
                self._evidence_around(text, match.start()),
            )
        for match in DATABASE_URI_RE.finditer(text):
            host = match.group(3)
            self._add_finding(
                "medium",
                "low",
                "Database credential honeytoken candidate",
                location,
                f"{self._mask_secret(match.group(1))}:***@{host}",
                self._evidence_around(text, match.start()),
            )

    def _detect_credit_card_candidates(self, text: str, location: str) -> None:
        contexts = list(CARD_CONTEXT_RE.finditer(text))
        if not contexts:
            return
        for match in CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 13 <= len(digits) <= 19 and self._luhn_valid(digits):
                nearest = min(abs(match.start() - context.start()) for context in contexts)
                if nearest > 512:
                    continue
                self._add_finding(
                    "medium",
                    "low",
                    "Payment-card honeytoken candidate",
                    location,
                    self._mask_card(digits),
                    self._evidence_around(text, match.start()),
                )

    def _scan_network_indicators(self, text: str, location: str, generic_only: bool = False) -> None:
        occupied: list[tuple[int, int]] = []
        for pattern in (URL_RE, PROTOCOL_RELATIVE_URL_RE, UNC_RE):
            for match in pattern.finditer(text):
                value = self._clean_indicator(match.group(0))
                if not value:
                    continue
                occupied.append((match.start(), match.end()))
                if self._is_contextual(location, value):
                    continue
                category = "External network reference"
                self._add_network_finding(value, location, category, False, False, self._evidence_around(text, match.start()))
        if generic_only:
            return
        for match in EMAIL_RE.finditer(text):
            if self._overlaps(match.start(), match.end(), occupied):
                continue
            value = self._clean_indicator(match.group(0))
            host = value.rsplit("@", 1)[-1]
            if self._is_ignored_host(host):
                continue
            local = value.rsplit("@", 1)[0].lower()
            if THINKST_TOKEN_LABEL_RE.fullmatch(local) or self._host_has_thinkst_token_label(host) or self._is_known_callback_host(host):
                self._add_finding(
                    "high",
                    "medium",
                    "Honeytoken email address candidate",
                    location,
                    self._mask_email(value),
                    self._evidence_around(text, match.start()),
                )
            occupied.append((match.start(), match.end()))
        for match in FQDN_RE.finditer(text):
            if self._overlaps(match.start(), match.end(), occupied):
                continue
            host = self._normalize_host(match.group(0))
            if not host or self._is_ignored_host(host) or self._is_contextual(location, host):
                continue
            if self._is_known_callback_host(host):
                self._add_finding(
                    "high",
                    "high",
                    "Known callback-service hostname",
                    location,
                    self._mask_hostname(host),
                    self._evidence_around(text, match.start()),
                )
            elif self._host_has_thinkst_token_label(host):
                self._add_finding(
                    "high",
                    "medium",
                    "Thinkst-style 25-character token hostname candidate",
                    location,
                    self._mask_hostname(host),
                    self._evidence_around(text, match.start()),
                )
            elif self._looks_like_callback_host(host):
                self._add_finding(
                    "medium",
                    "low",
                    "High-entropy callback hostname candidate",
                    location,
                    self._mask_hostname(host),
                    self._evidence_around(text, match.start()),
                )

    def _add_network_finding(
        self,
        value: str,
        location: str,
        category: str,
        auto_load: bool,
        hidden: bool,
        evidence: str,
        severity: str | None = None,
        confidence: str | None = None,
    ) -> None:
        value = self._clean_indicator(value)
        if not value:
            return
        host = self._host_from_indicator(value)
        if not host and (value.startswith("\\\\") or value.startswith("//") or re.match(r"(?i)^[A-Za-z][A-Za-z0-9+.-]*://", value)):
            return
        if host and self._is_ignored_host(host):
            return
        known_callback = bool(host and self._is_known_callback_host(host))
        thinkst_style = self._indicator_has_thinkst_token(value)
        if severity is None:
            if known_callback:
                severity = "high"
                confidence = "high"
                category = f"Known callback-service reference: {category}"
            elif thinkst_style and auto_load:
                severity = "high"
                confidence = "high"
                category = f"Thinkst-style auto-loading token reference: {category}"
            elif thinkst_style:
                severity = "high"
                confidence = "medium"
                category = f"Thinkst-style token reference: {category}"
            elif auto_load and hidden:
                severity = "high"
                confidence = "high"
            elif auto_load:
                severity = "medium"
                confidence = "medium"
            elif value.startswith("\\\\"):
                severity = "medium"
                confidence = "medium"
            else:
                severity = "low"
                confidence = "low"
        confidence = confidence or "low"
        display_value = self._mask_url(value)
        self._add_finding(severity, confidence, category, location, display_value, evidence)
        if auto_load or known_callback or thinkst_style:
            self._mark_contextual(location, value)

    def _scan_embedded_encoded_data(self, text: str, location: str, depth: int) -> None:
        for match in DATA_URI_RE.finditer(text):
            if not self._consume_encoded_candidate():
                return
            payload = match.group(3)
            try:
                if match.group(2):
                    decoded = base64.b64decode(payload, validate=False)
                else:
                    decoded = urllib.parse.unquote_to_bytes(payload)
            except (ValueError, binascii.Error):
                continue
            if not decoded or len(decoded) > self.limits.max_member_size:
                continue
            self._scan_bytes(decoded, f"{location}[data-uri]", depth + 1)
        for match in BASE64_RE.finditer(text):
            if not self._consume_encoded_candidate():
                return
            candidate = re.sub(r"\s+", "", match.group(0))
            if len(candidate) > self.limits.max_member_size * 2:
                continue
            padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
            decoders = (base64.b64decode, base64.urlsafe_b64decode)
            decoded = b""
            for decoder in decoders:
                try:
                    decoded = decoder(padded)
                    if decoded:
                        break
                except (ValueError, binascii.Error):
                    continue
            if self._decoded_payload_interesting(decoded):
                self._scan_bytes(decoded, f"{location}[base64]", depth + 1)
        for match in HEX_BLOB_RE.finditer(text):
            if not self._consume_encoded_candidate():
                return
            compact = re.sub(r"[^0-9A-Fa-f]", "", match.group(0))
            if len(compact) % 2 or len(compact) > self.limits.max_member_size * 2:
                continue
            try:
                decoded = bytes.fromhex(compact)
            except ValueError:
                continue
            if self._decoded_payload_interesting(decoded):
                self._scan_bytes(decoded, f"{location}[hex]", depth + 1)

    def _scan_zip(self, data: bytes, location: str, depth: int) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                infos = archive.infolist()
                if len(infos) > self.limits.max_members - self.budget.members:
                    infos = infos[: max(0, self.limits.max_members - self.budget.members)]
                    if self.report is not None:
                        self.report.partial = True
                        self.report.warnings.append(f"Archive member limit reached in {location}")
                for info in infos:
                    if info.is_dir():
                        continue
                    if not self._charge_member(location):
                        return
                    member_location = self._join_location(location, info.filename)
                    self._analyze_text(info.filename, f"{member_location}[zip-name]", depth + 1, allow_encoded=False)
                    if info.flag_bits & 0x1:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Encrypted ZIP member skipped: {member_location}")
                        continue
                    if info.file_size > self.limits.max_member_size:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Oversized ZIP member skipped: {member_location}")
                        continue
                    if info.compress_size > 0 and info.file_size / info.compress_size > self.limits.max_compression_ratio:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Extreme ZIP compression ratio skipped: {member_location}")
                        continue
                    try:
                        with archive.open(info, "r") as handle:
                            member = self._read_limited(handle, self.limits.max_member_size)
                    except Exception as exc:
                        if self.report is not None:
                            self.report.warnings.append(f"Unable to read ZIP member {member_location}: {exc}")
                        continue
                    if member is None:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"ZIP member exceeded read limit: {member_location}")
                        continue
                    self._scan_bytes(member, member_location, depth + 1)
                if archive.comment:
                    self._scan_generic_bytes(archive.comment, f"{location}[zip-comment]", depth + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
            if self.report is not None:
                self.report.warnings.append(f"Unable to parse ZIP archive {location}: {exc}")
                self._scan_generic_bytes(data, location, depth)

    def _scan_rar(self, data: bytes, location: str, depth: int) -> None:
        self._scan_generic_bytes(data, f"{location}[rar-raw]", depth, allow_encoded=False)
        if rarfile is None:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Install rarfile and an extraction backend for complete RAR scanning: {location}")
            return
        try:
            with rarfile.RarFile(io.BytesIO(data), "r") as archive:
                for info in archive.infolist():
                    if info.isdir():
                        continue
                    if not self._charge_member(location):
                        return
                    member_location = self._join_location(location, info.filename)
                    self._analyze_text(info.filename, f"{member_location}[rar-name]", depth + 1, allow_encoded=False)
                    if info.needs_password():
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Encrypted RAR member skipped: {member_location}")
                        continue
                    if info.file_size > self.limits.max_member_size:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Oversized RAR member skipped: {member_location}")
                        continue
                    if info.compress_size > 0 and info.file_size / info.compress_size > self.limits.max_compression_ratio:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Extreme RAR compression ratio skipped: {member_location}")
                        continue
                    try:
                        with archive.open(info) as handle:
                            payload = self._read_limited(handle, self.limits.max_member_size)
                    except Exception as exc:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Unable to read RAR member {member_location}: {exc}")
                        continue
                    if payload is None:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"RAR member exceeded read limit: {member_location}")
                        continue
                    self._scan_bytes(payload, member_location, depth + 1)
                if archive.comment:
                    comment = archive.comment if isinstance(archive.comment, bytes) else str(archive.comment).encode()
                    self._scan_generic_bytes(comment, f"{location}[rar-comment]", depth + 1)
        except Exception as exc:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Unable to parse RAR archive {location}: {exc}")

    def _scan_tar(self, data: bytes, location: str, depth: int) -> None:
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    if not self._charge_member(location):
                        return
                    member_location = self._join_location(location, member.name)
                    if member.size > self.limits.max_member_size:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Oversized TAR member skipped: {member_location}")
                        continue
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    with handle:
                        payload = self._read_limited(handle, self.limits.max_member_size)
                    if payload is None:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"TAR member exceeded read limit: {member_location}")
                        continue
                    self._scan_bytes(payload, member_location, depth + 1)
        except (tarfile.TarError, OSError, EOFError) as exc:
            if self.report is not None:
                self.report.warnings.append(f"Unable to parse TAR archive {location}: {exc}")
                self._scan_generic_bytes(data, location, depth)

    def _scan_compressed(self, data: bytes, location: str, depth: int, kind: str) -> None:
        try:
            if kind == "gzip":
                handle: BinaryIO = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")
            elif kind == "bzip2":
                handle = bz2.BZ2File(io.BytesIO(data), mode="rb")
            else:
                handle = lzma.LZMAFile(io.BytesIO(data), mode="rb")
            with handle:
                payload = self._read_limited(handle, self.limits.max_member_size)
        except (OSError, EOFError, lzma.LZMAError) as exc:
            if self.report is not None:
                self.report.warnings.append(f"Unable to decompress {kind} data at {location}: {exc}")
            return
        if payload is None:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Decompressed {kind} payload exceeded limit at {location}")
            return
        ratio = len(payload) / max(1, len(data))
        if ratio > self.limits.max_compression_ratio:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Extreme {kind} compression ratio skipped at {location}")
            return
        suffix = {"gzip": "gunzip", "bzip2": "bunzip2", "xz": "unxz"}[kind]
        decoded_name = self._decompressed_name(location, kind)
        self._scan_bytes(payload, f"{decoded_name}[{suffix}]", depth + 1)

    def _scan_pdf(self, data: bytes, location: str, depth: int) -> None:
        self._scan_generic_bytes(data, f"{location}[pdf-raw]", depth, allow_encoded=False)
        if b"/Encrypt" in data[: min(len(data), 4 * 1024 * 1024)] and self.report is not None:
            self.report.partial = True
            self.report.warnings.append(f"PDF encryption marker found; encrypted content may be unscannable: {location}")
        for match in PDF_LITERAL_URI_RE.finditer(data):
            key = match.group(1).decode("ascii", "ignore").upper()
            value = self._decode_pdf_string(match.group(2))
            if not value:
                continue
            decoded_location = f"{location}[pdf-{key.lower()}]"
            if key == "URI" and self._is_external_reference(value):
                self._add_network_finding(value, decoded_location, "PDF URI action", False, False, value)
            else:
                self._analyze_text(value, decoded_location, depth, allow_encoded=False)
        for index, match in enumerate(PDF_STREAM_RE.finditer(data), 1):
            if self.budget.pdf_streams >= self.limits.max_pdf_streams:
                if self.report is not None:
                    self.report.partial = True
                    self.report.warnings.append(f"PDF stream limit reached in {location}")
                break
            self.budget.pdf_streams += 1
            dictionary = match.group("dict")
            stream = match.group("data")
            stream_location = f"{location}[pdf-stream-{index}]"
            if len(stream) > self.limits.max_member_size:
                if self.report is not None:
                    self.report.partial = True
                    self.report.warnings.append(f"Oversized PDF stream skipped: {stream_location}")
                continue
            self._scan_generic_bytes(stream, f"{stream_location}[raw]", depth, allow_encoded=False)
            filters = self._pdf_filters(dictionary)
            image_payload = self._pdf_image_payload(stream, filters, dictionary)
            if image_payload is not None:
                image_location = f"{stream_location}[image]"
                self._scan_generic_bytes(image_payload, image_location, depth, allow_encoded=False)
                self._scan_qr(image_payload, image_location)
            decoded = self._decode_pdf_filters(stream, filters, dictionary)
            if decoded is None:
                if not filters:
                    decoded = stream
                else:
                    continue
            if len(decoded) > self.limits.max_member_size:
                if self.report is not None:
                    self.report.partial = True
                    self.report.warnings.append(f"Decoded PDF stream exceeded limit: {stream_location}")
                continue
            self._scan_bytes(decoded, stream_location, depth + 1)

    def _scan_rtf(self, data: bytes, location: str, depth: int) -> None:
        text = data.decode("latin-1", "ignore")
        decoded = self._decode_rtf(text)
        self._analyze_text(text, f"{location}[rtf-raw]", depth, allow_encoded=False)
        if decoded != text:
            self._analyze_text(decoded, f"{location}[rtf-decoded]", depth, allow_encoded=False)
        for index, match in enumerate(RTF_OBJDATA_RE.finditer(text), 1):
            compact = re.sub(r"\s+", "", match.group(1))
            if len(compact) > self.limits.max_member_size * 2:
                continue
            try:
                payload = bytes.fromhex(compact)
            except ValueError:
                continue
            self._scan_bytes(payload, f"{location}[rtf-objdata-{index}]", depth + 1)

    def _scan_mime(self, data: bytes, location: str, depth: int) -> None:
        try:
            message = email.parser.BytesParser(policy=email.policy.default).parsebytes(data)
        except Exception as exc:
            if self.report is not None:
                self.report.warnings.append(f"Unable to parse MIME message {location}: {exc}")
            self._scan_generic_bytes(data, location, depth)
            return
        headers = []
        for name in ("Subject", "From", "To", "Cc", "Reply-To", "Content-Location", "Content-Base"):
            value = message.get(name)
            if value:
                headers.append(f"{name}: {value}")
        if headers:
            self._analyze_text("\n".join(headers), f"{location}[headers]", depth, allow_encoded=False)
        for index, part in enumerate(message.walk(), 1):
            if part.is_multipart():
                continue
            if not self._charge_member(location):
                return
            filename = part.get_filename() or f"part-{index}.{self._extension_for_mime(part.get_content_type())}"
            part_location = self._join_location(location, filename)
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                raw_payload = part.get_payload()
                if isinstance(raw_payload, str):
                    payload = raw_payload.encode(part.get_content_charset() or "utf-8", "replace")
                else:
                    continue
            if len(payload) > self.limits.max_member_size:
                if self.report is not None:
                    self.report.partial = True
                    self.report.warnings.append(f"Oversized MIME part skipped: {part_location}")
                continue
            content_location = part.get("Content-Location")
            if content_location:
                value = self._clean_indicator(str(content_location))
                if self._is_external_reference(value):
                    self._add_network_finding(value, part_location, "MIME Content-Location external resource", True, False, str(content_location), "medium", "medium")
            self._scan_bytes(payload, part_location, depth + 1)

    def _scan_png(self, data: bytes, location: str, depth: int) -> None:
        offset = 8
        index = 0
        saw_iend = False
        while offset + 12 <= len(data):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            chunk_type = data[offset + 4:offset + 8]
            end = offset + 12 + length
            if end > len(data):
                break
            payload = data[offset + 8:offset + 8 + length]
            index += 1
            chunk_location = f"{location}[png-{chunk_type.decode('ascii', 'replace')}-{index}]"
            try:
                if chunk_type == b"tEXt":
                    self._scan_generic_bytes(payload, chunk_location, depth + 1)
                elif chunk_type == b"zTXt":
                    nul = payload.find(b"\x00")
                    if nul >= 0 and nul + 2 <= len(payload):
                        keyword = payload[:nul]
                        decoded = self._bounded_zlib_decompress(payload[nul + 2:])
                        self._scan_generic_bytes(keyword, f"{chunk_location}[keyword]", depth + 1)
                        if decoded is not None:
                            self._scan_bytes(decoded, chunk_location, depth + 1)
                elif chunk_type == b"iTXt":
                    self._scan_png_itxt(payload, chunk_location, depth)
                elif chunk_type == b"iCCP":
                    nul = payload.find(b"\x00")
                    if nul >= 0 and nul + 2 <= len(payload):
                        self._scan_generic_bytes(payload[:nul], f"{chunk_location}[profile-name]", depth + 1)
                        decoded = self._bounded_zlib_decompress(payload[nul + 2:])
                        if decoded is not None:
                            self._scan_bytes(decoded, chunk_location, depth + 1)
                elif chunk_type == b"eXIf":
                    self._scan_generic_bytes(payload, chunk_location, depth + 1)
                elif chunk_type != b"IDAT" and chunk_type[:1].islower():
                    self._scan_generic_bytes(payload, chunk_location, depth + 1, allow_encoded=False)
                if chunk_type == b"IEND":
                    saw_iend = True
            except Exception as exc:
                if self.report is not None:
                    self.report.warnings.append(f"Unable to parse PNG metadata at {chunk_location}: {exc}")
            offset = end
            if saw_iend:
                break
        if offset < len(data):
            self._scan_generic_bytes(data[offset:], f"{location}[png-trailing-data]", depth + 1)

    def _scan_png_itxt(self, payload: bytes, location: str, depth: int) -> None:
        first = payload.find(b"\x00")
        if first < 0 or first + 3 > len(payload):
            return
        keyword = payload[:first]
        compressed = payload[first + 1] == 1
        cursor = first + 3
        language_end = payload.find(b"\x00", cursor)
        if language_end < 0:
            return
        cursor = language_end + 1
        translated_end = payload.find(b"\x00", cursor)
        if translated_end < 0:
            return
        text_data = payload[translated_end + 1:]
        self._scan_generic_bytes(keyword, f"{location}[keyword]", depth + 1)
        if compressed:
            decoded = self._bounded_zlib_decompress(text_data)
            if decoded is not None:
                self._scan_bytes(decoded, location, depth + 1)
        else:
            self._scan_bytes(text_data, location, depth + 1)

    def _scan_ole(self, data: bytes, location: str, depth: int) -> None:
        self._scan_generic_bytes(data, f"{location}[ole-raw]", depth, allow_encoded=False)
        if olefile is None:
            if self.report is not None:
                self.report.warnings.append(f"Install olefile for complete legacy Office stream scanning: {location}")
            return
        try:
            with olefile.OleFileIO(io.BytesIO(data)) as container:
                for parts in container.listdir(streams=True, storages=False):
                    if not self._charge_member(location):
                        return
                    member_name = "/".join(parts)
                    member_location = self._join_location(location, member_name)
                    size = container.get_size(parts)
                    if size > self.limits.max_member_size:
                        if self.report is not None:
                            self.report.partial = True
                            self.report.warnings.append(f"Oversized OLE stream skipped: {member_location}")
                        continue
                    payload = container.openstream(parts).read(self.limits.max_member_size + 1)
                    if len(payload) > self.limits.max_member_size:
                        continue
                    self._scan_bytes(payload, member_location, depth + 1)
        except Exception as exc:
            if self.report is not None:
                self.report.warnings.append(f"Unable to parse OLE file {location}: {exc}")

    def _scan_pe(self, data: bytes, location: str, depth: int) -> None:
        self._scan_generic_bytes(data, f"{location}[pe-raw]", depth, allow_encoded=False)
        blobs = self._extract_pe_certificate_blobs(data)
        if not blobs:
            return
        if pkcs7 is None:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Install cryptography for Authenticode certificate scanning: {location}")
            return
        for blob_index, blob in enumerate(blobs, 1):
            try:
                certificates = pkcs7.load_der_pkcs7_certificates(blob)
            except Exception:
                continue
            for cert_index, certificate in enumerate(certificates, 1):
                cert_location = f"{location}[authenticode-{blob_index}-{cert_index}]"
                self._analyze_certificate(
                    certificate,
                    cert_location,
                    "PE Authenticode certificate honeytoken candidate",
                )

    def _scan_certificate_container(self, data: bytes, location: str, depth: int) -> None:
        self._scan_generic_bytes(data, f"{location}[certificate-raw]", depth, allow_encoded=False)
        if x509 is None:
            if self.report is not None:
                self.report.partial = True
                self.report.warnings.append(f"Install cryptography for complete certificate scanning: {location}")
            return
        certificates = []
        if b"-----BEGIN CERTIFICATE-----" in data:
            for match in re.finditer(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                data,
                re.DOTALL,
            ):
                try:
                    certificates.append(x509.load_pem_x509_certificate(match.group(0)))
                except Exception:
                    continue
        if pkcs7 is not None:
            for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
                try:
                    certificates.extend(loader(data))
                except Exception:
                    pass
        try:
            certificates.append(x509.load_der_x509_certificate(data))
        except Exception:
            pass
        if pkcs12 is not None:
            try:
                _, certificate, additional = pkcs12.load_key_and_certificates(data, None)
                if certificate is not None:
                    certificates.append(certificate)
                certificates.extend(additional or ())
            except Exception:
                pass
        seen: set[tuple[int, str]] = set()
        for index, certificate in enumerate(certificates, 1):
            key = (certificate.serial_number, certificate.subject.rfc4514_string())
            if key in seen:
                continue
            seen.add(key)
            self._analyze_certificate(
                certificate,
                f"{location}[certificate-{index}]",
                "X.509 certificate honeytoken candidate",
            )

    def _analyze_certificate(self, certificate: object, location: str, category: str) -> None:
        if x509 is None:
            return
        fields: list[tuple[str, str]] = []
        try:
            fields.append(("subject", certificate.subject.rfc4514_string()))
            fields.append(("issuer", certificate.issuer.rfc4514_string()))
        except Exception:
            return
        extension_types = (
            x509.SubjectAlternativeName,
            x509.IssuerAlternativeName,
        )
        for extension_type in extension_types:
            try:
                extension = certificate.extensions.get_extension_for_class(extension_type).value
            except Exception:
                continue
            for general_name in extension:
                value = getattr(general_name, "value", None)
                if isinstance(value, str):
                    fields.append((extension_type.__name__, value))
        try:
            extension = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
            for description in extension:
                value = getattr(description.access_location, "value", None)
                if isinstance(value, str):
                    fields.append(("AuthorityInformationAccess", value))
        except Exception:
            pass
        try:
            extension = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            for point in extension:
                for general_name in point.full_name or ():
                    value = getattr(general_name, "value", None)
                    if isinstance(value, str):
                        fields.append(("CRLDistributionPoints", value))
        except Exception:
            pass
        for field_name, field_value in fields:
            if not field_value:
                continue
            callback = self._contains_callback_indicator(field_value) or self._indicator_has_thinkst_token(field_value)
            marker = "canarytoken" in field_value.lower() or "thinkst" in field_value.lower()
            if not callback and not marker:
                continue
            self._add_finding(
                "critical" if callback else "high",
                "high",
                category,
                location,
                self._mask_url(field_value),
                f"Certificate {field_name}: {field_value}",
            )
            for match in URL_RE.finditer(field_value):
                self._mark_contextual(location, match.group(0))
            for match in FQDN_RE.finditer(field_value):
                self._mark_contextual(location, match.group(0))

    @staticmethod
    def _extract_pe_certificate_blobs(data: bytes) -> list[bytes]:
        if len(data) < 64 or not data.startswith(b"MZ"):
            return []
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []
            optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            optional_offset = pe_offset + 24
            optional_end = optional_offset + optional_size
            if optional_end > len(data) or optional_size < 120:
                return []
            magic = struct.unpack_from("<H", data, optional_offset)[0]
            if magic == 0x10B:
                number_offset = optional_offset + 92
                directory_offset = optional_offset + 96
            elif magic == 0x20B:
                number_offset = optional_offset + 108
                directory_offset = optional_offset + 112
            else:
                return []
            if number_offset + 4 > optional_end:
                return []
            directory_count = struct.unpack_from("<I", data, number_offset)[0]
            security_offset = directory_offset + 4 * 8
            if directory_count <= 4 or security_offset + 8 > optional_end:
                return []
            table_offset, table_size = struct.unpack_from("<II", data, security_offset)
            if table_offset == 0 or table_size < 8 or table_offset >= len(data):
                return []
            table_end = min(len(data), table_offset + table_size)
            cursor = table_offset
            blobs = []
            while cursor + 8 <= table_end:
                length, _, certificate_type = struct.unpack_from("<IHH", data, cursor)
                if length < 8 or cursor + length > table_end:
                    break
                if certificate_type == 0x0002:
                    blobs.append(data[cursor + 8:cursor + length])
                cursor += (length + 7) & ~7
            return blobs
        except (struct.error, OverflowError):
            return []

    def _scan_qr(self, data: bytes, location: str) -> None:
        if not self.enable_qr or cv2 is None or np is None or len(data) > self.limits.max_qr_image_size:
            return
        try:
            image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
            if image is None:
                return
            detector = cv2.QRCodeDetector()
            values: list[str] = []
            try:
                ok, decoded_info, _, _ = detector.detectAndDecodeMulti(image)
                if ok:
                    values.extend(value for value in decoded_info if value)
            except Exception:
                pass
            if not values:
                try:
                    value, _, _ = detector.detectAndDecode(image)
                    if value:
                        values.append(value)
                except Exception:
                    pass
            for index, value in enumerate(dict.fromkeys(values), 1):
                if not self._qr_payload_relevant(value):
                    continue
                qr_location = f"{location}[qr-{index}]"
                callback = self._contains_callback_indicator(value)
                self._add_finding(
                    "high" if callback else "medium",
                    "high" if callback else "low",
                    "QR code callback honeytoken" if callback else "QR code external-reference honeytoken candidate",
                    qr_location,
                    self._mask_url(self._truncate(value, 512)),
                    "QR payload decoded from image",
                )
                self._mark_contextual(qr_location, value)
                self._analyze_text(value, qr_location, 0, allow_encoded=False)
        except Exception as exc:
            if self.report is not None:
                self.report.warnings.append(f"QR scan failed at {location}: {exc}")

    def _detect_kind(self, data: bytes, name: str) -> str:
        if data.startswith(b"%PDF-"):
            return "pdf"
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
            return "zip"
        if data.startswith(b"\x1f\x8b"):
            return "gzip"
        if data.startswith(b"BZh"):
            return "bzip2"
        if data.startswith(b"\xfd7zXZ\x00"):
            return "xz"
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "ole"
        if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
            return "rar"
        if data.startswith(b"MZ"):
            return "pe"
        if data.startswith(b"-----BEGIN CERTIFICATE-----"):
            return "certificate"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if data.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "gif"
        if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return "webp"
        if data.startswith(b"BM"):
            return "bmp"
        if data.startswith((b"II*\x00", b"MM\x00*")):
            return "tiff"
        stripped = data[:4096].lstrip()
        if stripped.startswith(b"{\\rtf"):
            return "rtf"
        if self._looks_like_mime(data):
            return "mime"
        lower_name = name.lower()
        if lower_name.endswith((".cer", ".crt", ".der", ".pem", ".p7b", ".p7c", ".p7s", ".p12", ".pfx")) and (
            data.startswith(b"0") or b"-----BEGIN CERTIFICATE-----" in data[:65536] or b"-----BEGIN PKCS7-----" in data[:65536]
        ):
            return "certificate"
        if lower_name.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")):
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
                    return "tar"
            except (tarfile.TarError, OSError, EOFError):
                pass
        if len(data) >= 512 and data[257:262] in {b"ustar", b"ustar\x00"}:
            return "tar"
        return "generic"

    def _text_views(self, data: bytes) -> list[tuple[str, str]]:
        if not data:
            return []
        sample = data[: min(len(data), 65536)]
        views: list[tuple[str, str]] = []
        if data.startswith(b"\xef\xbb\xbf"):
            decoded = data.decode("utf-8-sig", "replace")
            if self._looks_like_decoded_text(decoded[:65536]):
                views.append(("utf-8-sig", decoded))
            return views
        if data.startswith(b"\xff\xfe\x00\x00"):
            decoded = data.decode("utf-32-le", "replace")
            if self._looks_like_decoded_text(decoded[:65536]):
                views.append(("utf-32-le", decoded))
            return views
        if data.startswith(b"\x00\x00\xfe\xff"):
            decoded = data.decode("utf-32-be", "replace")
            if self._looks_like_decoded_text(decoded[:65536]):
                views.append(("utf-32-be", decoded))
            return views
        if data.startswith(b"\xff\xfe"):
            decoded = data.decode("utf-16-le", "replace")
            if self._looks_like_decoded_text(decoded[:65536]):
                views.append(("utf-16-le", decoded))
            return views
        if data.startswith(b"\xfe\xff"):
            decoded = data.decode("utf-16-be", "replace")
            if self._looks_like_decoded_text(decoded[:65536]):
                views.append(("utf-16-be", decoded))
            return views
        nul_ratio = sample.count(0) / max(1, len(sample))
        if nul_ratio >= 0.15:
            even_nuls = sample[0::2].count(0)
            odd_nuls = sample[1::2].count(0)
            if odd_nuls > even_nuls * 2:
                decoded = data.decode("utf-16-le", "ignore")
                if self._looks_like_decoded_text(decoded[:65536]):
                    views.append(("utf-16-le", decoded))
            elif even_nuls > odd_nuls * 2:
                decoded = data.decode("utf-16-be", "ignore")
                if self._looks_like_decoded_text(decoded[:65536]):
                    views.append(("utf-16-be", decoded))
            return views
        try:
            decoded_utf8 = data.decode("utf-8")
        except UnicodeDecodeError:
            decoded_utf8 = None
        if decoded_utf8 is not None and self._looks_like_decoded_text(decoded_utf8[:65536]):
            views.append(("utf-8", decoded_utf8))
            return views
        ascii_text_bytes = sum(byte in PRINTABLE_BYTES for byte in sample)
        disallowed_controls = sum(
            byte < 32 and byte not in (9, 10, 13) or 127 <= byte <= 159
            for byte in sample
        )
        if (
            ascii_text_bytes / max(1, len(sample)) >= 0.65
            and disallowed_controls / max(1, len(sample)) <= 0.01
        ):
            decoded_cp1252 = data.decode("windows-1252", "replace")
            if self._looks_like_decoded_text(decoded_cp1252[:65536]):
                views.append(("windows-1252", decoded_cp1252))
        return views

    @staticmethod
    def _looks_like_decoded_text(text: str) -> bool:
        if not text:
            return False
        sample = text[:65536]
        allowed = sum(character.isprintable() or character in "\t\r\n" for character in sample)
        controls = sum(
            ord(character) < 32 and character not in "\t\r\n" or 127 <= ord(character) <= 159
            for character in sample
        )
        replacements = sample.count("\ufffd")
        length = max(1, len(sample))
        return allowed / length >= 0.85 and controls / length <= 0.01 and replacements / length <= 0.01

    def _extract_ascii_strings(self, data: bytes) -> str:
        strings = re.findall(rb"[\x09\x20-\x7e]{6,}", data)
        if not strings:
            return ""
        total = 0
        selected: list[str] = []
        for item in strings:
            if total + len(item) > self.limits.max_member_size:
                break
            selected.append(item.decode("ascii", "ignore"))
            total += len(item) + 1
        return "\n".join(selected)

    def _decode_backslash_escapes(self, text: str) -> str:
        def replace_hex(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        def replace_unicode(match: re.Match[str]) -> str:
            try:
                value = int(match.group(1), 16)
                if 0 <= value <= 0x10FFFF:
                    return chr(value)
            except ValueError:
                pass
            return match.group(0)

        decoded = re.sub(r"\\x([0-9A-Fa-f]{2})", replace_hex, text)
        decoded = re.sub(r"\\u([0-9A-Fa-f]{4})", replace_unicode, decoded)
        decoded = re.sub(r"\\U([0-9A-Fa-f]{8})", replace_unicode, decoded)
        return decoded

    def _decode_rtf(self, text: str) -> str:
        def replace_hex(match: re.Match[str]) -> str:
            try:
                return bytes.fromhex(match.group(1)).decode("windows-1252", "replace")
            except ValueError:
                return ""

        decoded = re.sub(r"\\'([0-9A-Fa-f]{2})", replace_hex, text)

        def replace_unicode(match: re.Match[str]) -> str:
            try:
                value = int(match.group(1))
                if value < 0:
                    value += 65536
                return chr(value)
            except (ValueError, OverflowError):
                return ""

        decoded = re.sub(r"\\u(-?\d+)(?:\?)?", replace_unicode, decoded)
        return decoded

    def _pdf_filters(self, dictionary: bytes) -> list[str]:
        match = PDF_FILTER_RE.search(dictionary)
        if not match:
            return []
        if match.group("single"):
            names = [match.group("single")]
        else:
            names = PDF_FILTER_NAME_RE.findall(match.group("array") or b"")
        aliases = {
            "Fl": "FlateDecode",
            "AHx": "ASCIIHexDecode",
            "A85": "ASCII85Decode",
            "LZW": "LZWDecode",
            "RL": "RunLengthDecode",
        }
        result = []
        for name in names:
            decoded = name.decode("ascii", "ignore")
            result.append(aliases.get(decoded, decoded))
        return result

    def _decode_pdf_filters(self, data: bytes, filters: Sequence[str], dictionary: bytes) -> bytes | None:
        output = data
        for filter_name in filters:
            try:
                if filter_name == "FlateDecode":
                    decoded = self._bounded_zlib_decompress(output)
                    if decoded is None:
                        decoded = self._bounded_zlib_decompress(output, raw=True)
                    if decoded is None:
                        return None
                    output = decoded
                elif filter_name == "ASCIIHexDecode":
                    compact = re.sub(rb"\s+", b"", output).split(b">", 1)[0]
                    if len(compact) % 2:
                        compact += b"0"
                    output = binascii.unhexlify(compact)
                elif filter_name == "ASCII85Decode":
                    stripped = output.strip()
                    adobe = stripped.startswith(b"<~") or stripped.endswith(b"~>")
                    if not adobe:
                        stripped = stripped.rstrip(b"~>")
                    output = base64.a85decode(stripped, adobe=adobe, ignorechars=b" \t\n\r\x0b\x0c")
                elif filter_name == "RunLengthDecode":
                    output = self._pdf_run_length_decode(output)
                elif filter_name == "LZWDecode":
                    early_change = 0 if re.search(rb"/EarlyChange\s+0\b", dictionary) else 1
                    output = self._pdf_lzw_decode(output, early_change)
                elif filter_name in {"DCTDecode", "JPXDecode", "CCITTFaxDecode", "JBIG2Decode", "Crypt"}:
                    return None
                else:
                    return None
            except (ValueError, binascii.Error, zlib.error, MemoryError):
                return None
            if len(output) > self.limits.max_member_size:
                return None
        return output

    def _pdf_image_payload(self, data: bytes, filters: Sequence[str], dictionary: bytes) -> bytes | None:
        for index, filter_name in enumerate(filters):
            if filter_name not in {"DCTDecode", "JPXDecode"}:
                continue
            prefix = filters[:index]
            return self._decode_pdf_filters(data, prefix, dictionary) if prefix else data
        return None

    def _bounded_zlib_decompress(self, data: bytes, raw: bool = False) -> bytes | None:
        try:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS if raw else zlib.MAX_WBITS)
            output = decompressor.decompress(data, self.limits.max_member_size + 1)
            if len(output) > self.limits.max_member_size:
                return None
            remaining = self.limits.max_member_size + 1 - len(output)
            output += decompressor.flush(remaining)
            if len(output) > self.limits.max_member_size:
                return None
            return output
        except zlib.error:
            return None

    def _pdf_run_length_decode(self, data: bytes) -> bytes:
        output = bytearray()
        index = 0
        while index < len(data):
            length = data[index]
            index += 1
            if length == 128:
                break
            if length <= 127:
                count = length + 1
                output.extend(data[index:index + count])
                index += count
            else:
                count = 257 - length
                if index >= len(data):
                    break
                output.extend(data[index:index + 1] * count)
                index += 1
            if len(output) > self.limits.max_member_size:
                raise ValueError("RunLengthDecode output limit exceeded")
        return bytes(output)

    def _pdf_lzw_decode(self, data: bytes, early_change: int) -> bytes:
        clear_code = 256
        end_code = 257
        bit_position = 0
        code_size = 9
        table: dict[int, bytes] = {index: bytes([index]) for index in range(256)}
        next_code = 258
        previous: bytes | None = None
        output = bytearray()

        def read_code(bits: int) -> int | None:
            nonlocal bit_position
            if bit_position + bits > len(data) * 8:
                return None
            value = 0
            for _ in range(bits):
                byte_index = bit_position // 8
                bit_index = 7 - bit_position % 8
                value = (value << 1) | ((data[byte_index] >> bit_index) & 1)
                bit_position += 1
            return value

        while True:
            code = read_code(code_size)
            if code is None or code == end_code:
                break
            if code == clear_code:
                table = {index: bytes([index]) for index in range(256)}
                next_code = 258
                code_size = 9
                previous = None
                continue
            if code in table:
                entry = table[code]
            elif code == next_code and previous is not None:
                entry = previous + previous[:1]
            else:
                raise ValueError("Invalid LZW code")
            output.extend(entry)
            if len(output) > self.limits.max_member_size:
                raise ValueError("LZWDecode output limit exceeded")
            if previous is not None and next_code < 4096:
                table[next_code] = previous + entry[:1]
                next_code += 1
                threshold = (1 << code_size) - early_change
                if next_code >= threshold and code_size < 12:
                    code_size += 1
            previous = entry
        return bytes(output)

    def _decode_pdf_string(self, value: bytes) -> str:
        if value.startswith(b"<") and value.endswith(b">") and not value.startswith(b"<<"):
            compact = re.sub(rb"\s+", b"", value[1:-1])
            if len(compact) % 2:
                compact += b"0"
            try:
                decoded = bytes.fromhex(compact.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                return ""
        elif value.startswith(b"(") and value.endswith(b")"):
            source = value[1:-1]
            output = bytearray()
            index = 0
            escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
            while index < len(source):
                byte = source[index]
                if byte != 0x5C:
                    output.append(byte)
                    index += 1
                    continue
                index += 1
                if index >= len(source):
                    break
                byte = source[index]
                if byte in escapes:
                    output.append(escapes[byte])
                    index += 1
                elif byte in (ord("("), ord(")"), ord("\\")):
                    output.append(byte)
                    index += 1
                elif byte in (10, 13):
                    if byte == 13 and index + 1 < len(source) and source[index + 1] == 10:
                        index += 2
                    else:
                        index += 1
                elif ord("0") <= byte <= ord("7"):
                    digits = bytes([byte])
                    index += 1
                    for _ in range(2):
                        if index < len(source) and ord("0") <= source[index] <= ord("7"):
                            digits += bytes([source[index]])
                            index += 1
                        else:
                            break
                    output.append(int(digits, 8) & 0xFF)
                else:
                    output.append(byte)
                    index += 1
            decoded = bytes(output)
        else:
            return ""
        if decoded.startswith((b"\xfe\xff", b"\xff\xfe")):
            encoding = "utf-16-be" if decoded.startswith(b"\xfe\xff") else "utf-16-le"
            return decoded[2:].decode(encoding, "replace")
        return decoded.decode("utf-8", "replace")

    def _decoded_payload_interesting(self, data: bytes) -> bool:
        if not data or len(data) > self.limits.max_member_size:
            return False
        magic = (
            b"%PDF-",
            b"PK\x03\x04",
            b"\x1f\x8b",
            b"BZh",
            b"\xfd7zXZ\x00",
            b"\xd0\xcf\x11\xe0",
            b"\x89PNG",
            b"{\\rtf",
            b"<svg",
            b"<html",
            b"<?xml",
        )
        stripped = data.lstrip().lower()
        if any(data.startswith(item) or stripped.startswith(item.lower()) for item in magic):
            return True
        lower = data[: min(len(data), 4 * 1024 * 1024)].lower()
        return any(
            marker in lower
            for marker in (
                b"http://",
                b"https://",
                b"ldap://",
                b"smb://",
                b"\\\\",
                b"canary",
                b"mcpservers",
                b"aws_access_key_id",
                b"silentprocessexit",
                b"resolve-dnsname",
                b"${jndi:",
            )
        )

    def _add_finding(self, severity: str, confidence: str, category: str, location: str, value: str, evidence: str) -> None:
        if self.report is None:
            return
        if severity not in SEVERITY_ORDER:
            severity = "low"
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER[self.minimum_severity]:
            return
        value = self._redact_sensitive_text(value)
        evidence = self._redact_sensitive_text(evidence)
        value = self._truncate(re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value).strip(), 1024)
        evidence = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", evidence)
        evidence = self._truncate(re.sub(r"\s+", " ", evidence).strip(), 512)
        location_key = re.sub(
            r"(?:\[(?:html-unescaped|slash-unescaped|percent-decoded|escape-decoded)\])+$",
            "",
            location,
        )
        fingerprint = (location_key, category, value)
        if fingerprint in self._seen:
            return
        if len(self.report.findings) >= self.limits.max_findings:
            self.report.partial = True
            warning = f"Finding limit of {self.limits.max_findings} reached"
            if warning not in self.report.warnings:
                self.report.warnings.append(warning)
            return
        self._seen.add(fingerprint)
        self.report.findings.append(Finding(severity, confidence, category, location, value, evidence))

    def _charge_expanded(self, size: int, location: str) -> bool:
        if self.report is None:
            return False
        if size > self.limits.max_member_size:
            self.report.partial = True
            self.report.warnings.append(f"Expanded payload exceeds member limit at {location}")
            return False
        if self.budget.expanded_bytes + size > self.limits.max_total_expanded:
            self.report.partial = True
            warning = f"Total expanded-data limit reached at {location}"
            if warning not in self.report.warnings:
                self.report.warnings.append(warning)
            return False
        self.budget.expanded_bytes += size
        return True

    def _charge_member(self, location: str) -> bool:
        if self.report is None:
            return False
        if self.budget.members >= self.limits.max_members:
            self.report.partial = True
            warning = f"Archive member limit reached at {location}"
            if warning not in self.report.warnings:
                self.report.warnings.append(warning)
            return False
        self.budget.members += 1
        return True

    def _consume_encoded_candidate(self) -> bool:
        if self.budget.encoded_candidates >= self.limits.max_encoded_candidates:
            return False
        self.budget.encoded_candidates += 1
        return True

    @staticmethod
    def _read_limited(handle: BinaryIO, limit: int) -> bytes | None:
        data = handle.read(limit + 1)
        if len(data) > limit:
            return None
        return data

    @staticmethod
    def _looks_like_mime(data: bytes) -> bool:
        head = data[:16384]
        if b"\x00" in head:
            return False
        header_end = head.find(b"\r\n\r\n")
        if header_end < 0:
            header_end = head.find(b"\n\n")
        if header_end < 0:
            return False
        headers = head[:header_end].lower()
        return (
            b"mime-version:" in headers
            or b"content-type:" in headers
            or (b"from:" in headers and b"subject:" in headers and b"date:" in headers)
        )

    @staticmethod
    def _join_location(parent: str, child: str) -> str:
        safe = child.replace("\\", "/")
        safe = posixpath.normpath("/" + safe).lstrip("/")
        if safe.startswith("../") or safe == "..":
            safe = safe.replace("../", "")
        return f"{parent}!/{safe}"

    @staticmethod
    def _decompressed_name(location: str, kind: str) -> str:
        suffixes = {
            "gzip": (".gz", ".tgz", ".svgz"),
            "bzip2": (".bz2", ".tbz2", ".tbz"),
            "xz": (".xz", ".txz"),
        }
        lowered = location.lower()
        for suffix in suffixes[kind]:
            if lowered.endswith(suffix):
                return location[: -len(suffix)]
        return location

    @staticmethod
    def _extension_for_mime(content_type: str) -> str:
        mapping = {
            "text/plain": "txt",
            "text/html": "html",
            "image/svg+xml": "svg",
            "application/pdf": "pdf",
            "application/zip": "zip",
            "application/rtf": "rtf",
            "message/rfc822": "eml",
        }
        return mapping.get(content_type.lower(), "bin")

    @staticmethod
    def _clean_indicator(value: str) -> str:
        value = html.unescape(value).replace("\\/", "/").strip()
        value = value.strip("\x00\t\r\n <>\"'`")
        while value and value[-1] in ".,;:!?":
            value = value[:-1]
        pairs = {")": "(", "]": "[", "}": "{"}
        while value and value[-1] in pairs and value.count(pairs[value[-1]]) < value.count(value[-1]):
            value = value[:-1]
        return value

    @staticmethod
    def _normalize_host(host: str) -> str:
        host = host.strip().strip(".[]").lower()
        if ":" in host and host.count(":") == 1:
            candidate, port = host.rsplit(":", 1)
            if port.isdigit():
                host = candidate
        try:
            return host.encode("ascii").decode("idna") if host.startswith("xn--") else host
        except UnicodeError:
            return host

    def _host_from_indicator(self, value: str) -> str:
        value = self._clean_indicator(value)
        if value.startswith("\\\\"):
            return self._normalize_host(value[2:].split("\\", 1)[0])
        candidate = value
        if value.startswith("//"):
            candidate = "http:" + value
        if re.match(r"(?i)^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
            try:
                return self._normalize_host(urllib.parse.urlsplit(candidate).hostname or "")
            except ValueError:
                return ""
        if "@" in value and EMAIL_RE.fullmatch(value):
            return self._normalize_host(value.rsplit("@", 1)[-1])
        if FQDN_RE.fullmatch(value):
            return self._normalize_host(value)
        if re.fullmatch(r"(?i)[A-Za-z0-9.-]+:\d{1,5}", value):
            return self._normalize_host(value.rsplit(":", 1)[0])
        return ""

    def _is_external_reference(self, value: str) -> bool:
        value = self._clean_indicator(value)
        if not value or value.startswith(('#', 'data:', 'cid:', 'mailto:', 'tel:', 'javascript:', 'about:')):
            return False
        if value.startswith("\\\\"):
            return True
        if value.startswith("//"):
            return bool(self._host_from_indicator(value))
        if re.match(r"(?i)^[A-Za-z][A-Za-z0-9+.-]*://", value):
            return bool(self._host_from_indicator(value))
        return False

    def _is_ignored_host(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        return any(normalized == suffix or normalized.endswith("." + suffix) for suffix in IGNORED_HOST_SUFFIXES)

    def _is_known_callback_host(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        return any(normalized == suffix or normalized.endswith("." + suffix) for suffix in self.callback_host_suffixes)

    def _host_has_thinkst_token_label(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        return any(THINKST_TOKEN_LABEL_RE.fullmatch(label) for label in normalized.split("."))

    def _indicator_has_thinkst_token(self, value: str) -> bool:
        cleaned = self._clean_indicator(value)
        if not cleaned:
            return False
        if "@" in cleaned and EMAIL_RE.fullmatch(cleaned):
            local, host = cleaned.rsplit("@", 1)
            if THINKST_TOKEN_LABEL_RE.fullmatch(local.lower()) or self._host_has_thinkst_token_label(host):
                return True
        host = self._host_from_indicator(cleaned)
        if host and self._host_has_thinkst_token_label(host):
            return True
        if cleaned.startswith("\\\\"):
            components = cleaned[2:].split("\\")
            return any(THINKST_TOKEN_LABEL_RE.fullmatch(component.lower()) for component in components)
        candidate = "http:" + cleaned if cleaned.startswith("//") else cleaned
        try:
            parts = urllib.parse.urlsplit(candidate)
        except ValueError:
            parts = None
        if parts is not None and parts.scheme and parts.hostname:
            path = urllib.parse.unquote(parts.path)
            for component in path.split("/"):
                if THINKST_TOKEN_LABEL_RE.fullmatch(component.lower()):
                    return True
            for key, item in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
                for component in (key, item):
                    if THINKST_TOKEN_LABEL_RE.fullmatch(urllib.parse.unquote(component).lower()):
                        return True
        return THINKST_TOKEN_LABEL_RE.fullmatch(cleaned.lower()) is not None

    def _looks_like_callback_host(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        labels = normalized.split(".")
        for label in labels[:-1]:
            if not HIGH_ENTROPY_LABEL_RE.fullmatch(label):
                continue
            compact = label.replace("-", "")
            if len(compact) < 16 or not any(ch.isalpha() for ch in compact) or not any(ch.isdigit() for ch in compact):
                continue
            if self._shannon_entropy(compact.lower()) >= 3.5:
                return True
        return False

    def _contains_callback_indicator(self, text: str) -> bool:
        for match in URL_RE.finditer(text):
            value = match.group(0)
            host = self._host_from_indicator(value)
            if self._is_known_callback_host(host) or self._indicator_has_thinkst_token(value):
                return True
        for match in PROTOCOL_RELATIVE_URL_RE.finditer(text):
            value = match.group(0)
            host = self._host_from_indicator(value)
            if self._is_known_callback_host(host) or self._indicator_has_thinkst_token(value):
                return True
        for match in UNC_RE.finditer(text):
            value = match.group(0)
            host = self._host_from_indicator(value)
            if self._is_known_callback_host(host) or self._indicator_has_thinkst_token(value):
                return True
        for match in FQDN_RE.finditer(text):
            host = self._normalize_host(match.group(0))
            if self._is_known_callback_host(host) or self._host_has_thinkst_token_label(host):
                return True
        return False

    def _qr_payload_relevant(self, value: str) -> bool:
        return bool(
            URL_RE.search(value)
            or PROTOCOL_RELATIVE_URL_RE.search(value)
            or UNC_RE.search(value)
            or FQDN_RE.search(value)
            or EMAIL_RE.search(value)
            or AWS_ACCESS_KEY_RE.search(value)
            or JNDI_RE.search(value)
            or self._contains_callback_indicator(value)
        )

    @staticmethod
    def _is_placeholder_value(value: str) -> bool:
        raw = value.strip().lower()
        if raw.startswith(("${", "{{", "%(", "$env:", "env.")):
            return True
        normalized = raw.strip("<>[]{}()\"'")
        if not normalized:
            return True
        return any(
            marker in normalized
            for marker in (
                "example",
                "placeholder",
                "your_client",
                "your-client",
                "client_id_here",
                "client-secret-here",
                "changeme",
                "replace_me",
                "replace-me",
                "xxxxxxxx",
            )
        )

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = collections.Counter(value)
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _svg_hidden(attrs: str, document: str) -> bool:
        width_match = re.search(r"(?i)\bwidth\s*=\s*[\"']?([0-9]+(?:\.[0-9]+)?)", attrs)
        height_match = re.search(r"(?i)\bheight\s*=\s*[\"']?([0-9]+(?:\.[0-9]+)?)", attrs)
        if width_match and height_match and float(width_match.group(1)) <= 1 and float(height_match.group(1)) <= 1:
            return True
        root = re.search(r"(?is)<svg\b([^>]*)>", document)
        if root:
            root_width = re.search(r"(?i)\bwidth\s*=\s*[\"']?([0-9]+(?:\.[0-9]+)?)", root.group(1))
            root_height = re.search(r"(?i)\bheight\s*=\s*[\"']?([0-9]+(?:\.[0-9]+)?)", root.group(1))
            if root_width and root_height and float(root_width.group(1)) <= 1 and float(root_height.group(1)) <= 1:
                return True
        normalized = re.sub(r"\s+", "", attrs.lower())
        return any(token in normalized for token in ("opacity:0", "display:none", "visibility:hidden", "width:0", "height:0"))

    def _mark_contextual(self, location: str, value: str) -> None:
        normalized = self._normalize_indicator(value)
        if normalized:
            self._contextual_indicators.add((location, normalized))
        host = self._host_from_indicator(value)
        if host:
            self._contextual_indicators.add((location, self._normalize_indicator(host)))
        for match in FQDN_RE.finditer(value):
            self._contextual_indicators.add((location, self._normalize_indicator(match.group(0))))

    def _is_contextual(self, location: str, value: str) -> bool:
        normalized = self._normalize_indicator(value)
        if not normalized:
            return False
        return (location, normalized) in self._contextual_indicators

    def _normalize_indicator(self, value: str) -> str:
        cleaned = self._clean_indicator(value)
        if cleaned.startswith("//"):
            cleaned = "http:" + cleaned
        if cleaned.startswith("\\\\"):
            return cleaned.lower()
        try:
            parts = urllib.parse.urlsplit(cleaned)
        except ValueError:
            return cleaned.lower()
        if parts.scheme and parts.hostname:
            host = self._normalize_host(parts.hostname)
            port = f":{parts.port}" if parts.port else ""
            return urllib.parse.urlunsplit((parts.scheme.lower(), host + port, parts.path, parts.query, ""))
        return cleaned.lower()

    @staticmethod
    def _overlaps(start: int, end: int, occupied: Sequence[tuple[int, int]]) -> bool:
        return any(start < other_end and end > other_start for other_start, other_end in occupied)

    @staticmethod
    def _evidence_around(text: str, offset: int, radius: int = 180) -> str:
        start = max(0, offset - radius)
        end = min(len(text), offset + radius)
        return text[start:end]

    @staticmethod
    def _byte_evidence(data: bytes, start: int, end: int, radius: int = 96) -> str:
        left = max(0, start - radius)
        right = min(len(data), end + radius)
        return data[left:right].decode("utf-8", "replace")

    @staticmethod
    def _truncate(value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return value[: max(0, limit - 3)] + "..."

    def _redact_sensitive_text(self, text: str) -> str:
        if not text:
            return text
        redacted = text

        def replace_url(match: re.Match[str]) -> str:
            raw = match.group(0)
            cleaned = self._clean_indicator(raw)
            suffix = raw[len(cleaned):] if raw.startswith(cleaned) else ""
            return self._mask_url(cleaned) + suffix

        def replace_unc(match: re.Match[str]) -> str:
            raw = match.group(0)
            cleaned = self._clean_indicator(raw)
            suffix = raw[len(cleaned):] if raw.startswith(cleaned) else ""
            return self._mask_url(cleaned) + suffix

        def replace_host(match: re.Match[str]) -> str:
            host = match.group(0)
            if self._host_has_thinkst_token_label(host) or self._looks_like_callback_host(host):
                return self._mask_hostname(host)
            return host

        redacted = URL_RE.sub(replace_url, redacted)
        redacted = PROTOCOL_RELATIVE_URL_RE.sub(replace_url, redacted)
        redacted = UNC_RE.sub(replace_unc, redacted)
        redacted = FQDN_RE.sub(replace_host, redacted)
        redacted = AWS_ACCESS_KEY_RE.sub(lambda match: self._mask_secret(match.group(0)), redacted)
        redacted = AWS_SECRET_KEY_RE.sub(
            lambda match: match.group(0).replace(match.group(1), self._mask_secret(match.group(1))),
            redacted,
        )
        for pattern in (GITHUB_TOKEN_RE, GOOGLE_API_KEY_RE, SLACK_TOKEN_RE, STRIPE_KEY_RE, JWT_RE):
            redacted = pattern.sub(lambda match: self._mask_secret(match.group(0)), redacted)
        redacted = re.sub(
            r"(?i)(Authorization\s*[:=]\s*[\"']?Bearer\s+)([A-Za-z0-9._~-]{8,})",
            lambda match: match.group(1) + self._mask_secret(match.group(2)),
            redacted,
        )
        redacted = re.sub(
            r"(?i)((?:password|passwd|secret|api[_-]?key|access[_-]?token|accountkey|client-key-data|private_key)\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"';,}]{8,})",
            lambda match: match.group(1) + self._mask_secret(match.group(2)),
            redacted,
        )
        return redacted

    @staticmethod
    def _mask_secret(value: str) -> str:
        value = value.strip()
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * min(12, len(value) - 8) + value[-4:]

    def _mask_url(self, value: str) -> str:
        cleaned = self._clean_indicator(value)
        if cleaned.startswith("\\\\"):
            host = self._host_from_indicator(cleaned)
            if not host:
                return cleaned
            return "\\\\" + self._mask_hostname(host) + cleaned[2 + len(host):]
        candidate = "http:" + cleaned if cleaned.startswith("//") else cleaned
        try:
            parts = urllib.parse.urlsplit(candidate)
        except ValueError:
            return cleaned
        if not parts.scheme or not parts.hostname:
            return cleaned
        host = self._mask_hostname(parts.hostname)
        if parts.port:
            host += f":{parts.port}"
        if parts.username:
            username = self._mask_secret(parts.username)
            password = ":***" if parts.password is not None else ""
            host = f"{username}{password}@{host}"
        path_components = parts.path.split("/")
        path = "/".join(
            self._mask_secret(component) if THINKST_TOKEN_LABEL_RE.fullmatch(urllib.parse.unquote(component).lower()) else component
            for component in path_components
        )
        query = parts.query
        if query:
            pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
            masked_pairs = []
            for key, item in pairs:
                if (
                    re.search(r"(?i)(?:token|key|secret|password|passwd|auth|signature|sig|credential)", key)
                    or THINKST_TOKEN_LABEL_RE.fullmatch(urllib.parse.unquote(item).lower())
                ):
                    item = self._mask_secret(item)
                masked_pairs.append((key, item))
            query = urllib.parse.urlencode(masked_pairs, doseq=True)
        result = urllib.parse.urlunsplit((parts.scheme, host, path, query, ""))
        if cleaned.startswith("//") and result.startswith("http:"):
            result = result[5:]
        return result

    @staticmethod
    def _mask_hostname(host: str) -> str:
        labels = host.split(".")
        masked = []
        for label in labels:
            if THINKST_TOKEN_LABEL_RE.fullmatch(label.lower()) or (len(label) >= 16 and any(ch.isdigit() for ch in label) and any(ch.isalpha() for ch in label)):
                masked.append(label[:4] + "*" * min(12, max(0, len(label) - 8)) + label[-4:])
            else:
                masked.append(label)
        return ".".join(masked)

    @staticmethod
    def _mask_email(value: str) -> str:
        local, host = value.rsplit("@", 1)
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * min(12, len(local) - 2) + local[-1]
        return f"{masked_local}@{CanaryTokenScanner._mask_hostname(host)}"

    @staticmethod
    def _mask_card(digits: str) -> str:
        return "*" * max(0, len(digits) - 4) + digits[-4:]

    @staticmethod
    def _luhn_valid(digits: str) -> bool:
        total = 0
        parity = len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0


def parse_size_mb(value: str) -> int:
    try:
        amount = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if amount <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return int(amount * 1024 * 1024)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="CanaryTokenScanner.py",
        description="Static scanner for network-triggered document tokens, callback indicators, embedded credentials, and nested file content.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit JSON")
    parser.add_argument("--quiet-clean", action="store_true", help="Do not print clean files")
    parser.add_argument("--no-qr", action="store_true", help="Disable optional OpenCV QR decoding")
    parser.add_argument(
        "--callback-domain",
        action="append",
        default=[],
        help="Additional callback-domain suffix to treat as known; repeatable",
    )
    parser.add_argument(
        "--minimum-severity",
        choices=tuple(SEVERITY_ORDER),
        default="low",
        help="Lowest finding severity to report",
    )
    parser.add_argument("--max-file-size-mb", type=parse_size_mb, default=256 * 1024 * 1024)
    parser.add_argument("--max-member-size-mb", type=parse_size_mb, default=64 * 1024 * 1024)
    parser.add_argument("--max-expanded-size-mb", type=parse_size_mb, default=512 * 1024 * 1024)
    parser.add_argument("--max-members", type=int, default=10000)
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--max-findings", type=int, default=2000)
    parser.add_argument("--no-fail", action="store_true", help="Return exit status zero even when findings are present")
    return parser


def iter_files(path: str) -> Iterator[str]:
    if os.path.isfile(path):
        yield os.path.abspath(path)
        return
    for root, directories, files in os.walk(path, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if not os.path.islink(os.path.join(root, directory))
        )
        for name in sorted(files):
            candidate = os.path.join(root, name)
            if os.path.islink(candidate):
                continue
            if os.path.isfile(candidate):
                yield os.path.abspath(candidate)


def report_to_dict(report: FileReport) -> dict[str, object]:
    return {
        "path": report.path,
        "suspicious": report.suspicious,
        "partial": report.partial,
        "findings": [asdict(finding) for finding in report.findings],
        "warnings": report.warnings,
        "errors": report.errors,
    }


def print_human_report(report: FileReport, quiet_clean: bool) -> None:
    if report.suspicious:
        print(f"SUSPICIOUS {report.path}")
        for finding in report.findings:
            print(f"  [{finding.severity.upper()}] [{finding.confidence} confidence] {finding.category}")
            print(f"    location: {finding.location}")
            print(f"    value: {finding.value}")
            if finding.evidence:
                print(f"    evidence: {finding.evidence}")
    elif not quiet_clean:
        print(f"CLEAN {report.path}")
    for warning in report.warnings:
        print(f"  WARNING {warning}", file=sys.stderr)
    for error in report.errors:
        print(f"  ERROR {error}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.exists(target):
        parser.error(f"path does not exist: {target}")
    if args.max_members <= 0 or args.max_depth < 0 or args.max_findings <= 0:
        parser.error("numeric limits must be positive and max-depth must be non-negative")
    limits = Limits(
        max_file_size=args.max_file_size_mb,
        max_member_size=args.max_member_size_mb,
        max_total_expanded=args.max_expanded_size_mb,
        max_members=args.max_members,
        max_depth=args.max_depth,
        max_findings=args.max_findings,
    )
    scanner = CanaryTokenScanner(
        limits,
        args.minimum_severity,
        enable_qr=not args.no_qr,
        callback_domains=args.callback_domain,
    )
    reports = [scanner.scan_file(file_path) for file_path in iter_files(target)]
    if not reports and os.path.isdir(target):
        reports = []
    if args.json_output:
        print(json.dumps([report_to_dict(report) for report in reports], indent=2, ensure_ascii=False))
    else:
        for report in reports:
            print_human_report(report, args.quiet_clean)
    has_findings = any(report.suspicious for report in reports)
    has_errors = any(report.errors for report in reports)
    if has_errors:
        return 2
    if has_findings and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
