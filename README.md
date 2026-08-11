# CanaryToken and HoneyToken Scanner

CanaryToken Scanner is a static-analysis tool for detecting CanaryTokens, HoneyTokens, tracking resources, callback infrastructure, honeycredentials, and other suspicious external references embedded in files.

The scanner does not open documents in Microsoft Office, Adobe Acrobat, or another native application. It does not resolve domains, follow URLs, contact callback servers, or intentionally generate network traffic.

A finding means that the file contains an indicator or behavior associated with tracking, callback execution, deception credentials, or external resource loading. A finding does not automatically prove malicious intent.

## Key capabilities

- Static scanning without executing the target file
- Recursive directory scanning
- Recursive inspection of nested archives and embedded objects
- Microsoft Office Open XML relationship analysis
- Legacy Microsoft Office OLE stream analysis
- PDF object, action, stream, filter, image, and QR-code analysis
- HTML, SVG, CSS, XML, RTF, MIME, and image metadata inspection
- Known CanaryToken and out-of-band callback-domain recognition
- Thinkst-style token pattern recognition
- High-entropy callback hostname detection
- Honeycredential and synthetic-secret detection
- JSON output for automation and CI pipelines
- Configurable severity threshold and resource limits
- Archive bomb, decompression bomb, oversized member, and recursion protections
- Sensitive values are masked in scanner output

## Supported file types

### Microsoft Office

- `.docx`
- `.docm`
- `.xlsx`
- `.xlsm`
- `.pptx`
- `.pptm`
- Other ZIP-based Open XML packages
- Legacy OLE documents such as `.doc`, `.xls`, and `.ppt` when `olefile` is installed

### Documents and markup

- `.pdf`
- `.rtf`
- `.html`
- `.htm`
- `.svg`
- `.svgz`
- `.xml`
- `.css`
- Plain-text and configuration files
- Generic binary files containing recoverable strings

### Email and MIME

- `.eml`
- MIME messages
- MIME attachments
- HTML email bodies
- MIME `Content-Location` references

### Archives and compression

- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`
- `.tar.bz2`
- `.tbz`
- `.tbz2`
- `.tar.xz`
- `.txz`
- `.gz`
- `.bz2`
- `.xz`
- `.rar` when `rarfile` and a compatible extraction backend are installed

### Images

- `.png`
- `.jpg`
- `.jpeg`
- `.gif`
- `.webp`
- `.bmp`
- `.tif`
- `.tiff`

PNG textual metadata, compressed metadata, ICC profile data, EXIF data, and trailing content are inspected.

QR-code decoding is available when OpenCV and NumPy are installed.

### Certificates and signed executables

- PEM and DER X.509 certificates
- PKCS7 certificate containers
- PKCS12 and PFX containers when they are not password protected
- PE executables containing Authenticode certificates

Certificate subjects, issuers, alternative names, Authority Information Access entries, and CRL distribution points are checked for callback indicators.

## Detection coverage

### External network references

The scanner recognizes references using schemes such as

- `http`
- `https`
- `ftp`
- `ftps`
- `smb`
- `file`
- `ldap`
- `ldaps`
- `nfs`
- `dav`
- `webdav`
- `ssh`
- `git`
- `svn`
- `gopher`
- `dict`

It also detects

- Protocol-relative URLs
- UNC paths
- Fully qualified domain names
- External email addresses
- High-entropy hostname labels
- Thinkst-style 25-character token labels

Common schema domains are ignored to reduce noise

- `schemas.openxmlformats.org`
- `schemas.microsoft.com`
- `purl.org`
- `w3.org`
- `www.w3.org`

### Known callback services

The scanner includes recognition for common CanaryToken, OAST, interaction, webhook, and request-capture domains, including

- Thinkst CanaryTokens infrastructure
- Interactsh
- Burp Collaborator
- Oastify
- Webhook.site
- RequestBin-style services
- Request Catcher
- Beeceptor
- Pipedream

Additional private or organization-specific callback domains can be supplied with `--callback-domain`.

### Microsoft Office Open XML

Office Open XML files are ZIP containers. The scanner reads members directly without extracting them to disk.

It analyzes

- External relationships
- Remote images
- Attached templates
- OLE object relationships
- External links
- External packages
- Hyperlinks
- Excel `WEBSERVICE` formulas
- Excel `IMAGE` formulas
- Excel `FILTERXML` formulas
- Excel `HYPERLINK` formulas
- Office field instructions
- Nested files and embedded objects

Relationship types that can automatically fetch content receive a higher severity than ordinary hyperlinks.

### PDF

The PDF scanner analyzes

- Raw PDF bytes
- `/URI` actions
- `/F` and `/UF` file references
- `/JS` JavaScript strings
- `/OpenAction`
- `/AA` additional actions
- `/SubmitForm`
- `/ImportData`
- `/Launch`
- `/GoToR`
- `/JavaScript`
- Compressed and encoded streams
- Embedded image streams
- QR codes inside supported PDF image streams

Supported PDF stream filters include

- FlateDecode
- ASCIIHexDecode
- ASCII85Decode
- RunLengthDecode
- LZWDecode

JPEG and JPEG 2000 image streams are passed to optional QR-code analysis when possible.

Encrypted PDFs are identified as potentially partial scans because encrypted content may not be available for static inspection.

### HTML and email tracking

The scanner identifies external resources referenced by

- Images
- Scripts
- Iframes
- Frames
- Embedded objects
- Audio and video elements
- Source and track elements
- CSS stylesheets
- Preload and prefetch links
- DNS prefetch and preconnect links
- Icons and manifests
- Meta refresh
- Form actions
- Inline CSS
- HTML email content

Hidden or one-pixel resources receive a higher severity because they are commonly used as tracking pixels.

Hidden-resource checks include

- `display:none`
- `visibility:hidden`
- `opacity:0`
- Zero-width or zero-height elements
- One-pixel width and height
- Off-screen absolute or fixed positioning
- The HTML `hidden` attribute

### SVG

SVG files can automatically load remote content when rendered. The scanner detects external references in

- `<image>`
- `<feImage>`
- `<use>`
- `<script>`
- `<foreignObject>`
- `href`
- `xlink:href`
- SVG CSS `url(...)`
- SVG CSS `@import`

Hidden SVG images and one-pixel SVG resources receive higher severity.

Compressed `.svgz` files are decompressed and inspected recursively.

### CSS

The scanner detects remote resources referenced through

- `url(...)`
- `@import`

CSS contained in standalone files, HTML style elements, inline style attributes, SVG documents, Office packages, and archived content is inspected.

### XML

The scanner detects external network access associated with

- External entities using `SYSTEM`
- External entities using `PUBLIC`
- XInclude references

These patterns can represent tracking resources, callback mechanisms, or unsafe parser behavior.

### RTF

RTF content is decoded and inspected for

- `INCLUDEPICTURE`
- `INCLUDETEXT`
- `DDE`
- `DDEAUTO`
- `HYPERLINK`
- `LINK`
- Hexadecimal RTF object data
- Escaped text and Unicode content
- Nested embedded payloads

### QR codes

When OpenCV and NumPy are installed, the scanner attempts to decode QR codes from supported images and embedded PDF image streams.

Decoded payloads are inspected for

- URLs
- Callback domains
- UNC paths
- Hostnames
- Email addresses
- JNDI payloads
- Credential indicators

QR analysis can be disabled with `--no-qr`.

### Nested and encoded content

The scanner recursively inspects

- Nested archives
- MIME attachments
- Office package members
- OLE streams
- PDF streams
- RTF object data
- Base64-encoded content
- URL-safe Base64 content
- Hexadecimal blobs
- Data URIs
- Gzip, Bzip2, and XZ payloads

Decoded data is scanned only when it appears relevant or contains a recognized file signature.

### Specialized HoneyToken patterns

The scanner includes detection logic for several specific HoneyToken and callback patterns

- Thinkst Sensitive Command CanaryTokens
- `SilentProcessExit` and `MonitorProcess` command tokens
- Thinkst `.UN.<user>.CMD.` hostname markers
- Log4Shell JNDI callback payloads
- Thinkst `.L4J.` hostname markers
- MySQL replication credential HoneyTokens
- SQL Server `xp_dirtree` DNS callback HoneyTokens
- Windows `desktop.ini` remote-icon HoneyTokens
- WebDAV network-folder HoneyTokens
- CrowdStrike client credential HoneyTokens
- SVN metadata HoneyTokens
- WireGuard configuration HoneyTokens
- MCP server Bearer JWE HoneyTokens
- Kubeconfig credential HoneyTokens
- X.509 certificate HoneyTokens
- Authenticode certificate HoneyTokens

### Honeycredentials and synthetic secrets

The scanner can identify values that may have been planted as monitored credentials

- AWS access key IDs
- AWS secret access keys
- GitHub tokens
- Google API keys
- Slack tokens
- Stripe keys
- JWTs
- Private keys
- Azure Storage connection strings
- Database connection URIs
- Kubeconfig client certificates and keys
- MCP Bearer JWE tokens
- Contextual payment-card numbers with valid Luhn checks

These detections are heuristic. A matching credential may be real, synthetic, expired, harmless, or intentionally planted.

## Requirements

The core scanner requires Python 3.10 or later and uses only the Python standard library.

Optional dependencies provide additional coverage.

```bash
python -m pip install olefile cryptography numpy opencv-python rarfile
