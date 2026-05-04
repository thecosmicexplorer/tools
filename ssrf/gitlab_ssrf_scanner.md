# GitLab CVE-2025-12345 SSRF Scanner

### Overview
This script is a security tool for scanning GitLab instances vulnerable to Server-Side Request Forgery (SSRF) via the API v4 endpoint. It verifies the presence of GitLab, detects the installed version, and determines whether the instance is vulnerable to CVE-2025-12345.

CVE-2025-12345 is a critical severity vulnerability in certain versions of GitLab, which allows an attacker with API access to perform arbitrary HTTP requests internally. This can be used for data exfiltration or bypassing network restrictions.

### Features
- Scans targets for GitLab installations.
- Extracts the version of GitLab and compares it against patched versions.
- Can perform **safe detection** (only verify instance is potentially vulnerable) or **active probing** to confirm exploitability.
- Reports results in JSON format.

### Usage
#### Single target scan:
