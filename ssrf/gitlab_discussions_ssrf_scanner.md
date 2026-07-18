# GitLab Discussions SSRF Scanner (CVE-2026-78910)

This tool scans for a Server-Side Request Forgery (SSRF) vulnerability in the GitLab Discussions feature (CVE-2026-78910). The vulnerability allows an authenticated user to make arbitrary HTTP requests to internal and external services, potentially leading to sensitive information disclosure.

### CVE Details
- **CVE ID**: CVE-2026-78910
- **Affected Versions**: GitLab < 15.10.3, < 15.9.6, < 15.8.7
- **Severity**: Critical (CVSS 9.4)
- **Vulnerability Description**: The vulnerability arises from insufficient validation in crafted requests made to the Discussions feature, which can lead to SSRF attacks targeting the server or other internal services.
- **Patch Version**: GitLab 15.10.3, 15.9.6, 15.8.7

### Usage
- **Scan a single instance**:
  