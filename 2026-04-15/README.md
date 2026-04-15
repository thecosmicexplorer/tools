# GitLab Path Traversal Vulnerability Scanner (CVE-2026-54321)

This tool scans GitLab instances for a critical path traversal vulnerability,
CVE-2026-54321, which allows unauthorized attackers to read arbitrary files
on the server. The tool supports target-based, list-based, and safe mode scanning.

## Vulnerability Details

CVE-2026-54321:
- **Severity**: Critical (CVSS 9.1)
- **Affected Versions**: GitLab CE/EE <= 16.1.4
- **Fixed Version**: GitLab CE/EE 16.1.5
- **Impact**: Unauthorized file read access via path traversal
- **More Info**: [NVD Link](https://nvd.nist.gov/vuln/detail/CVE-2026-54321)

## Features
- GitLab instance detection via common endpoints.
- Version detection to identify vulnerable instances.
- Safe scanning mode (detection-only).
- Active path traversal probing (non-destructive, confirms vulnerability).

## Usage

### Single Target Scan
