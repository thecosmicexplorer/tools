# GitLens Path Traversal Vulnerability Scanner

## Overview
This tool scans URLs for instances of the vulnerable GitLens extension, targeting CVE-2026-54321: a critical path traversal vulnerability in GitLens ≤ v13.0.6. If detected, the tool can actively probe the server to confirm exploitability or run in a passive detection-only mode.

## CVE Information
- **CVE**: CVE-2026-54321
- **CVSS**: 9.6 (Critical)
- **Affected Software**: GitLens ≤ v13.0.6 (VS Code extension)
- **Patched Version**: GitLens v13.0.7
- **Impact**: Arbitrary file read outside the intended root directory
- **Exploit Vector**: Malicious `gitlens.json` file in a workspace
- **Fix**: Input validation and path sanitization (v13.0.7)

## Usage
### Scan a Single Target
