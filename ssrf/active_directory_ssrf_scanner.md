# Active Directory Federation Services (AD FS) SSRF Scanner

## Overview
This tool identifies potential Server-Side Request Forgery (SSRF) vulnerabilities in Active Directory Federation Services (AD FS). SSRF vulnerabilities can enable attackers to exploit the server to make unauthorized requests or exfiltrate sensitive information.

## Features
- Detection of AD FS instances via fingerprints and known endpoints.
- Active probing to identify SSRF vulnerabilities (optional: `--safe` mode for detection-only scans).
- High concurrency support for large-scale scanning.
- JSON output for integration into reporting workflows.

## CVE References
- Multi-CVE coverage for SSRF vulnerabilities affecting AD FS.
- Visit [Microsoft AD FS documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/) for additional technical details.

## Usage

