# Vault KV v2 Path Traversal Scanner (CVE-2026-45678)

## Overview
This tool scans for a critical path traversal vulnerability affecting older versions of HashiCorp Vault's KV v2 Secrets Engine (CVE-2026-45678, CVSS 9.8). The vulnerability allows attackers to perform unauthorized access to sensitive files on the backend filesystem using crafted API requests.

## CVE Details
- **CVE ID**: [CVE-2026-45678](https://nvd.nist.gov/vuln/detail/CVE-2026-45678)
- **Description**: Improper file path sanitization in HashiCorp Vault's KV v2 Secrets Engine allows attackers to bypass security restrictions and access arbitrary files on the backend filesystem.
- **Affected Versions**: Vault < 1.16.1.
- **Patched Versions**: Vault >= 1.16.1.
- **CVSS v3.1 Base Score**: 9.8 (Critical).

## Prerequisites
- Python 3.10+
- `pip install -r requirements.txt` (requires `httpx`)

## Usage
1. Scan a single instance:
   