# Vault KV v2 Path Traversal Scanner

This tool identifies and attempts to exploit a critical path traversal vulnerability (CVE-2026-XXXXX) in HashiCorp Vault when the KV v2 secrets engine is used. This vulnerability enables unauthorized attackers to access secrets stored in Vault using a crafted API request. It is crucial to remediate this vulnerability immediately due to its high CVSS rating of 9.6.

## Features

- Detects instances of HashiCorp Vault servers.
- Extracts the Vault version and determines if it is vulnerable.
- Actively probes for path traversal via the KV v2 secrets engine (disabled in `--safe` mode).
- Supports scanning single or multiple targets.
- Provides JSON output for easy integration into security pipelines.
- Includes concurrency control for large-scale scans.

## Requirements

- Python 3.10 or higher.
- [httpx](https://www.python-httpx.org/) library for asynchronous HTTP requests.

## CVE Details

**CVE ID**: CVE-2026-XXXXX  
**Affected Software**:
- HashiCorp Vault prior to version 1.14.0 with the KV v2 secrets engine enabled.

**References**:
- [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-XXXXX)
- [HashiCorp Vault Issue](https://github.com/hashicorp/vault/issues/XXXXX)
- [HashiCorp Forum](https://discuss.hashicorp.com/latest)

## Usage

### Scan a Single Target

