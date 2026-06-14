# Jenkins Script Console Remote Code Execution Scanner

This tool scans for Jenkins servers with potential unauthorized access to the "Script Console" feature, a critical vulnerability that could allow remote code execution (RCE). Misconfigurations and outdated Jenkins installations are at risk of such exploitation.

### CVE Reference

- **CVE**: MULTI (multiple vulnerabilities and misconfigurations)
- **Severity**: CRITICAL
- **Vulnerability Class**: Remote Code Execution (RCE)

### Features

- Detects Jenkins instances via known fingerprints.
- Extracts and verifies Jenkins version against a list of known issues.
- Actively probes endpoints to validate exploitability (feature can be disabled with `--safe`).
- Saves findings in JSON format for reporting or integration purposes.
- Supports concurrency for fast, scalable scanning of multiple targets.
- Option to disable SSL/TLS verification for scanning over HTTPS with self-signed certificates.

### Installation

1. Clone this repository:  
   