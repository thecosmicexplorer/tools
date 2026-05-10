# Grafana Authentication Bypass Scanner

This tool scans for potential authentication bypass vulnerabilities related to misconfigurations or known issues in Grafana instances. Grafana is a widely used open-source platform for monitoring and observability, and improper authentication configurations can result in unauthorized access to sensitive dashboards or administrative functions.

## Supported Vulnerabilities

1. **Anonymous Access Misconfiguration**
   - Checks if the Grafana instance has anonymous access enabled via the `/api/org` endpoint.

2. **Version-Based Vulnerabilities**
   - Detects Grafana versions and compares them against known vulnerabilities, including:
     - `CVE-2021-43798`: Path traversal allowing unauthorized access to local files (fixed in 8.3.0).
     - `CVE-2022-21673`: Misconfigured cookie password leading to Denial of Service (DoS) or remote code execution (fixed in 8.3.0).
     - `CVE-2022-39328`: Incorrect access control in Azure AD OAuth integration (fixed in 9.2.4).

## Features

- **Target Detection**: Automatically identifies Grafana instances by looking for specific fingerprints.
- **Version Extraction**: Extracts and parses the Grafana version from the login page.
- **Anonymous Access Check**: Verifies if anonymous access is enabled using the `/api/org` endpoint.
- **Vulnerability Assessment**: Matches extracted version against known vulnerable versions.
- **Safe Scanning Mode**: Allows detection-only scanning without active probing for vulnerabilities.

## Requirements

- Python 3.10 or newer
- `httpx` library for Python (`pip install httpx`)

## Usage

### Examples

#### Scan a single URL
