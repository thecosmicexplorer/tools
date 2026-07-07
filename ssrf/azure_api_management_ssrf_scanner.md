# Azure API Management SSRF Scanner

## Overview

This tool scans for potential Server-Side Request Forgery (SSRF) vulnerabilities in Azure API Management (APIM) instances. By detecting SSRF-friendly misconfigurations and probing their exploitability, this scanner helps identify risky setups where an attacker might abuse the APIM service to make arbitrary HTTP requests.

## CVE(s)
This scanner probes for SSRF vulnerabilities associated with Azure API Management services and related configuration issues. Specific CVEs are not provided, as SSRF can often arise from misconfigurations rather than fixed vulnerabilities.

## Features
- Detects Azure API Management instances via HTTP response fingerprinting.
- Actively probes for SSRF vulnerabilities unless the `--safe` flag is set.
- Allows bulk scanning of multiple targets.
- Generates JSON output for use in automated pipelines or reporting.

## Usage

### Scanning a single target
