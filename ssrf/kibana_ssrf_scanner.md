# Kibana SSRF Vulnerability Scanner

## Overview
This tool is designed to scan for potential Server-Side Request Forgery (SSRF) vulnerabilities 
in Kibana APIs. It identifies targets running Kibana, extracts their version number, and checks 
for known vulnerabilities related to SSRF. An optional `--safe` mode allows for detection without 
active probing.

### Supported CVEs
- **CVE-2021-22137:** Discovered in Elasticsearch and Kibana, related to the `_snapshot` API. More information [here](https://nvd.nist.gov/vuln/detail/CVE-2021-22137).

## Features
- Detects Kibana installation on target systems.
- Extracts and analyzes Kibana version information.
- Actively probes for SSRF via specific API endpoints.
- Supports JSON output for integration with security workflows.
- Concurrency management for fast scanning of multiple targets.
- Optional `--safe` mode for detection without active exploitation attempts.

## Installation
1. Clone the repository:
   