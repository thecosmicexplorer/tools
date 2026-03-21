# Grafana CVE-2025-12345 Server-Side Request Forgery (SSRF) Scanner

This tool scans for instances of Grafana with the Server-Side Request Forgery (SSRF) vulnerability (CVE-2025-12345, CVSS 9.8). The vulnerability exists in Grafana versions prior to 10.0.3 and can allow attackers to trigger SSRF via the "import data source" API endpoint.

## Features
- **Detection**: Identifies whether a server is running Grafana.
- **Version Check**: Determines if the detected version is vulnerable.
- **Active Probing**: Probes for SSRF vulnerability (can be disabled with `--safe` mode).
- **Concurrency**: Scans multiple targets concurrently for faster results.
- **JSON Output**: Saves findings to a JSON file for further analysis.
- **User-friendly Output**: Displays color-coded terminal messages for critical, high, or informational severities.

## Prerequisites
Requires Python 3.10+ and the `httpx` library. Install dependencies with:
