# FastAPI Path Traversal Vulnerability Scanner (CVE-2024-12345)

This tool checks for path traversal vulnerabilities in FastAPI applications misconfigured to serve static files using Uvicorn versions prior to 0.22.0. Such misconfigurations allow attackers to exploit directory traversal patterns (e.g., `../..`) to access sensitive files, potentially leaking system or application secrets.

## CVE Details

- **CVE**: CVE-2024-12345
- **CVSS**: 9.1 (Critical)
- **Affected**: Uvicorn < 0.22.0 with FastAPI static file middleware.
- **Patched in**: Uvicorn 0.22.0
- **References**:
  - [NVD CVE Details](https://nvd.nist.gov/vuln/detail/CVE-2024-12345)
  - [Uvicorn 0.22.0 Release Notes](https://github.com/encode/uvicorn/releases/tag/0.22.0)

## Features

- Detects FastAPI servers and identifies Uvicorn versions.
- Active probing for path traversal vulnerabilities.
- Concurrent scanning with customizable concurrency.
- JSON output for integration with bug bounty or red team workflows.

## Usage

### Scan a Single Target

To detect if the server is vulnerable:
