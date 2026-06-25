# Ansible AWX Unauthenticated Remote Code Execution Scanner (CVE-2026-44578)

This tool scans for Ansible AWX servers that are vulnerable to the unauthenticated remote code execution vulnerability (CVE-2026-44578). The vulnerability exists due to a deserialization flaw in the task queue's API endpoint, allowing remote attackers to execute arbitrary code without authentication.

## Features
- Detects vulnerable versions of Ansible AWX.
- Actively probes the target system for exploitation.
- Option to run in safe detection mode without payload execution.
- Support for bulk scanning with concurrent requests.
- Outputs scan results in JSON format.
- TLS verification can be disabled (not recommended).

## Requirements
- Python 3.10 or later
- `httpx` and `packaging` modules (`pip install httpx packaging`)

## Usage Examples

### Scan a single target
