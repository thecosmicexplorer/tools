# Harbor Container Registry Authentication Bypass Scanner

This Python script scans for the CVE-2026-56789 vulnerability in Harbor container registry instances. The vulnerability impacts specific versions of Harbor (2.5.0 through 2.8.1) and allows an attacker to bypass authentication protections due to flaws in authentication token validation. Successful exploitation grants unauthorized access to protected API endpoints, enabling privilege escalation scenarios.

## CVE Details:
- **CVE ID:** [CVE-2026-56789](https://nvd.nist.gov/vuln/detail/CVE-2026-56789)
- **CVSS Score:** 9.8 (Critical)
- **Affected Version Range:** Harbor v2.5.0 - v2.8.1
- **Fixed Version:** Harbor v2.8.2
- **Discovered:** April 2026

## Prerequisites:
- Python 3.10+ is required to execute this tool.
- The `httpx` library is used for asynchronous HTTP requests (`pip install httpx`).
- The script uses `colorama` for colorized console output (`pip install colorama`).

## Usage
Run the script to detect vulnerable Harbor registries and optionally attempt to exploit the authentication bypass vulnerability:

