# SuperServer CVE-2026-11234 Authentication Bypass Scanner

This tool is designed to detect and validate the presence of the CVE-2026-11234 authentication 
bypass vulnerability in exposed SuperServer API management panel instances. If the vulnerability 
is present, an attacker can gain unauthorized administrative access to the system by sending specially crafted payloads to the `/login` endpoint.

## CVE Details

- **CVE:** CVE-2026-11234
- **Impact:** Authentication Bypass, Privilege Escalation
- **Affected Versions:** SuperServer API < 5.3.2
- **Description:** A flaw in the SuperServer authentication mechanism allows unauthorized users 
to bypass password validation and obtain an admin token.
- **Patch Released:** March 2026 (version 5.3.2)
- **CVSS Score:** 9.8 (Critical)

## Usage

#### Scan a single target:
