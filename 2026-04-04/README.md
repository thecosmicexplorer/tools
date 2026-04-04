# JFrog Artifactory CVE-2026-54321 Authentication Bypass Scanner

This tool scans JFrog Artifactory instances to detect the critical SSO authentication bypass vulnerability (CVE-2026-54321). 
The vulnerability impacts Artifactory versions 7.53.0 to 7.63.2, allowing attackers to bypass authentication and gain unauthorized 
access to the admin panel.

Fixed in version 7.63.3, this bug is especially relevant for red teams and security researchers targeting enterprise environments 
with SSO-enabled configurations.

## CVE-2026-54321 Details
- Impact: Authentication Bypass vulnerability
- Affected versions: JFrog Artifactory >= 7.53.0, < 7.63.3
- Patched version: 7.63.3
- Vulnerability: Weak validation of SSO authentication tokens
- CVSS Score: 9.8 (Critical)
- References:
  - [CVE-2026-54321 NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2026-54321)
  - [JFrog Security Advisory](https://www.jfrog.com/knowledge-base/security-update-artifactory-7-63-3)

## Usage

### Scan a single target
