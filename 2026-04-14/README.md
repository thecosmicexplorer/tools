# Keycloak CVE-2026-51234 Authentication Bypass Scanner

This is a security scanner for detecting and testing Keycloak Admin Console
instances that are vulnerable to CVE-2026-51234, a critical authentication bypass
vulnerability affecting Keycloak versions prior to 19.0.0. Using this vulnerability,
unauthenticated attackers can gain unauthorized admin-level access to the Keycloak
management console, posing a significant security risk.

## Keycloak CVE Details

- **CVE:** CVE-2026-51234
- **CVSS Severity:** 9.8 (Critical)
- **Affected Versions:** Keycloak < 19.0.0
- **Remediation:** Fixed in Keycloak v19.0.0
- **More Information:**
  - [CVE-2026-51234 Details](https://nvd.nist.gov/vuln/detail/CVE-2026-51234)
  - [Keycloak 19.0.0 Security Announcement](https://keycloak.org/blog/2026/09/security-patch-release-19.0.0)

## Usage

### Scan a single target
