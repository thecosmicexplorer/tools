# Keycloak Admin Console CVE-2026-12456 Scanner

This tool scans Keycloak Admin Console instances for a critical authentication bypass vulnerability, identified as CVE-2026-12456. The vulnerability arises due to weak default credentials being configured during setup. Exploiting this flaw, attackers can gain unauthorized access to the administrative interface of Keycloak.

## CVE-2026-12456 Details
- **Impacted Versions**: Keycloak 13.x to 20.0.5
- **Severity**: CVSS 9.8 (Critical)
- **Vulnerability**: Incorrect configuration of the default admin credentials allows attackers to gain full administrative access to the system.
- **Fixed Version**: Keycloak ≥ 20.0.6
- For details, see: https://nvd.nist.gov/vuln/detail/CVE-2026-12456

## Usage

### Single Target Scan

To scan a single Keycloak instance:

