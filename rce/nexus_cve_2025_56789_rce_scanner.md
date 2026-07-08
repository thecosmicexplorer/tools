# Nexus Repository RCE Scanner (CVE-2025-56789)

This tool scans for Nexus Repository Manager instances vulnerable to an unauthenticated Remote Code Execution (RCE) vulnerability identified as `CVE-2025-56789`.

## Vulnerability Details

- **CVE ID**: CVE-2025-56789
- **CVSS Score**: 9.6 (Critical)
- **Affected Versions**: Nexus Repository Manager OSS/Pro < 3.45.1
- **Issue**: Improper input sanitization in the REST API allows attackers to inject and execute operating system commands.
- **Patched Version**: 3.45.1
- **References**:
  - [NVD Advisory](https://nvd.nist.gov/vuln/detail/CVE-2025-56789)
  - [Sonatype Advisory](https://support.sonatype.com/hc/en-us/articles/Nexus-Repository-Manager-3-x-Security-Advisory-2025-08)

## Usage Instructions

### Scan a Single Target
