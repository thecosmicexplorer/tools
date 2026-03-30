# Nexus Repository Manager RCE Scanner (CVE-2026-78901)

This script scans for instances of Nexus Repository Manager that are vulnerable
to the recently disclosed Remote Code Execution (RCE) vulnerability (CVE-2026-78901, CVSS 9.8).

## Summary

On supported versions of Nexus Repository Manager OSS/Pro (prior to v3.44.0), an attacker with 
valid credentials can exploit a command injection vulnerability in the Repository API. This 
vulnerability allows executing arbitrary commands on the server, potentially leading to full system
compromise. This vulnerability is highly critical due to the extensive use of Nexus in enterprise 
package management and its placement in the CI/CD pipelines.

### Affected Versions
- Nexus Repository Manager OSS/Pro versions below **3.44.0**

### Fixed Versions
- Nexus Repository Manager OSS/Pro starting from **3.44.0**

---

## Usage

This tool relies on a valid username and password of a Nexus Repository Manager user to exploit CVE-2026-78901.

