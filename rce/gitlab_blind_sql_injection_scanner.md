# GitLab GraphQL API Vulnerability Scanner (CVE-2026-48392)

## Overview
This tool scans GitLab instances for a critical **Blind SQL Injection** vulnerability (CVE-2026-48392) discovered in the GraphQL API (`projectPath` parameter). An attacker exploiting this flaw can potentially execute time-based SQL payloads, read sensitive information from the database, and pivot to further attacks.

The vulnerability affects GitLab versions **prior to 16.4.0**, identified by CVSS v3.1 with a base score of **9.1**.

## CVE Details
- **CVE ID**: [CVE-2026-48392](https://nvd.nist.gov/vuln/detail/CVE-2026-48392)
- **Affected Versions**: GitLab < 16.4.0
- **Patched Versions**: GitLab >= 16.4.0
- **Impact**: Blind SQL Injection via crafted GraphQL queries targeting `projectPath`.
- **CVSS Score**: 9.1 (Critical)
- **Disclosed**: May 2026.
- **References**:
  - https://gitlab.com/gitlab-org/gitlab/-/issues/xxxxxx
  - https://docs.gitlab.com/ee/security/show_all_versions.html
  - https://cwe.mitre.org/data/definitions/89.html

## Usage Examples

### Scan a single target (active probing mode):
