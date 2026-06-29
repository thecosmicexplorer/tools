# Jenkins Script Console Authentication Bypass Scanner (CVE-2023-27898)

This tool scans for publicly exposed Jenkins instances that are vulnerable to an authentication bypass in the Script Console endpoint caused by improper authorization checks. If an instance is vulnerable, an attacker could execute arbitrary Groovy scripts, leading to remote code execution.

## CVE-2023-27898 Summary

- **CVE ID**: CVE-2023-27898
- **Affected Versions**: Jenkins <= 2.389 and LTS <= 2.375.1
- **CVSS Score**: 9.8 (Critical)
- **Impact**: Allows unauthenticated remote attackers to execute arbitrary Groovy scripts via the `/script` endpoint.
- **Remediation**: Update Jenkins to the latest patched version.

## Usage

### Scan a single target (active probe)
