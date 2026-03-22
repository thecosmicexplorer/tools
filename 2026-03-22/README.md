# Ansible CVE-2026-33456 RCE Scanner

This tool scans for Ansible servers vulnerable to a critical remote code execution (RCE) vulnerability described in CVE-2026-33456. This vulnerability is caused by improper sanitization in adhoc tasks, which allows attackers to exploit the task arguments to inject shell commands. Ansible versions prior to 2.15 are affected.

## CVE Details
- **CVE ID**: CVE-2026-33456
- **CVSS Score**: 10.0 (Critical)
- **Affected Versions**: Ansible < 2.15.0
- **Patched Version**: 2.15.0
- **Vulnerability Type**: Remote Code Execution (RCE)

## Features
- Detects Ansible instances based on fingerprints.
- Extracts and parses the Ansible version to check for vulnerable versions.
- Offers safe mode (--safe) to skip active probing and perform detection only.
- Allows active exploitation testing using a benign, non-destructive RCE payload.
- Outputs results in human-readable terminal format with color-coded severity.
- Exports results to JSON using the `--output` argument.

## Installation
1. Clone the repository:
   