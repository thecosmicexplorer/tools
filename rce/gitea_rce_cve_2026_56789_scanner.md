# Gitea RCE CVE-2026-56789 Scanner

## Overview
This tool scans for Gitea instances (v1.14.0 to v1.17.5) vulnerable to an unauthenticated remote code execution (RCE) vulnerability via malicious hook injection (CVE-2026-56789, CVSS 9.8). Vulnerable Gitea installations allow attackers to inject arbitrary hooks during repository migrations, leading to arbitrary code execution with the privileges of the Gitea server.

## CVE Details

- **CVE ID**: [CVE-2026-56789](https://nvd.nist.gov/vuln/detail/CVE-2026-56789)
- **Description**: Improper validation of repository hooks in the migration feature of Gitea versions 1.14.0 to 1.17.5.
- **Severity**: Critical (CVSS 9.8)
- **Patched Versions**: Gitea >= 1.17.6
- **Disclosure Date**: TBD

## Usage

