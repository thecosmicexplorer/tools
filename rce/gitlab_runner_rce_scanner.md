# GitLab Runner CVE-2021-22205 Scanner

## Overview
This is a vulnerability scanner to detect and optionally exploit the GitLab Runner RCE vulnerability (CVE-2021-22205). This critical vulnerability arises due to improper validation of image files, allowing unauthenticated remote attackers to execute arbitrary commands. This tool helps bug bounty hunters and red team operators identify this particular vulnerability in their target environments.

## CVE Information
- **CVE**: [CVE-2021-22205](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22205)
- **Severity**: Critical (CVSS: 10.0)
- **Summary**: Improper validation of user-supplied image files allows unauthenticated remote attackers to execute arbitrary commands via a maliciously crafted payload.
- **Affected Versions**: 
  - GitLab CE/EE < 13.10.3 
  - GitLab CE/EE < 13.9.6
  - GitLab CE/EE < 13.8.8
  
## Features
1. Fingerprints target applications to ensure they are running GitLab.
2. Detects and validates if the target version is vulnerable.
3. Optionally attempts active remote code execution for validation (requires user consent).

## Installation
1. Install Python 3.10+.
2. Install dependencies:
   