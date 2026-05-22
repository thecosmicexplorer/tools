# nomad_rce_cve_2025_45678_scanner

## Overview

This scanner detects HashiCorp Nomad clusters vulnerable to the remote code execution (RCE) flaw identified as **CVE-2025-45678**. It can verify the vulnerability by actively probing for exploitable behavior.

## CVE Details

- **CVE ID:** CVE-2025-45678
- **CVSS v3.1 base score:** 9.8 (Critical)
- **Description:** An unauthenticated API allows remote code execution via malicious job submission.
- **Affected Versions:** Nomad <= 1.5.3
- **Patched Versions:** Nomad >= 1.5.4

## Usage Examples

