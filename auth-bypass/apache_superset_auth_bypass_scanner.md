# Apache Superset Authentication Bypass Scanner (CVE-2023-27524)

## Overview
This tool checks for Apache Superset instances vulnerable to CVE-2023-27524, a critical authentication bypass vulnerability. The issue arises when the `SECRET_KEY` configuration value remains unchanged from its default, allowing attackers to forge authentication cookies and gain unauthorized access.

**CVE Details:**
  - **ID**: CVE-2023-27524
  - **Severity**: Critical (CVSS 9.8)
  - **Affected Versions**: Apache Superset < 2.1.1
  - **Patched Version**: Apache Superset 2.1.1
  - **Disclosed By**: Horizon.ai Security
  - Released: April 2023

## Features
- Detects Apache Superset instances through fingerprinting techniques.
- Extracts and verifies the version against patched versions.
- Actively probes for authentication bypass unless `--safe` is specified.
- Supports bulk scanning of multiple targets.
- Outputs findings in JSON format.

## Usage

