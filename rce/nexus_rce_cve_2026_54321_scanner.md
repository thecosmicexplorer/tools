# Nexus Repository Manager CVE-2026-54321 Scanner

## Overview
This tool scans for a critical remote code execution (RCE) vulnerability in Nexus Repository Manager (CVE-2026-54321). This vulnerability arises due to improper input validation in repository configuration APIs and allows remote attackers to execute arbitrary code without authentication.

## CVE-2026-54321 Details
- **Vulnerability**: Remote Code Execution (RCE)
- **Affected Versions**: Nexus Repository Manager versions prior to 3.44.0
- **CVSS Score**: 9.8 (Critical)
- **Exploitation**: The vulnerability can be triggered by sending a crafted payload to specific endpoints.
- **Recommendation**: Update to the latest version of Nexus Repository Manager (3.44.0 or later).

## Features
- Fingerprints Nexus Repository Manager using a specific identifier.
- Detects the presence of the RCE vulnerability.
- Active RCE probing with an optional `--safe` flag for detection-only scans.
- Supports scanning single or multiple targets.
- Outputs results in JSON format for further analysis.

## Usage

### Prerequisites
Ensure you have Python 3.10+ and the `httpx` library installed:
