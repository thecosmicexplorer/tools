# Apache Druid SSRF Scanner (CVE-2026-45123)

## Overview
The `apache_druid_ssrf_scanner.py` tool detects and actively probes Apache Druid instances for 
a critical Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-45123). This issue is caused 
by a flaw in the HTTP endpoint routing mechanism of Druid's Router, enabling unauthenticated attackers 
to craft requests redirecting the Druid server to arbitrary URLs or internal endpoints.

**Vulnerability details**:
- **CVE**: [CVE-2026-45123](https://nvd.nist.gov/vuln/detail/CVE-2026-45123)
- **CVSS**: 9.8 (Critical)
- **Affected Versions**: Apache Druid < 27.0.0
- **Patched Versions**: 27.0.0 or higher

## Features
- Detect exposed Apache Druid instances
- Extract their version numbers
- Automatically identify vulnerability status (patched or unpatched)
- Probe potentially vulnerable instances with SSRF payloads (or skip probes in `--safe` mode)
- Simultaneous scanning for multiple hosts using concurrency settings
- JSON output format for reporting scan results

## Installation
1. Ensure Python 3.10+ is installed.
2. Install required dependencies:
   