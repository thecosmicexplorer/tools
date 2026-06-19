# Apache OpenMeetings CVE-2025-67890 RCE Scanner

This tool scans for Apache OpenMeetings instances vulnerable to remote code execution (RCE) due to an insecure endpoint, as described in [CVE-2025-67890](https://nvd.nist.gov/vuln/detail/CVE-2025-67890).

## Vulnerability Details

- **CVE ID:** CVE-2025-67890
- **Severity:** 9.8 (Critical)
- **Affected Versions:** Apache OpenMeetings ≤ 7.0.5
- **Description:** An API gateway endpoint (`/services/EndpointManager`) in vulnerable versions allows unauthenticated attackers to execute arbitrary commands.
- **Patch:** Fixed in version 7.0.6 (April 2025).

## Usage Examples

