# GitLab GraphQL API RCE Scanner (CVE-2025-76543)

This tool scans for the critical Remote Code Execution (RCE) vulnerability in the GitLab GraphQL API (CVE-2025-76543, CVSS 9.8). This issue allows an unauthenticated attacker to execute arbitrary commands on a vulnerable GitLab server, potentially leading to full system compromise.

### Affected GitLab Versions

- GitLab CE/EE < `16.4.2` (versions `16.0.0` to `<16.4.2` specifically).

This tool detects the vulnerability, extracts GitLab version information from the server response, and optionally attempts an active exploitation to confirm the presence of the RCE.

## Prerequisites

- Python 3.10 or newer
- Install dependencies using `pip install -r requirements.txt`
  - `httpx`

## Usage

