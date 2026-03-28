# Harbor API v2 SSRF Scanner (CVE-2026-54321)

This tool scans for instances of the Harbor container registry vulnerable to a Server-Side Request Forgery (SSRF) vulnerability in the API v2 `/project/heatmap` endpoint (CVE-2026-54321). Harbor is commonly used in CI/CD pipelines, and exploitation of this SSRF bug can lead to significant information disclosure and lateral movement opportunities.

## Key Information
- **CVE:** [CVE-2026-54321](https://nvd.nist.gov/vuln/detail/CVE-2026-54321)
- **Vulnerability:** SSRF in `/project/heatmap` endpoint allows unauthorized requests to internal/private resources.
- **Affected Versions:** Harbor < 2.8.1
- **Fixed Version:** Harbor 2.8.1 (March 2026)
- **CVSS Score:** 9.4 (Critical)

## Usage
To use this tool, run the script with the appropriate arguments as shown below.

### Examples
1. **Scan a single target:**
   