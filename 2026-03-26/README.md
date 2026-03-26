# GitLab CVE-2026-44567 SSRF Scanner

This tool scans for GitLab instances vulnerable to an SSRF vulnerability that allows unauthenticated adversaries to perform server-side request forgery (SSRF) via file upload endpoints (CVE-2026-44567).

## CVE Details

- **CVE**: [CVE-2026-44567](https://nvd.nist.gov/vuln/detail/CVE-2026-44567)
- **Description**: A security flaw in GitLab CE/EE versions before 16.7.5 allows an unauthenticated attacker to craft a specially crafted file upload request to access internal resources, potentially exposing sensitive data.
- **Impact**: Server-Side Request Forgery (SSRF)
- **Patched in Version**: GitLab CE/EE 16.7.5 (March 2026)

## Usage

### Scan a single GitLab instance:

