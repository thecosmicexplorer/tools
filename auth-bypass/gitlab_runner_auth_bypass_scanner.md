# GitLab Runner Authentication Bypass Scanner (CVE-2026-78901)

This tool scans GitLab Runner instances for an authentication bypass vulnerability 
(CVE-2026-78901). It detects affected instances and optionally probes for active exploitation.

## CVE Details
- **CVE**: CVE-2026-78901
- **Impact**: Unauthorized access to GitLab Runner API endpoints, exposing sensitive CI/CD pipelines and tokens.
- **Affected Versions**: GitLab Runner `< 15.17.0`
- **Fixed in Version**: GitLab Runner `15.17.0`

## Requirements
- Python 3.10+
- `httpx` library (install via `pip install httpx`)

## Usage

### Scan a single target
