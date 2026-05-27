# Gitea Path Traversal Scanner (CVE-2026-12345)

This tool scans for instances of the Gitea development platform vulnerable to an unauthenticated path traversal vulnerability. Identified as CVE-2026-12345 (CVSS 9.1), this flaw allows remote attackers to read arbitrary files from the target server, potentially exposing sensitive information such as SSH keys or environment configuration.

## Features
- **Detection**: Identifies Gitea instances and extracts their versions.
- **Version Check**: Compares detected versions with patched version thresholds.
- **Active Probing**: Tests for file exposure using crafted path traversal payloads (disabled in safe mode).
- **JSON Output**: Saves scan results for post-processing.

## CVE Details
- **Impact**: Critical (CVSS 9.1)
- **Patched in**: Gitea 1.20.5
- **References**:
  - [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-12345)
  - [Gitea Advisory](https://github.com/go-gitea/gitea/security/advisories/GHSA-xyzq-asdf-zm12)

## Usage

### Single Host Scan
