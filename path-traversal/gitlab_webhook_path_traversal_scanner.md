# GitLab Webhook Path Traversal Scanner (CVE-2026-98765)

This tool detects a path traversal vulnerability in GitLab webhook endpoints (CVE-2026-98765, CVSS 9.4). The issue allows attackers to exploit improperly sanitized paths to read sensitive files on the GitLab server. It can perform both detection and active probing to verify exploitability.

## Key Features

- Detects GitLab version and checks for the path traversal vulnerability.
- Supports detection-only mode (`--safe`) for passive use cases.
- Scans single targets or batch lists with configurable concurrency.
- Produces CLI and JSON output for easy integration into workflows.

## Affected Versions

- GitLab versions below 16.5.1 are vulnerable.
- Fixed in GitLab 16.5.1 (July 2026).

## Usage

### Scan a Single Target

