# GitLab Path Traversal Scanner (CVE-2026-44567)

This Python script scans GitLab instances for a high-severity path traversal vulnerability (CVE-2026-44567). 

## Key Features:
- Detects GitLab instances and retrieves their version number.
- Compares the version against the patched version (16.7.0).
- Performs active probing for path traversal exploitation (disabled in `--safe` mode).
- Supports scanning multiple targets concurrently with configurable concurrency.
- Outputs results in JSON format for log retention and analysis.

## CVE Details:
- **CVE ID:** CVE-2026-44567
- **CVSS:** 9.1 (Critical)
- **Vulnerable versions:** GitLab `< 16.7.0`

## Installation:
Requires Python 3.10+. Install dependencies using:
