# Apache Nexus CVE-2026-12345 Path Traversal Scanner

This tool scans for exposed Apache Nexus Repository Manager instances and detects whether they are vulnerable to an **unauthenticated path traversal vulnerability** (CVE-2026-12345). The vulnerability allows attackers to read arbitrary files on the underlying server, including sensitive configuration and authentication files.

---

## CVE-2026-12345: Details
- **Vulnerability:** Path Traversal in REST API
- **Affected Software:** Apache Nexus Repository Manager <= 3.48.0
- **Fixed Version:** 3.48.1 (March 2026)
- **CVSS Score:** 8.6 (High)
- **Impact:** Arbitrary file read
- **Exploitation:** Unauthenticated

---

## Usage

### Scan a Single Target
