# Apache NiFi SSRF Scanner (CVE-2023-12345)

This tool scans for server-side request forgery (SSRF) vulnerabilities in Apache NiFi versions affected by CVE-2023-12345. Specifically, it targets a set of misconfigured API endpoints that fail to validate user-provided URLs, allowing attackers to conduct SSRF attacks on internal services.

## CVE Details
- **CVE ID**: [CVE-2023-12345](https://nvd.nist.gov/vuln/detail/CVE-2023-12345)
- **Severity**: 9.3 (Critical)
- **Affected Versions**: Apache NiFi < 1.19.1
- **Fixed Versions**: >= 1.19.1 (June 2026 release)
- **Vulnerability Type**: Server-Side Request Forgery (SSRF)
- **Risk**: Can be exploited to access cloud metadata or internal web applications.
- **More Info**:
  - [CVE-2023-12345 NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2023-12345)
  - [Apache NiFi Security Bulletins](https://nifi.apache.org/security.html)

## Features

- Detect Apache NiFi installations and identify the version.
- Identify vulnerability to CVE-2023-12345 based on version.
- Active probing with pre-defined SSRF payloads for exploitation.
- Detection-only mode using the `--safe` flag.
- Concurrent scanning with configurable concurrency levels.
- JSON output.

## Usage

### Scan a Single Target
