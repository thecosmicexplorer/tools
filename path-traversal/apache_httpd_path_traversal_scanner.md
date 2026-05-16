# Apache HTTP Server Path Traversal Scanner (CVE-2024-20145)

This tool scans for instances of Apache HTTP Server vulnerable to the path traversal vulnerability identified as CVE-2024-20145.

## Vulnerability Overview

CVE-2024-20145 is a path traversal vulnerability affecting the `mod_proxy` module in Apache HTTP Server versions below 2.4.60. Under specific configurations that leverage `ProxyPassMatch` or RewriteRules with a `proxy:` URL scheme, it's possible for an attacker to craft malicious requests and exploit path traversal to access sensitive host files like `/etc/passwd` or configuration files.

### Key Details:
- **Vulnerable software:** Apache HTTP Server < 2.4.60 with specific configured rules.
- **Impact:** High confidentiality impact.
- **Patch version:** Fixed in Apache HTTP Server 2.4.60 (May 2024).
- [CVE-2024-20145 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-20145)
- [Apache Security Advisory](https://httpd.apache.org/security/vulnerabilities_2.4.html#CVE-2024-20145)

## Features

- Detects whether a server is running Apache HTTP Server.
- Identifies versions vulnerable to CVE-2024-20145.
- Actively probes for path traversal vulnerability (can be disabled with `--safe`).

## Usage

### Example Commands

Scan a single target:
