# Argo CD Repository Configuration Path Traversal to RCE Scanner

This tool scans for Argo CD instances vulnerable to the path traversal vulnerability (CVE-2025-43268), 
which can lead to unauthenticated remote code execution (RCE). The scanner detects vulnerable versions 
and optionally attempts active probes for verification.

## CVE-2025-43268 Details

- Affects: Argo CD < v2.8.2
- Vulnerability: Improper sanitization in repository configuration processing allows attackers to perform path traversal, accessing sensitive files (e.g., `/etc/passwd`) and performing unauthorized deployments.
- Fixed in: Argo CD v2.8.2

### Usage

