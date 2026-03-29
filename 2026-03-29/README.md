# Semaphore CI/CD Path Traversal Scanner (CVE-2026-49012)

This is a security scanner for detecting and exploiting the path traversal vulnerability in Semaphore CI/CD (CVE-2026-49012). The `/webhook/trigger` endpoint in Semaphore versions <= 3.5.2 fails to properly validate file paths, allowing attackers to request arbitrary files on the file system.

### Affected Versions

- Semaphore CI/CD server versions <= 3.5.2
- Fixed in Semaphore version 3.5.3

### Impact

This vulnerability allows unauthenticated attackers to access sensitive files on the file system, including `/etc/passwd`, SSH private keys, and deployment environment files.

### References

- [NVD CVE-2026-49012](https://nvd.nist.gov/vuln/detail/CVE-2026-49012)  
- [Semaphore Release Notes](https://docs.semaphoreci.com/releases/)  
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

## Usage

### Scan a single target
