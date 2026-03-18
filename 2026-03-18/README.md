# Apache Tomcat CVE-2025-24813 — Partial PUT RCE Scanner

Async Python scanner that detects Apache Tomcat instances vulnerable to
**CVE-2025-24813** (CVSS **9.8**), a critical partial-PUT deserialization
remote code execution vulnerability disclosed in March 2025.

---

## The vulnerability

When the Tomcat `DefaultServlet` is configured with write access
(`readonly=false` in `conf/web.xml`), Tomcat stores the body of partial
`PUT` requests (those carrying a `Content-Range` header) as a temporary
file in the upload work directory.

An attacker can exploit this in two steps:

1. **Upload** a serialized Java payload via a partial `PUT` request.
   Tomcat saves it as a predictable temp file.
2. **Trigger** deserialization by issuing a `GET` request that maps to
   the temp file, causing Tomcat to deserialize the content and execute
   arbitrary code — **no authentication required**.

| Attribute | Value |
|-----------|-------|
| CVE | CVE-2025-24813 |
| CVSS | 9.8 Critical |
| Affected | Tomcat 9.0.0.M1–9.0.98, 10.1.0-M1–10.1.34, 11.0.0-M1–11.0.2 |
| Fixed | Tomcat 9.0.99, 10.1.35, 11.0.3 (2025-03-10) |
| KEV | Yes — CISA added March 2025 |

---

## Features

- **Async** — `httpx` + `asyncio`; scans hundreds of hosts concurrently
- **Fingerprinting** — detects Tomcat via page content, HTTP headers, error pages
- **Version extraction** — parses version from multiple locations; compares to patched releases
- **Partial PUT probe** — sends a harmless plaintext `Content-Range` PUT to confirm write access (skip with `--safe`)
- **Manager access check** — detects unauthenticated or default-credential access to the Tomcat Manager
- **ANSI colors** — `CRITICAL`=red, `HIGH`=yellow, `INFO`=green
- **JSON output** — machine-readable findings via `--output`

---

## Requirements

```
pip install httpx
```

Python 3.10+ required (uses `match`-compatible typing).

---

## Usage

```bash
# Scan a single target
python tomcat_partial_put_scanner.py --target https://tomcat.example.com

# Scan a list of targets, save JSON results
python tomcat_partial_put_scanner.py --list hosts.txt --output findings.json

# Detection only — no partial PUT probes sent
python tomcat_partial_put_scanner.py --list hosts.txt --safe

# High concurrency, ignore self-signed TLS certs
python tomcat_partial_put_scanner.py --list hosts.txt --concurrency 50 --no-verify

# Non-standard port
python tomcat_partial_put_scanner.py --target http://10.10.0.5:8080
```

### Options

| Flag | Description |
|------|-------------|
| `--target URL` | Scan a single target |
| `--list FILE` | File with one URL per line |
| `--output FILE` | Save findings to JSON |
| `--safe` | Skip active partial PUT probes |
| `--concurrency N` | Max concurrent requests (default: 30) |
| `--no-verify` | Disable TLS certificate verification |

---

## Output example

```
========================================================================
  TOMCAT FOUND  : https://tomcat.example.com
  Version       : 10.1.34
  Risk          : CRITICAL
  [CRITICAL] Version 10.1.34 is in vulnerable range 10.1.0–10.1.34. Patched version: 10.1.35.
  [CRITICAL] Tomcat accepted partial PUT (HTTP 201). DefaultServlet has write access — prerequisite for CVE-2025-24813 confirmed.
    Probe URL: https://tomcat.example.com/cve-2025-24813-probe-abc123.txt

  >>> WRITE ACCESS CONFIRMED — CVE-2025-24813 EXPLOITATION PREREQUISITE MET <<<
========================================================================
```

---

## Remediation

1. **Upgrade** to Tomcat 9.0.99, 10.1.35, or 11.0.3 or later.
2. **Disable DefaultServlet write access**: ensure `readonly=true` (the default) in `conf/web.xml`.
3. **Restrict the Manager app** with strong credentials and IP allowlisting.
4. **Apply WAF rules** to block `PUT` requests with `Content-Range` headers if patching is delayed.

---

## References

- [NVD — CVE-2025-24813](https://nvd.nist.gov/vuln/detail/CVE-2025-24813)
- [Apache Tomcat Security Advisory (10.x)](https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.35)
- [Apache announcement thread](https://lists.apache.org/thread/y6lzhnwy6nxcq174o1by4p0hxnfk4dr)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

---

> **Legal notice**: This tool is for authorised security testing and research
> only. Do not scan systems you do not own or have explicit written permission
> to test.
