# n8n CVE-2025-68613 Expression Injection Scanner

Defensive scanner for **CVE-2025-68613** — an unauthenticated expression injection RCE in n8n workflow automation (CVSS 9.9, CISA KEV).

## What is CVE-2025-68613?

n8n versions **< 1.89.1** evaluate workflow expressions in unauthenticated `/webhook/` and `/webhook-test/` endpoints without proper sanitization. An attacker can inject `{{ <expression> }}` payloads that execute server-side, leading to full RCE without authentication.

- **CVSS Score:** 9.9 (Critical)
- **Affected versions:** n8n < 1.89.1
- **Fixed in:** n8n 1.89.1 (March 2025)
- **CISA KEV:** Yes — actively exploited
- **Exposure:** ~24,700 instances publicly accessible (Shodan, March 2025)

## Detection Capabilities

1. **Instance fingerprinting** — detects n8n by title, API responses, and UI markers
2. **Version extraction** — parses n8n version from API responses and HTML
3. **Vulnerability assessment** — flags instances running < 1.89.1
4. **Expression injection probe** — safe arithmetic probe (`{{ 1 + 1 }}`) confirms live injection without destructive payloads
5. **Unauthenticated API check** — detects exposed workflows, credentials, and execution history

## Usage

```bash
pip install httpx

# Scan a single target
python n8n_rce_scanner.py --target https://n8n.example.com

# Scan a list of targets
python n8n_rce_scanner.py --list targets.txt --output findings.json

# Detection only (no injection probes)
python n8n_rce_scanner.py --target https://n8n.example.com --safe

# Shodan-powered bulk scan
SHODAN_API_KEY=your_key python n8n_rce_scanner.py --shodan --output results.json
```

## Output Example

```
======================================================================
  n8n FOUND   : https://n8n.acme.com
  Version     : 1.87.2
  Risk        : CRITICAL
  [CRITICAL] Version 1.87.2 is below the patched version 1.89.1
  [HIGH] Unauthenticated access to workflow list at /rest/workflows (12 items)
  >>> VULNERABLE TO CVE-2025-68613 — PATCH IMMEDIATELY <<<
======================================================================
```

## Remediation

1. **Update n8n** to v1.89.1 or later immediately
2. **Restrict access** — place n8n behind a VPN or authentication proxy
3. **Disable public webhooks** if not required
4. **Audit execution logs** for unexpected expression evaluations

## Ethical Use

Only run against infrastructure you own or have written authorization to test. Use `--safe` mode when testing production systems to avoid any side effects from the injection probe.

## References

- [NVD CVE-2025-68613](https://nvd.nist.gov/vuln/detail/CVE-2025-68613)
- [n8n v1.89.1 Release Notes](https://docs.n8n.io/release-notes/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
