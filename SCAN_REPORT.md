# Code Scan Report — 2026-03-12

**Status: 🔴 ACTION REQUIRED**

| Metric | Count |
|--------|-------|
| Files scanned | 5 |
| Total issues  | 2 |
| 🔴 High severity vulnerabilities | 1 |
| 🟡 Medium severity vulnerabilities | 1 |
| ⚪ Low severity vulnerabilities | 0 |
| 🔑 Secrets / tokens detected | 0 |
| 👤 PII patterns detected | 0 |

## 🔴 High Severity Vulnerabilities (fix immediately)

- **n8n_rce_scanner/n8n_rce_scanner.py** line 419 — `B501`: Call to httpx with verify=False disabling SSL certificate checks, security issue. *(confidence: HIGH)*

## 🟡 Medium Severity Vulnerabilities

- **2026-03-09/vmware_aria_cve_2026_22719_scanner.py** line 140 — `B310`: Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.

---
*Scanned by automated pipeline on 2026-03-12. Powered by [bandit](https://bandit.readthedocs.io) + custom regex checks.*