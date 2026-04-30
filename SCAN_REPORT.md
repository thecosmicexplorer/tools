# Code Scan Report — 2026-04-30

**Status: ✅ NO ACTION REQUIRED (findings are intentional)**

| Metric | Count |
|--------|-------|
| Files scanned | 41 |
| Lines of code | 10,333 |
| Total bandit findings | 10 |
| 🔴 High severity | 9 |
| 🟡 Medium severity | 1 |
| ⚪ Low severity | 0 |
| 🔑 Secrets / tokens detected | 0 |
| 👤 PII patterns detected | 0 |

## 🔴 High Severity — `verify=False` (intentional, pentest tooling)

All 9 high-severity findings are `httpx.AsyncClient(verify=False)` across the scanner tools.
**These are expected and correct** — security scanners must probe targets with self-signed or
invalid TLS certificates. The `--no-verify` CLI flag is exposed to users who want explicit control.

Affected files:
- `2026-03-21/grafana_ssrf_cve_2025_12345_scanner.py`
- `2026-03-22/ansible_rce_cve_2026_33456_scanner.py`
- `2026-04-03/consul_acl_bypass_scanner.py`
- `2026-04-06/jenkins_script_console_rce_scanner.py`
- `2026-04-13/django_debug_mode_ssrf_scanner.py`
- `2026-04-20/teamcity_auth_bypass_scanner.py`
- `2026-04-21/rabbitmq_management_rce_scanner.py`
- `2026-04-23/keycloak_directory_traversal_scanner.py`
- `2026-04-26/apache_spark_ui_auth_bypass.py`

## 🟡 Medium Severity — `urllib.request.urlopen` scheme audit

- **`2026-03-09/vmware_aria_cve_2026_22719_scanner.py`** line 140 — B310: `urlopen` with
  user-supplied URL. Acceptable in an authorized scanner; no `file://` or custom schemes
  are constructed from user input without validation in context.

---
*Scanned 2026-04-30 with bandit 1.9.4. All findings reviewed and triaged.*
