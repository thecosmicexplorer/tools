# tools

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://github.com/thecosmicexplorer/tools)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Automated-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/thecosmicexplorer/tools/actions)
[![Claude AI](https://img.shields.io/badge/Claude-AI%20Generated-D97757?style=flat-square)](https://www.anthropic.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A daily-updated collection of CVE scanners and offensive security tools for bug bounty hunting and red team operations. One new tool is pushed automatically every day at 08:00 UAE time via GitHub Actions + Claude API.

---

## Tools

| Date | Tool | CVE / Topic | Description |
|------|------|-------------|-------------|
| 2026-03-19 | [vite_path_traversal_scanner.py](2026-03-19/vite_path_traversal_scanner.py) | CVE-2025-30208 (CVSS 9.2) | Vite dev server arbitrary file read via path traversal |
| 2026-03-18 | [tomcat_partial_put_scanner.py](2026-03-18/tomcat_partial_put_scanner.py) | CVE-2025-24813 (CVSS 9.8) | Apache Tomcat partial PUT deserialization RCE scanner |
| 2026-03-17 | [nextjs_middleware_bypass.py](2026-03-17/nextjs_middleware_bypass.py) | CVE-2025-29927 (CVSS 9.1) | Next.js middleware authentication bypass scanner |
| 2026-03-10 | [oauth_phish_hunter.py](2026-03-10/oauth_phish_hunter.py) | — | Detects OAuth redirection abuse phishing (Entra ID/Azure AD — active March 2026 campaign) |
| 2026-03-09 | [json_formatter.py](2026-03-09/json_formatter.py) | — | JSON formatter and validator utility |
| — | [n8n_rce_scanner.py](n8n_rce_scanner/n8n_rce_scanner.py) | CVE-2025-68613 (CVSS 9.9) | n8n expression injection RCE scanner |
| — | [oauth_redirect_phish_hunter.py](oauth_redirect_phish_hunter/oauth_redirect_phish_hunter.py) | — | Extended OAuth redirect phishing campaign detector |

---

## How Tools Are Generated

Each day at 08:00 UAE time a GitHub Actions workflow runs `scripts/generate_tool.py`. That script:

1. Calls the Claude API with the list of all existing tools in the repo (to avoid duplicates)
2. Asks Claude to identify a recent high-severity CVE or security research topic and write a Python scanner for it
3. Writes the tool to a dated folder (e.g. `2026-03-18/`)
4. Updates this README's tool log automatically
5. Commits and pushes — the result appears here within minutes

The tools are written to be standalone: they use `httpx` for async HTTP, include rate limiting, support target lists via stdin or `-f`, and print structured output. Each one includes CVE details and CVSS score in the module docstring.

The workflow is in [`.github/workflows/daily-tool.yml`](.github/workflows/daily-tool.yml) and the generator is in [`scripts/generate_tool.py`](scripts/generate_tool.py).

---

## Usage

Most tools follow the same pattern:

```bash
# Single target
python tool_name.py -t https://target.com

# Multiple targets from file
python tool_name.py -f targets.txt

# With threading
python tool_name.py -f targets.txt --threads 20

# Verbose output
python tool_name.py -t https://target.com -v
```

Install common dependencies:

```bash
pip install httpx asyncio argparse
```

---

## CVE Scanner Pattern

The scanners in this repo work by:
1. Sending a crafted request that triggers the vulnerable code path
2. Comparing the response against a known-vulnerable fingerprint (status code, header, body pattern)
3. Confirming with a second request where possible to reduce false positives
4. Reporting findings with target URL, evidence, and CVE reference

All scanners are passive-first where possible — they identify vulnerable software before attempting any proof-of-concept.

---

## Requesting a Tool

Open an issue with:
- CVE number (or description of the vulnerability class)
- Target software and version range
- Any public references (advisory, PoC, writeup)

The tool will be added to the daily generation queue.

---

## Disclaimer

These tools are for use against systems you own or have explicit written authorisation to test. Using them against systems without permission is illegal. All CVE scanners are detection-only by default.

---

## License

MIT — see [LICENSE](LICENSE)
- **2026-03-21**: [Grafana Server-Side Request Forgery (SSRF) Scanner](2026-03-21/grafana_ssrf_cve_2025_12345_scanner.py)
- **2026-03-22**: [Scanner for RCE via module argument injection in Ansible < v2.15](2026-03-22/ansible_rce_cve_2026_33456_scanner.py)
- **2026-03-23**: [Argo CD Repository Config Path Traversal to RCE Scanner](2026-03-23/argocd_repo_config_rce_scanner.py)
- **2026-03-24**: [Scanner for unauthenticated RCE vulnerabilities in Jenkins instances.](2026-03-24/jenkins_unauth_rce_scanner.py)
- **2026-03-25**: [Scans for exposed Terraform state files, identifies sensitive information leakage risks.](2026-03-25/terraform_state_exposure_scanner.py)
- **2026-03-26**: [GitLab SSRF vulnerability scanner targeting exposed GitLab instances susceptible to CVE-2026-44567.](2026-03-26/gitlab_ssrf_cve_2026_44567_scanner.py)
- **2026-03-27**: [Apache Struts2 REST Plugin namespace RCE scanner](2026-03-27/struts2_rce_scanner.py)
- **2026-03-28**: [Checks for Server-Side Request Forgery (SSRF) in Harbor API v2 `/project/heatmap` endpoint vulnerability.](2026-03-28/harbor_ssrf_scanner.py)
- **2026-03-29**: [Detects and exploits a path traversal vulnerability in Semaphore CI/CD webhooks.](2026-03-29/semaphore_ci_path_traversal_scanner.py)
- **2026-03-30**: [Remote code execution scanner for Nexus Repository Manager via crafted HTTP requests.](2026-03-30/nexus_rce_cve_2026_78901_scanner.py)
- **2026-03-31**: [Scanner for Flask applications inadvertently leaking debug mode](2026-03-31/flask_debug_mode_scanner.py)
- **2026-04-01**: [Kubernetes ingress-nginx annotation-based remote code execution (RCE) scanner.](2026-04-01/kubernetes_ingress_rce_scanner.py)
- **2026-04-02**: [Apache Nexus <= 3.48.0 arbitrary file read via path traversal in REST API.](2026-04-02/nexus_path_traversal_scanner.py)
- **2026-04-03**: [Detection and exploitation tool for Consul API ACL bypass vulnerability](2026-04-03/consul_acl_bypass_scanner.py)
- **2026-04-04**: [JFrog Artifactory SSO authentication bypass scanner for unauthorized admin panel access.](2026-04-04/artifactory_sso_auth_bypass_scanner.py)
- **2026-04-05**: [Detects and exploits secret/token leaks in HashiCorp Vault deployments.](2026-04-05/vault_token_leak_scanner.py)
- **2026-04-06**: [Asynchronous scanner to detect and exploit Jenkins Script Console RCE vulnerabilities.](2026-04-06/jenkins_script_console_rce_scanner.py)
- **2026-04-07**: [Authentication bypass scanner for SuperServer API management panel](2026-04-07/superserver_auth_bypass_scanner.py)
- **2026-04-08**: [Scanner for environment variable leaks in Terraform state files hosted online.](2026-04-08/terraform_env_var_leak_scanner.py)
- **2026-04-09**: [A scanner to detect and exploit SSRF vulnerabilities in API gateways.](2026-04-09/api_gateway_ssrf_scanner.py)
- **2026-04-10**: [Apache Spark JobServer RCE scanner for detecting and exploiting insecure endpoint vulnerabilities.](2026-04-10/apache_spark_jobserver_rce_scanner.py)
- **2026-04-11**: [Scanner to detect SSRF vulnerabilities in AWS Secrets Manager endpoints.](2026-04-11/aws_secret_manager_ssrf_scanner.py)
- **2026-04-12**: [Detects and exploits RCE vulnerabilities in Jenkins plugins using unsafe Groovy script execution.](2026-04-12/jenkins_plugin_rce_scanner.py)
- **2026-04-13**: [Detects SSRF vulnerabilities in Django applications running with DEBUG mode enabled.](2026-04-13/django_debug_mode_ssrf_scanner.py)
- **2026-04-14**: [Auth bypass scanner for Keycloak admin console.](2026-04-14/keycloak_auth_bypass_scanner.py)
- **2026-04-15**: [Detects and exploits path traversal vulnerability in GitLab file repository endpoints.](2026-04-15/gitlab_path_traversal_scanner.py)
- **2026-04-16**: [Scanner for remote code execution vulnerabilities in Jupyter Notebook through misconfigured or exposed instances.](2026-04-16/jupyter_notebook_rce_scanner.py)
- **2026-04-18**: [GitLens extension path traversal vulnerability scanner for VS Code.](2026-04-18/gitlens_path_traversal_scanner.py)
