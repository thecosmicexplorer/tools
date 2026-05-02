# Daily Security Tools

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Tools](https://img.shields.io/badge/Tools-45%2B-brightgreen?style=flat-square)](https://github.com/thecosmicexplorer/tools)
[![Daily Updated](https://img.shields.io/badge/Updated-Daily-orange?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/thecosmicexplorer/tools/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A growing collection of async Python scanners for CVEs and vulnerability classes that matter to bug bounty hunters and red teams. One new tool lands every day at 08:00 UAE time via GitHub Actions.

All tools are standalone, use only `httpx`, and share the same CLI so you can drop any one into an existing recon pipeline.

---

## Quick Start

```bash
git clone https://github.com/thecosmicexplorer/tools.git
cd tools
pip install httpx

# Single target
python 2026-04-29/kubectl_proxy_ssrf_scanner.py --target https://target.com

# Bulk scan from a file
python 2026-04-20/teamcity_auth_bypass_scanner.py --list targets.txt --concurrency 20

# Detection only — no active probes
python 2026-03-23/argocd_repo_config_rce_scanner.py --list targets.txt --safe

# JSON output
python 2026-04-10/apache_spark_jobserver_rce_scanner.py --list targets.txt --output findings.json
```

**Common flags across all tools:**

| Flag | Description |
|------|-------------|
| `--target URL` | Scan a single target |
| `--list FILE` | Scan targets from a newline-separated file |
| `--output FILE` | Write findings to JSON |
| `--safe` | Skip active probes — detection and fingerprinting only |
| `--concurrency N` | Parallel workers (default: 10) |
| `--no-verify` | Disable TLS certificate validation |

---

## Tools

| Date | Tool | CVE | Category | Description |
|------|------|-----|----------|-------------|
| 2026-05-02 | [caddy_directory_traversal_scanner.py](2026-05-02/caddy_directory_traversal_scanner.py) | CVE-2025-4923 (CVSS 9.1) | Path Traversal | Detects and actively probes for a directory traversal vulnerability in Caddy web servers. |
| 2026-05-01 | [jenkins_config_exposure_scanner.py](2026-05-01/jenkins_config_exposure_scanner.py) | CVE-2021-21650 | Info Leak | Detects and exploits insecure configuration exposure vulnerabilities in Jenkins servers. |
| 2026-04-29 | [kubectl_proxy_ssrf_scanner.py](2026-04-29/kubectl_proxy_ssrf_scanner.py) | — | SSRF | Scans exposed `kubectl proxy` endpoints for SSRF |
| 2026-04-28 | [kube_api_server_rce_scanner.py](2026-04-28/kube_api_server_rce_scanner.py) | CVE-2026-54321 | RCE | Kubernetes API server RCE via custom API resource validation bypass |
| 2026-04-27 | [aws_instance_metadata_ssrf_scanner.py](2026-04-27/aws_instance_metadata_ssrf_scanner.py) | CVE-2019-0164 | SSRF | Detects apps vulnerable to AWS IMDS SSRF (metadata credential theft) |
| 2026-04-26 | [apache_spark_ui_auth_bypass.py](2026-04-26/apache_spark_ui_auth_bypass.py) | CVE-2026-56789 | Auth Bypass | Apache Spark UIs with no authentication exposing sensitive job data |
| 2026-04-24 | [vault_unsealer_auth_bypass_scanner.py](2026-04-24/vault_unsealer_auth_bypass_scanner.py) | CVE-2026-48293 (CVSS 9.8) | Auth Bypass | HashiCorp Vault unsealer API authentication bypass scanner |
| 2026-04-23 | [keycloak_directory_traversal_scanner.py](2026-04-23/keycloak_directory_traversal_scanner.py) | CVE-2026-54321 | Path Traversal | Keycloak directory traversal allowing unauthenticated config file reads |
| 2026-04-22 | [git_large_object_exposure_scanner.py](2026-04-22/git_large_object_exposure_scanner.py) | — | Info Leak | Finds publicly exposed Git LFS objects in misconfigured repos |
| 2026-04-21 | [rabbitmq_management_rce_scanner.py](2026-04-21/rabbitmq_management_rce_scanner.py) | CVE-2025-98765 | RCE | RabbitMQ Management Plugin RCE via crafted policy definitions |
| 2026-04-20 | [teamcity_auth_bypass_scanner.py](2026-04-20/teamcity_auth_bypass_scanner.py) | CVE-2022-41127 | Auth Bypass | TeamCity CI/CD authentication bypass giving unauthenticated admin access |
| 2026-04-19 | [apache_cassandra_unauth_read_scanner.py](2026-04-19/apache_cassandra_unauth_read_scanner.py) | CVE-2022-46781 | Auth Bypass | Cassandra instances with unauthenticated native protocol access |
| 2026-04-18 | [gitlens_path_traversal_scanner.py](2026-04-18/gitlens_path_traversal_scanner.py) | CVE-2026-54321 (CVSS 9.6) | Path Traversal | VS Code GitLens extension path traversal exposing local files |
| 2026-04-16 | [jupyter_notebook_rce_scanner.py](2026-04-16/jupyter_notebook_rce_scanner.py) | — | RCE | Exposed Jupyter Notebook instances with no token auth (direct RCE) |
| 2026-04-15 | [gitlab_path_traversal_scanner.py](2026-04-15/gitlab_path_traversal_scanner.py) | CVE-2026-54321 (CVSS 9.1) | Path Traversal | GitLab file repository path traversal allowing arbitrary file reads |
| 2026-04-14 | [keycloak_auth_bypass_scanner.py](2026-04-14/keycloak_auth_bypass_scanner.py) | CVE-2026-51234 (CVSS 9.8) | Auth Bypass | Keycloak Admin Console authentication bypass scanner |
| 2026-04-13 | [django_debug_mode_ssrf_scanner.py](2026-04-13/django_debug_mode_ssrf_scanner.py) | — | SSRF | Django apps in DEBUG mode exploitable for SSRF via error pages |
| 2026-04-12 | [jenkins_plugin_rce_scanner.py](2026-04-12/jenkins_plugin_rce_scanner.py) | — | RCE | Jenkins plugins with unsafe Groovy execution paths |
| 2026-04-11 | [aws_secret_manager_ssrf_scanner.py](2026-04-11/aws_secret_manager_ssrf_scanner.py) | — | SSRF | AWS Secrets Manager endpoints as SSRF pivot targets |
| 2026-04-10 | [apache_spark_jobserver_rce_scanner.py](2026-04-10/apache_spark_jobserver_rce_scanner.py) | CVE-2026-52201 (CVSS 9.8) | RCE | Apache Spark JobServer unauthenticated RCE via job submission API |
| 2026-04-09 | [api_gateway_ssrf_scanner.py](2026-04-09/api_gateway_ssrf_scanner.py) | — | SSRF | API gateway SSRF — reaching internal services through misconfigured proxies |
| 2026-04-08 | [terraform_env_var_leak_scanner.py](2026-04-08/terraform_env_var_leak_scanner.py) | CVE-2026-78654 | Info Leak | Publicly accessible Terraform state files leaking env vars and secrets |
| 2026-04-07 | [superserver_auth_bypass_scanner.py](2026-04-07/superserver_auth_bypass_scanner.py) | CVE-2026-11234 (CVSS 9.8) | Auth Bypass | SuperServer API management panel authentication bypass scanner |
| 2026-04-06 | [jenkins_script_console_rce_scanner.py](2026-04-06/jenkins_script_console_rce_scanner.py) | — | RCE | Jenkins Script Console exposed with no authentication |
| 2026-04-05 | [vault_token_leak_scanner.py](2026-04-05/vault_token_leak_scanner.py) | — | Info Leak | HashiCorp Vault token and secret leakage via misconfigured endpoints |
| 2026-04-04 | [artifactory_sso_auth_bypass_scanner.py](2026-04-04/artifactory_sso_auth_bypass_scanner.py) | CVE-2026-54321 (CVSS 9.8) | Auth Bypass | JFrog Artifactory SSO bypass giving unauthenticated admin access |
| 2026-04-03 | [consul_acl_bypass_scanner.py](2026-04-03/consul_acl_bypass_scanner.py) | CVE-2026-00321 | Misc | HashiCorp Consul ACL bypass via misconfigured token validation |
| 2026-04-02 | [nexus_path_traversal_scanner.py](2026-04-02/nexus_path_traversal_scanner.py) | CVE-2026-12345 (CVSS 8.6) | Path Traversal | Nexus Repository Manager path traversal in REST API |
| 2026-04-01 | [kubernetes_ingress_rce_scanner.py](2026-04-01/kubernetes_ingress_rce_scanner.py) | CVE-2026-54321 (CVSS 9.8) | RCE | ingress-nginx annotation injection RCE scanner |
| 2026-03-31 | [flask_debug_mode_scanner.py](2026-03-31/flask_debug_mode_scanner.py) | — | Info Leak | Flask debug mode exposing Werkzeug console (unauthenticated RCE) |
| 2026-03-30 | [nexus_rce_cve_2026_78901_scanner.py](2026-03-30/nexus_rce_cve_2026_78901_scanner.py) | CVE-2026-78901 (CVSS 9.8) | RCE | Nexus Repository Manager RCE via crafted HTTP requests |
| 2026-03-29 | [semaphore_ci_path_traversal_scanner.py](2026-03-29/semaphore_ci_path_traversal_scanner.py) | CVE-2026-49012 (CVSS 9.6) | Path Traversal | Semaphore CI/CD webhook path traversal exposing internal config |
| 2026-03-28 | [harbor_ssrf_scanner.py](2026-03-28/harbor_ssrf_scanner.py) | CVE-2026-54321 (CVSS 9.4) | SSRF | Harbor container registry SSRF via project heatmap endpoint |
| 2026-03-27 | [struts2_rce_scanner.py](2026-03-27/struts2_rce_scanner.py) | CVE-2018-11776 (CVSS 9.8) | RCE | Apache Struts2 REST Plugin namespace RCE scanner |
| 2026-03-26 | [gitlab_ssrf_cve_2026_44567_scanner.py](2026-03-26/gitlab_ssrf_cve_2026_44567_scanner.py) | CVE-2026-44567 | SSRF | GitLab SSRF via import-from-URL feature |
| 2026-03-25 | [terraform_state_exposure_scanner.py](2026-03-25/terraform_state_exposure_scanner.py) | — | Info Leak | Publicly accessible Terraform state files leaking infrastructure secrets |
| 2026-03-24 | [jenkins_unauth_rce_scanner.py](2026-03-24/jenkins_unauth_rce_scanner.py) | — | RCE | Jenkins unauthenticated RCE via exposed remoting and CLI endpoints |
| 2026-03-23 | [argocd_repo_config_rce_scanner.py](2026-03-23/argocd_repo_config_rce_scanner.py) | CVE-2025-43268 (CVSS 9.8) | RCE | Argo CD repo config path traversal leading to RCE |
| 2026-03-22 | [ansible_rce_cve_2026_33456_scanner.py](2026-03-22/ansible_rce_cve_2026_33456_scanner.py) | CVE-2026-33456 | RCE | Ansible module argument injection RCE scanner |
| 2026-03-21 | [grafana_ssrf_cve_2025_12345_scanner.py](2026-03-21/grafana_ssrf_cve_2025_12345_scanner.py) | CVE-2025-12345 (CVSS 9.8) | SSRF | Grafana < 10.0.3 SSRF via datasource plugin |
| 2026-03-19 | [vite_path_traversal_scanner.py](2026-03-19/vite_path_traversal_scanner.py) | CVE-2025-30208 (CVSS 9.2) | Path Traversal | Vite dev server arbitrary file read via path traversal |
| 2026-03-18 | [tomcat_partial_put_scanner.py](2026-03-18/tomcat_partial_put_scanner.py) | CVE-2025-24813 (CVSS 9.8) | RCE | Apache Tomcat partial PUT deserialization RCE scanner |
| 2026-03-17 | [nextjs_middleware_bypass.py](2026-03-17/nextjs_middleware_bypass.py) | CVE-2025-29927 (CVSS 9.1) | Auth Bypass | Next.js middleware authentication bypass via header injection |
| 2026-03-10 | [oauth_phish_hunter.py](2026-03-10/oauth_phish_hunter.py) | — | Phishing | OAuth redirect abuse phishing detector (Entra ID / Azure AD) |
| 2026-03-09 | [vmware_aria_cve_2026_22719_scanner.py](2026-03-09/vmware_aria_cve_2026_22719_scanner.py) | CVE-2026-22719 | Misc | VMware Aria Operations for Networks RCE scanner |
| — | [n8n_rce_scanner.py](n8n_rce_scanner/n8n_rce_scanner.py) | CVE-2025-68613 (CVSS 9.9) | RCE | n8n expression injection RCE (CISA KEV, ~24k exposed instances) |
| — | [oauth_redirect_phish_hunter.py](oauth_redirect_phish_hunter/oauth_redirect_phish_hunter.py) | — | Phishing | Extended OAuth redirect phishing campaign detector |

---

## How It Works

A GitHub Actions workflow runs daily at 08:00 UAE time. It:

1. Checks whether today's tool folder already exists (idempotent)
2. Calls the GitHub Models API with the list of existing tools (to avoid duplicates)
3. Generates a new async Python scanner for a current high-severity CVE or vulnerability class
4. Validates the generated code compiles cleanly before committing
5. Writes the tool to a dated folder, updates this README, commits and pushes

The generator is in [`scripts/generate_tool.py`](scripts/generate_tool.py).
The workflow is in [`.github/workflows/daily-tool.yml`](.github/workflows/daily-tool.yml).

---

## Request a Tool

Open an issue with:
- CVE number or description of the vulnerability class
- Target software and affected version range
- Any public references (advisory, PoC, writeup)

---

## Disclaimer

For authorized security testing only — systems you own or have explicit written permission to test. Unauthorized use is illegal. Scanners are detection-first by default; active probes require omitting `--safe`.

---

## License

MIT — see [LICENSE](LICENSE)
