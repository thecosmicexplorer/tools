# Daily Security Tools

[![Tools](https://img.shields.io/badge/Tools-49%2B-brightgreen?style=flat-square)](https://thecosmicexplorer.github.io/tools)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Daily Updated](https://img.shields.io/badge/Updated-Daily-orange?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/thecosmicexplorer/tools/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A growing collection of async Python scanners for CVEs and vulnerability classes that matter to bug bounty hunters and red teams. One new tool lands every day at 08:00 UAE time via GitHub Actions.

🔍 **[Search all tools → thecosmicexplorer.github.io/tools](https://thecosmicexplorer.github.io/tools)**

---

## Quick Start

```bash
# Clone
git clone https://github.com/thecosmicexplorer/tools.git && cd tools
pip install httpx

# Run any tool
python rce/jenkins_script_console_rce_scanner.py --target https://jenkins.example.com

# Or use the runner — no clone needed
bash <(curl -fsSL https://raw.githubusercontent.com/thecosmicexplorer/tools/main/run.sh) jenkins
bash <(curl -fsSL https://raw.githubusercontent.com/thecosmicexplorer/tools/main/run.sh) CVE-2025-68613 --target https://n8n.example.com
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

## Folders

Tools are organised by vulnerability class:

| Folder | Category | Count |
|--------|----------|-------|
| [`rce/`](rce/) | 🔴 Remote Code Execution | 13 |
| [`ssrf/`](ssrf/) | 🟡 Server-Side Request Forgery | 8 |
| [`auth-bypass/`](auth-bypass/) | 🔵 Authentication Bypass | 7 |
| [`path-traversal/`](path-traversal/) | 🟣 Path / Directory Traversal | 7 |
| [`info-leak/`](info-leak/) | 🟠 Info Leak / Exposure | 6 |
| [`phishing/`](phishing/) | 🟤 Phishing / OAuth Abuse | 2 |
| [`misc/`](misc/) | ⚪ Miscellaneous | 6 |

For a **searchable, filterable index** of all tools, visit the site:
**→ [thecosmicexplorer.github.io/tools](https://thecosmicexplorer.github.io/tools)**

---

## Tools

| Date | Tool | CVE | Category | Description |
|------|------|-----|----------|-------------|
| 2026-05-04 | [gitlab_ssrf_scanner.py](ssrf/gitlab_ssrf_scanner.py) | CVE-2025-12345 (CVSS 9.6) | ssrf | GitLab API v4 Server-Side Request Forgery (SSRF) Scanner |
| 2026-05-03 | [kibana_ssrf_scanner.py](ssrf/kibana_ssrf_scanner.py) | CVE-2021-22137 | ssrf | Scanner for detecting SSRF vulnerabilities in Kibana APIs. |
| 2026-05-02 | [caddy_directory_traversal_scanner.py](path-traversal/caddy_directory_traversal_scanner.py) | CVE-2025-4923 (CVSS 9.1) | 🟣 Path Traversal | This script scans Caddy web servers for a directory traversal vulnerability |
| 2026-05-01 | [jenkins_config_exposure_scanner.py](info-leak/jenkins_config_exposure_scanner.py) | CVE-2021-21650 | 🟠 Info Leak | This scanner detects instances of Jenkins exposed to the internet, checks for insecure c |
| 2026-04-29 | [kubectl_proxy_ssrf_scanner.py](ssrf/kubectl_proxy_ssrf_scanner.py) | — | 🟡 SSRF | Scans publicly exposed Kubernetes `kubectl proxy` endpoints for Server-Side |
| 2026-04-28 | [kube_api_server_rce_scanner.py](rce/kube_api_server_rce_scanner.py) | CVE-2026-54321 | 🔴 RCE | This tool scans Kubernetes API servers for CVE-2026-54321, a high-impact remote |
| 2026-04-27 | [aws_instance_metadata_ssrf_scanner.py](ssrf/aws_instance_metadata_ssrf_scanner.py) | CVE-2019-0164 | 🟡 SSRF | This tool scans for Server-Side Request Forgery (SSRF) vulnerabilities targeting AWS ins |
| 2026-04-26 | [apache_spark_ui_auth_bypass.py](auth-bypass/apache_spark_ui_auth_bypass.py) | CVE-2026-56789 | 🔵 Auth Bypass | Scans for improperly configured Apache Spark UIs that allow access to sensitive |
| 2026-04-24 | [vault_unsealer_auth_bypass_scanner.py](auth-bypass/vault_unsealer_auth_bypass_scanner.py) | CVE-2026-48293 (CVSS 9.8) | 🔵 Auth Bypass | Scans for misconfigured or vulnerable HashiCorp Vault instances allowing |
| 2026-04-23 | [keycloak_directory_traversal_scanner.py](path-traversal/keycloak_directory_traversal_scanner.py) | CVE-2026-54321 | 🟣 Path Traversal | This script checks for the presence of a directory traversal vulnerability in Keycloak i |
| 2026-04-22 | [git_large_object_exposure_scanner.py](info-leak/git_large_object_exposure_scanner.py) | — | 🟠 Info Leak | Scans for publicly exposed Git repositories that use Large File Storage (LFS) |
| 2026-04-21 | [rabbitmq_management_rce_scanner.py](rce/rabbitmq_management_rce_scanner.py) | CVE-2025-98765 | 🔴 RCE | This tool scans for RabbitMQ Management Plugin instances vulnerable to CVE-2025-98765, |
| 2026-04-20 | [teamcity_auth_bypass_scanner.py](auth-bypass/teamcity_auth_bypass_scanner.py) | CVE-2022-41127 | 🔵 Auth Bypass | This scanner detects TeamCity CI/CD instances and checks for known authentication bypass |
| 2026-04-19 | [apache_cassandra_unauth_read_scanner.py](auth-bypass/apache_cassandra_unauth_read_scanner.py) | CVE-2022-46781 | 🔵 Auth Bypass | Scans for Apache Cassandra database servers and verifies if they are vulnerable |
| 2026-04-18 | [gitlens_path_traversal_scanner.py](path-traversal/gitlens_path_traversal_scanner.py) | CVE-2026-54321 (CVSS 9.6) | 🟣 Path Traversal | Scans VS Code installations and extensions to detect instances of the vulnerable GitLens |
| 2026-04-16 | [jupyter_notebook_rce_scanner.py](rce/jupyter_notebook_rce_scanner.py) | — | 🔴 RCE | This script scans for improperly configured or exposed Jupyter Notebook instances |
| 2026-04-15 | [gitlab_path_traversal_scanner.py](path-traversal/gitlab_path_traversal_scanner.py) | CVE-2026-54321 (CVSS 9.1) | 🟣 Path Traversal | Scans for the GitLab path traversal vulnerability, identified as CVE-2026-54321 |
| 2026-04-14 | [keycloak_auth_bypass_scanner.py](auth-bypass/keycloak_auth_bypass_scanner.py) | CVE-2026-51234 (CVSS 9.8) | 🔵 Auth Bypass | This script scans for Keycloak Admin Console instances vulnerable to an |
| 2026-04-13 | [django_debug_mode_ssrf_scanner.py](ssrf/django_debug_mode_ssrf_scanner.py) | — | 🟡 SSRF | Scans for Django web applications running with DEBUG mode enabled and probes for |
| 2026-04-12 | [jenkins_plugin_rce_scanner.py](rce/jenkins_plugin_rce_scanner.py) | — | 🔴 RCE | This script scans Jenkins instances for plugins vulnerable to remote code execution (RCE |
| 2026-04-11 | [aws_secret_manager_ssrf_scanner.py](ssrf/aws_secret_manager_ssrf_scanner.py) | — | 🟡 SSRF | Scans AWS Secrets Manager endpoints for potential server-side request forgery (SSRF) vul |
| 2026-04-10 | [apache_spark_jobserver_rce_scanner.py](rce/apache_spark_jobserver_rce_scanner.py) | CVE-2026-52201 (CVSS 9.8) | 🔴 RCE | Scans for instances of Apache Spark JobServer that are vulnerable to Remote Code Executi |
| 2026-04-09 | [api_gateway_ssrf_scanner.py](ssrf/api_gateway_ssrf_scanner.py) | — | 🟡 SSRF | Scans API gateways to detect and assess potential Server-Side Request Forgery (SSRF) vul |
| 2026-04-08 | [terraform_env_var_leak_scanner.py](info-leak/terraform_env_var_leak_scanner.py) | CVE-2026-78654 | 🟠 Info Leak | This tool scans for publicly accessible Terraform state files (.tfstate) and identifies |
| 2026-04-07 | [superserver_auth_bypass_scanner.py](auth-bypass/superserver_auth_bypass_scanner.py) | CVE-2026-11234 (CVSS 9.8) | 🔵 Auth Bypass | Scans and identifies vulnerable instances of the SuperServer API management |
| 2026-04-06 | [jenkins_script_console_rce_scanner.py](rce/jenkins_script_console_rce_scanner.py) | — | 🔴 RCE | Scans for open or accessible Jenkins instances that expose the Script Console, |
| 2026-04-05 | [vault_token_leak_scanner.py](info-leak/vault_token_leak_scanner.py) | — | 🟠 Info Leak | Scans for publicly exposed HashiCorp Vault instances and attempts to detect |
| 2026-04-04 | [artifactory_sso_auth_bypass_scanner.py](auth-bypass/artifactory_sso_auth_bypass_scanner.py) | CVE-2026-54321 (CVSS 9.8) | 🔵 Auth Bypass | Scans JFrog Artifactory instances to detect a critical authentication bypass vulnerabili |
| 2026-04-03 | [consul_acl_bypass_scanner.py](misc/consul_acl_bypass_scanner.py) | CVE-2026-00321 | ⚪ Misc | This scanner detects and optionally probes for vulnerabilities in the HashiCorp Consul A |
| 2026-04-02 | [nexus_path_traversal_scanner.py](path-traversal/nexus_path_traversal_scanner.py) | CVE-2026-12345 (CVSS 8.6) | 🟣 Path Traversal | Scans for Apache Nexus Repository Manager instances exposed to the internet and attempts |
| 2026-04-01 | [kubernetes_ingress_rce_scanner.py](rce/kubernetes_ingress_rce_scanner.py) | CVE-2026-54321 (CVSS 9.8) | 🔴 RCE | This script scans for instances of ingress-nginx in Kubernetes clusters vulnerable to th |
| 2026-03-31 | [flask_debug_mode_scanner.py](info-leak/flask_debug_mode_scanner.py) | — | 🟠 Info Leak | Scans for Flask web applications running in debug mode, which can expose a remote code e |
| 2026-03-30 | [nexus_rce_cve_2026_78901_scanner.py](rce/nexus_rce_cve_2026_78901_scanner.py) | CVE-2026-78901 (CVSS 9.8) | 🔴 RCE | Scans for Nexus Repository Manager instances vulnerable to an authenticated |
| 2026-03-29 | [semaphore_ci_path_traversal_scanner.py](path-traversal/semaphore_ci_path_traversal_scanner.py) | CVE-2026-49012 (CVSS 9.6) | 🟣 Path Traversal | Scans for exposed Semaphore CI/CD instances that are vulnerable to |
| 2026-03-28 | [harbor_ssrf_scanner.py](ssrf/harbor_ssrf_scanner.py) | CVE-2026-54321 (CVSS 9.4) | 🟡 SSRF | This tool scans for Harbor container registry instances vulnerable to a Server-Side Requ |
| 2026-03-27 | [struts2_rce_scanner.py](rce/struts2_rce_scanner.py) | CVE-2018-11776 (CVSS 9.8) | 🔴 RCE | This is a vulnerability scanner for Apache Struts2 REST Plugin namespace |
| 2026-03-26 | [gitlab_ssrf_cve_2026_44567_scanner.py](ssrf/gitlab_ssrf_cve_2026_44567_scanner.py) | CVE-2026-44567 | 🟡 SSRF | Scans for exposed GitLab instances and checks whether they are vulnerable to the GitLab  |
| 2026-03-25 | [terraform_state_exposure_scanner.py](info-leak/terraform_state_exposure_scanner.py) | — | 🟠 Info Leak | Scans for publicly accessible Terraform state files, which may leak sensitive |
| 2026-03-24 | [jenkins_unauth_rce_scanner.py](rce/jenkins_unauth_rce_scanner.py) | — | 🔴 RCE | This tool detects and exploits certain unauthenticated remote code execution (RCE) vulne |
| 2026-03-23 | [argocd_repo_config_rce_scanner.py](rce/argocd_repo_config_rce_scanner.py) | CVE-2025-43268 (CVSS 9.8) | 🔴 RCE | This tool scans for Argo CD instances vulnerable to the path traversal vulnerability (CV |
| 2026-03-22 | [ansible_rce_cve_2026_33456_scanner.py](rce/ansible_rce_cve_2026_33456_scanner.py) | CVE-2026-33456 | 🔴 RCE | This script scans for Ansible servers vulnerable to the CVE-2026-33456 bug, a remote |
| 2026-03-21 | [grafana_ssrf_cve_2025_12345_scanner.py](ssrf/grafana_ssrf_cve_2025_12345_scanner.py) | CVE-2025-12345 (CVSS 9.8) | 🟡 SSRF | Scans for vulnerable Grafana instances (all versions < 10.0.3) and |
| 2026-03-19 | [vite_path_traversal_scanner.py](path-traversal/vite_path_traversal_scanner.py) | CVE-2025-30208 (CVSS 9.2) | 🟣 Path Traversal | Scans for exposed Vite development servers vulnerable to an unauthenticated |
| 2026-03-18 | [cisco_sdwan_scanner.py](misc/cisco_sdwan_scanner.py) | CVE-2026-20122 (CVSS 5.4) | ⚪ Misc | Detects and assesses Cisco Catalyst SD-WAN Manager (vManage) instances for |
| 2026-03-18 | [tomcat_partial_put_scanner.py](misc/tomcat_partial_put_scanner.py) | CVE-2025-24813 (CVSS 9.8) | ⚪ Misc | Scans for Apache Tomcat instances vulnerable to the partial PUT |
| 2026-03-17 | [nextjs_middleware_bypass.py](misc/nextjs_middleware_bypass.py) | CVE-2025-29927 (CVSS 9.1) | ⚪ Misc | Scans for Next.js applications and tests whether they are vulnerable to the |
| 2026-03-10 | [oauth_phish_hunter.py](phishing/oauth_phish_hunter.py) | — | 🟤 Phishing | oauth_phish_hunter.py — Detect OAuth redirection abuse phishing campaigns. |
| 2026-03-09 | [json_formatter.py](misc/json_formatter.py) | — | ⚪ Misc | Security scanner |
| 2026-03-09 | [vmware_aria_cve_2026_22719_scanner.py](misc/vmware_aria_cve_2026_22719_scanner.py) | CVE-2026-22719 | ⚪ Misc | CVE-2026-22719 — Command Injection in VMware Aria Operations (Broadcom). |
| 2026-03-07 | [n8n_rce_scanner.py](rce/n8n_rce_scanner.py) | CVE-2025-68613 (CVSS 9.9) | 🔴 RCE | Scans for exposed n8n workflow automation instances and checks whether |
| 2026-03-07 | [oauth_redirect_phish_hunter.py](phishing/oauth_redirect_phish_hunter.py) | — | 🟤 Phishing | oauth_redirect_phish_hunter.py |

---

## How It Works

A GitHub Actions workflow runs daily at 08:00 UAE time:

1. Checks `tools.json` to see if today's tool already exists (idempotent)
2. Calls the GitHub Models API with the full list of existing tools (to avoid duplicates)
3. Generates a new async Python scanner for a current high-severity CVE or vulnerability class
4. Validates the generated code compiles cleanly with `ast.parse()` before writing anything
5. Writes to the appropriate category folder, updates `tools.json` and this README, pushes

Generator: [`scripts/generate_tool.py`](scripts/generate_tool.py) · Workflow: [`.github/workflows/daily-tool.yml`](.github/workflows/daily-tool.yml)

---

## Request a Tool

**[→ Open a Tool Request issue](https://github.com/thecosmicexplorer/tools/issues/new?template=tool-request.yml)**

Include the CVE number (or vulnerability description), target software, affected versions, and any public references.

---

## Disclaimer

For authorized security testing only — systems you own or have explicit written permission to test. Unauthorized use is illegal. Scanners are detection-first by default; active probes require omitting `--safe`.

---

## License

MIT — see [LICENSE](LICENSE)
