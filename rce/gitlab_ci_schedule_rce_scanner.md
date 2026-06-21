# GitLab CI Job Schedule RCE Scanner

This tool scans for GitLab instances that are vulnerable to remote code execution 
(RCE) attacks via manipulated GitLab CI/CD job schedules. It detects GitLab servers, 
extracts their version, and actively or passively evaluates their exposure to 
known and high-impact vulnerabilities. 

## Features
- Detects GitLab instances and extracts their version.
- Verifies if the detected version is vulnerable (based on known security advisories).
- Supports **active** exploitation attempts (configurable).
- Results are returned in color-coded terminal output and optionally saved as JSON.

## Vulnerability Details
Improperly secured GitLab CI/CD pipelines may expose functionality allowing remote 
code execution via maliciously manipulated CI/CD schedules or scripts. By leveraging 
unrestricted or unverified CI/CD schedules in GitLab projects, attackers can run 
arbitrary commands on backend systems leading to server compromise.

### Affected Versions 
Any GitLab version found lacking patched protection against this vulnerability. 
Please refer to GitLab's [security releases](https://gitlab.com/gitlab-org/gitlab/security-releases)
for more details.

## Installation
Ensure Python 3.10+ is installed, then install required dependencies:
