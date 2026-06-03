# GitLab CI/CD YAML Configuration Injection Scanner

This tool scans GitLab instances to identify vulnerabilities related to YAML configuration injection in `.gitlab-ci.yml` files. Exploiting this vulnerability could allow remote code execution or unauthorized access to sensitive data in CI/CD pipelines.

## Features

- Detect GitLab instances and extract their version
- Determine whether the detected version is vulnerable
- Optional active probing to test YAML injection vulnerabilities (requires permissions)
- ANSI output for critical findings
- JSON export for findings

## Usage

### Scan a Single Target
