# Azure DevOps Server SSRF Scanner

## Overview

This security scanner detects Server-Side Request Forgery (SSRF) vulnerabilities in Azure DevOps Server. An attacker exploiting these vulnerabilities can manipulate server outbound HTTP requests to access sensitive internal resources or launch further attacks.

## Features

- Identifies Azure DevOps Server instances.
- Extracts version information and checks for vulnerable versions.
- Active SSRF probes to detect exploitation potential (unless `--safe` mode is enabled).
- Supports concurrent scanning and JSON output for report generation.

## CVE Coverage

This scanner covers multiple SSRF vulnerabilities reported under Azure DevOps bug bounty programs. Ensure targets are patched against known issues.

## Usage Examples

### Scan a Single Target
