# Jira User Enumeration Scanner

This tool identifies Jira instances exposed online and checks for user enumeration vulnerabilities via specific REST API endpoints. These vulnerabilities can allow attackers to enumerate user accounts, potentially leading to social engineering, brute force attacks, or further exploitation.

## Features

- Detects Jira instances by scanning for well-known API endpoints and markers.
- Optionally enumerates user accounts by exploiting vulnerable API queries.
- Supports JSON output for integration into your workflows.
- Provides CLI options for target URL, file-based scanning, concurrency settings, and skipping active probes.

## CVE Details

- **Vulnerability Class**: User Enumeration
- **CVE(s)**: MULTI (various Jira vulnerabilities)
- **CWEs**: CWE-200 (Information Exposure)
- **CVSS**: 5.3–6.8, depending on specific Jira version and configuration

## Usage

