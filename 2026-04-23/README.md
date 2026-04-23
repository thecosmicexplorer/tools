# Keycloak Directory Traversal Scanner

## Overview

This tool scans for a directory traversal vulnerability (CVE-2026-54321) in Keycloak instances. The vulnerability affects Keycloak versions below 21.0.0 and allows attackers to access arbitrary files on the server's filesystem by abusing a crafted endpoint. This vulnerability poses a significant risk as it can disclose sensitive information such as configuration files and credentials.

## Features

- Detects Keycloak instances.
- Extracts the version of Keycloak to determine if it is vulnerable.
- Actively probes for directory traversal vulnerability (unless `--safe` is specified).
- Supports scanning a single target or a list of targets.
- Outputs results in JSON format for further analysis.

## CVE-2026-54321 Details

- **Description**: Directory traversal in `/realms/master/protocol/openid-connect/token/.%2F..` allows unauthorized access to arbitrary system files.
- **Affected Versions**: Keycloak < 21.0.0
- **Fixed Version**: 21.0.0
- **Impact**: High (exposure of sensitive files)
- **NIST CVSS Score**: 9.1

## Usage

### Scan a Single Target

