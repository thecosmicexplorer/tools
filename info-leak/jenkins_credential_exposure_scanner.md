# Jenkins Credential Exposure Scanner

## Overview
The Jenkins Credential Exposure Scanner identifies exposed Jenkins credentials due to misconfiguration or plugin vulnerabilities. Jenkins, a popular CI/CD tool, can leak sensitive information if improperly secured.

## Affected Vulnerabilities and Scenarios
- **CVE-2020-2100:** Incorrect API access controls allow unauthorized actions.
- **CVE-2022-XXXX:** Credentials in insecure `config.xml`.
- Incorrect ACL settings exposing sensitive administrative resources.

## Features
- Detect and fingerprint Jenkins instances.
- Extract Jenkins version and assess its vulnerability.
- Probe potential credential exposure URLs if `--safe` is not provided.
- Concurrent target scanning.
- JSON output support for easy parsing and integration.

## Example Usage
- Scan a single Jenkins target:
  