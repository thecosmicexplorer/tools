# Jenkins Credential Exposure Scanner

This tool scans Jenkins instances to detect insecure exposure of sensitive credentials in configuration files due to misconfigurations or insecure file permissions.

## Vulnerability Overview

Jenkins' configuration files may sometimes expose sensitive credentials if the system permissions or web access controls have not been properly secured. Attackers can exploit such vulnerabilities to gain unauthorized access to Jenkins pipelines or other connected systems.

### Key Risks:
- Unauthorized access to critical systems.
- Compromised sensitive credentials (e.g., database passwords, API tokens).
- Potential network compromise or privilege escalation.

## Features
- Detects Jenkins instances by querying known endpoints.
- Actively checks for exposed credential configuration files, except in `--safe` mode.
- JSON output for easy log parsing.
- SSL/TLS verification options via `--no-verify`.

## Installation and Usage

### Prerequisites
- Python 3.10+
- Required Python libraries:
  - `httpx`
  - `colorama`

To install dependencies:

