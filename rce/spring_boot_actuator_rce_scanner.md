# Spring Boot Actuator RCE Scanner

This tool checks for exposed Spring Boot Actuator management endpoints, identifying potential vulnerabilities that could lead to remote code execution (RCE) or sensitive information disclosure. Exposed and misconfigured Actuator endpoints can be leveraged by attackers to manipulate application state or execute unauthorized operations.

## CVE Information

This tool checks for a general class of misconfiguration vulnerabilities affecting Spring Boot Actuator. Examples include:
- CVE-2018-1271 (Remote Code Execution via `/env` endpoint)
- CVE-2020-5421 (Actuator exposure with potential sensitive data leakage)

It scans for exposed `/actuator` endpoints, identifies the ones posing risks, and optionally probes dangerous endpoints for active exploitation.

## Features

- Detects Spring Boot applications and common Actuator endpoints.
- Identifies misconfigurations with dangerous endpoints like `/env` and `/restart`.
- Provides active probing with `safe` mode to ensure no disruptive actions are performed.
- Supports concurrent scanning of multiple targets.
- Outputs results in CLI or JSON format.

## How to Use

### Scan a single target
