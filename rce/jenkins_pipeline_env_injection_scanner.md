# Jenkins Pipeline Environment Variable Injection Scanner

## Overview

This scanner detects and tests for environment variable injection vulnerabilities in Jenkins Pipeline configurations. Detectable and exploitable injections may allow attackers to execute malicious code during job runtime or expose sensitive information stored in environment variables.

## Vulnerability Details

- **Category**: Environment Variable Injection / RCE
- **Affected Systems**: Jenkins instances with insecure Pipeline configurations that allow unvalidated inputs in environment variables.
- **Remediation**: Ensure proper validation of environment variable inputs and avoid dynamic execution of untrusted input. Upgrade to securely configured versions and disable unsafe plugins.

## Usage

### Scan a single target
