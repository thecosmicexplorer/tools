# HashiCorp Vault Token Leak Scanner

This tool identifies exposed HashiCorp Vault service instances and checks for potential vulnerabilities, such as token leaks and misconfigured policies that might expose sensitive information.

## Features
- Detects publicly accessible Vault deployments.
- Identifies exposed tokens or secret leaks in unauthenticated endpoints.
- Verifies if the exposed Vault instance is running an unpatched version.
- Supports active probing for token leakage (safe mode available).

## CVE Details
- This tool is designed to identify vulnerabilities like those described in various CVEs affecting HashiCorp Vault (e.g., potential CVEs exposing tokens due to misconfigured policies or unauthenticated endpoints).
- Actual results and details will depend on the discovered instance configuration.

## Usage

### Basic Usage
- Scan a single Vault instance:
  