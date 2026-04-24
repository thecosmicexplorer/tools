# Vault Unsealer Authentication Bypass Scanner

**CVE:** CVE-2026-48293  
**Severity:** Critical (CVSS 9.8)  
**Vulnerability Type:** Authentication Bypass  

## Summary
This scanner checks for misconfigured or vulnerable HashiCorp Vault instances that allow unauthenticated access to the Unseal API endpoint, enabling potential attackers to bypass authentication and compromise Vault secrets. The issue is resolved in Vault version 1.12.5.

## Features
- Detects running HashiCorp Vault instances
- Extracts and identifies Vault version
- Optionally probes for Unseal API authentication bypass (configurable via `--safe` flag)
- Supports single target and bulk scanning
- Outputs results in JSON or console output

## Usage Examples

