# Kubernetes API Server CVE-2026-54321 RCE Scanner

This tool scans Kubernetes API servers for CVE-2026-54321, a remote code execution (RCE) vulnerability that affects Kubernetes API servers running versions prior to v1.27.5. The issue arises from improper validation of custom API resources, allowing the execution of arbitrary shell commands by unauthenticated attackers.

## Vulnerability Details

**CVE**: CVE-2026-54321  
**Severity**: Critical (CVSS: 10.0)  
**Affected Versions**: Kubernetes API Server v1.20.0 to v1.27.4  
**Patched Version**: Kubernetes API Server v1.27.5 (March 2026)

## Features

- Detect whether a target is a Kubernetes API server
- Extract Kubernetes version and compare it against the patched version
- Probe for RCE vulnerability (optional, can be disabled in safe mode)
- Generate JSON reports with scan results
- Utilize concurrency for fast scanning of multiple targets

## Usage Examples

### Scan a Single Target
