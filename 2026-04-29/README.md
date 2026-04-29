# kubectl Proxy SSRF Scanner

This tool scans publicly exposed Kubernetes `kubectl proxy` endpoints for misconfigurations that may lead to Server-Side Request Forgery (SSRF) vulnerabilities. Misconfigured `kubectl proxy` endpoints can allow attackers to escalate privileges or access sensitive metadata and internal resources.

## Features

- **Detection**: Identifies exposed `kubectl proxy` instances based on API response fingerprints.
- **SSRF Testing**: Actively tests for SSRF vulnerabilities against known endpoints (`169.254.169.254`, `127.0.0.1`, etc.).
- **Safe Mode**: Skips active SSRF probing when the `--safe` flag is used.
- **Concurrency Support**: Configurable parallel scanning with the `--concurrency` flag.
- **Output**: Human-readable ANSI terminal output and JSON format via `--output`.

## Usage

### Scan a Single Target
