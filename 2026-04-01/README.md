# Kubernetes ingress-nginx CVE-2026-54321 RCE Scanner

This tool scans for instances of Kubernetes ingress-nginx that are vulnerable to the annotation-based remote code execution (RCE) vulnerability tracked as CVE-2026-54321. The issue enables attackers with access to create ingress resources to inject malicious annotations, potentially allowing arbitrary command execution on the underlying system.

## Features

- Detects ingress-nginx instances and retrieves their installed version.
- Compares against the patched version (v1.9.0).
- Optionally performs active probing to confirm exploitability (disabled in `--safe` mode).
- Supports scanning single and multiple targets.
- Outputs findings to the terminal as well as an optional JSON file.

## Usage

### Scan a single target

