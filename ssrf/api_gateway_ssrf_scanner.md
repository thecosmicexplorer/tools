# API Gateway SSRF Vulnerability Scanner

This tool scans API gateway instances for potential Server-Side Request Forgery (SSRF) vulnerabilities. SSRF allows attackers to manipulate a vulnerable server into sending requests to unintended destinations.

## Features
- Detects common API gateway implementations (e.g., AWS API Gateway, Kong, Traefik, etc.)
- Tests common avenues for SSRF exploitation like internal admin or debug routes
- Can actively probe for exploitation of AWS metadata services (in non-safe mode)
- Concurrency to speed up scans
- Option to output results as a JSON file
- Optional safe mode for detection-only scans

## Usage Examples

Scan a single target for SSRF vulnerabilities:
