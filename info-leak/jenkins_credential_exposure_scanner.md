# Jenkins Credential Exposure Scanner

This tool scans Jenkins instances for exposed and misconfigured credentials.

## Key Features
- Detection of Jenkins API endpoints and fingerprinting.
- Scans for open `/script` and `/api` endpoints for credential leaks.
- Version extraction to identify outdated/vulnerable Jenkins instances.
- Active exploitation to extract leaked credentials (optional via `--safe`).

## Usage Examples
