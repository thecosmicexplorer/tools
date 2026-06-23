# Jupyter Notebook Token Leak Detection Scanner

This tool scans for misconfigured Jupyter Notebook or JupyterLab instances that either disable authentication or expose access tokens through URLs. While Jupyter applications require tokens for authentication, improper deployments often lead to accidental token disclosures or unauthenticated access, potentially allowing attackers to compromise the instances.

## Features

- Detects Jupyter Notebook or JupyterLab instances.
- Actively checks for exposed access tokens (optional, enabled by default).
- Supports a `--safe` mode for detection-only scanning without token enumeration.
- Performs version detection to identify potential vulnerabilities.
- Outputs results in JSON format with rich logging.

## Usage Examples

### Scan a single target for token leaks
