# Docker Hub Registry Authentication Bypass Scanner

## Overview

This tool scans Docker Hub registries for potential authentication bypass vulnerabilities. It identifies misconfigured
permissions that allow unauthorized access to private repositories and tags, which can lead to information disclosure
and potentially downstream exploit chains (e.g., RCE if private images contain unsafe code/configuration).

## Key Features

- Detects misconfigured Docker Hub registry APIs vulnerable to auth bypass.
- Active probing against `/tags/list` and `/manifests` endpoints.
- Supports detection-only mode (`--safe` flag).
- JSON output for file-based vulnerability reports.
- Bulk scanning with customizable concurrency.

## Usage Examples

### Single Target Detection and Probe
