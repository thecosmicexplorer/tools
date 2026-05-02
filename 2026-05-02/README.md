# Caddy Server Directory Traversal Vulnerability (CVE-2025-4923) Scanner

## Overview
This tool scans for the Caddy web server directory traversal vulnerability (CVE-2025-4923). The attack is made possible by vulnerable configurations that allow crafted HTTP requests to access files outside the intended web root directory. This vulnerability exposes critical server files such as `/etc/passwd` and `windows/win.ini`. The vulnerability affects Caddy versions v2.0.0 to v2.7.0 and is fixed in v2.7.1.

## Features
- Detects whether the server is running Caddy and its version.
- Checks if the server version is vulnerable to CVE-2025-4923.
- Optionally performs active directory traversal probing (disabled in safe mode).
- Supports scanning single or multiple targets via CLI.
- Outputs results in JSON format for integration with other tools.

## Usage Examples
To run the scanner, use one of the following commands:

- **Scan a single target**  
  