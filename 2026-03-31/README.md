# Flask Debug Mode Scanner

## Overview

The Flask Debug Mode Scanner identifies Flask applications inadvertently running with debug mode enabled, which can lead to serious security vulnerabilities. In debug mode, Flask activates a debugger that exposes internal application functionality, including an interactive code execution console that could lead to remote code execution (RCE) if improperly secured.

This tool provides fingerprinting and active probe mechanisms to detect these misconfigurations, and offers a safe mode for detection-only scans that avoid intrusive tests.

### Vulnerability Details

- **Affected Software**: Flask web applications with `debug=True` in production settings.
- **Impact**: Remote Code Execution (RCE) via the Werkzeug debugger's console.
- **Exposed Endpoints**: Commonly reachable paths like `/console` and `/_debug_toolbar/`.
- **Mitigation**: Always disable debug mode (`debug=False`) in production environments.

---

## Usage

### Single Target Scan:

