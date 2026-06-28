# npm_package_command_injection_scanner

## Overview

This tool scans for command injection vulnerabilities in `npm` package scripts via crafted parameters. Improper
sanitization in `package.json` scripts can allow attackers to execute arbitrary commands during `npm install` 
or `npm run` commands, leading to potential RCE.

### Supported Scenarios

- Detect command injection vulnerabilities in `npm` `package.json` scripts.
- Identify malicious or vulnerable npm scripts in supply chain attacks.
- Detect improper escaping of special characters in package scripts.

## Features

- **Async scanning:** Supports concurrent analysis of multiple directories or a bulk file list.
- **Script pattern analysis:** Detects common command injection patterns (`$`, `&&`, `%00`, etc.) in package.json scripts.
- **Safe mode:** Allows detection without active command probing.
- **JSON and console output:** Summary of scan results in both formats.

## Usage

Scan a single package directory:
