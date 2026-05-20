# Jenkins Script Console RCE Scanner

## Overview

This tool scans for improperly secured Jenkins instances with open access to the Script Console, a feature that enables Groovy-based remote code execution (RCE). Misconfigured or insufficiently secured Script Consoles pose a critical security risk, allowing attackers to execute arbitrary commands on the system.

## Features

- Detects Jenkins instances via `X-Jenkins` headers or content markers.
- Probes for open access to the Script Console endpoints (`/script`, `/scriptText`).
- Active RCE probes using Groovy scripts (optional, default: enabled).
- Supports bulk scanning with configurable concurrency.
- Outputs results to JSON for further analysis.

## Usage

### Basic Detection
Scan a single target for Script Console exposure:
