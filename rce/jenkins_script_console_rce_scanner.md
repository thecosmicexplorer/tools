# Jenkins Script Console RCE Scanner (CVE-2026-12345)

## Overview

This tool detects and exploits a remote code execution (RCE) vulnerability in Jenkins' Script Console endpoint (CVE-2026-12345). The affected versions of Jenkins have an insecure configuration that allows unauthenticated access to the `/script` endpoint, enabling a remote attacker to execute arbitrary commands on the underlying server. The CVSS score for this vulnerability is 9.8 (Critical).

## Features

- Detects Jenkins instances from predictable endpoints.
- Extracts and validates Jenkins version information.
- Checks if the detected Jenkins version is vulnerable.
- Exploits the vulnerability to execute attacker-provided commands (optional).
- Option to perform detection-only scans with the `--safe` flag.
- Supports single-target and bulk-target scans.
- Outputs results in colored terminal output and optional JSON format.

## Usage

Scan a single target:
