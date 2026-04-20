# TeamCity Authentication Bypass Scanner

This tool detects and probes for authentication bypass vulnerabilities in TeamCity CI/CD instances. It is designed for use by security researchers, penetration testers, and authorized engagements. The scanner includes detection mechanisms to identify running TeamCity instances and active probes to verify vulnerabilities, including unauthenticated REST API access.

## Features

- Detect TeamCity instances by fingerprinting common endpoints and HTML responses.
- Extract version information and compare against known patched versions.
- Active probing to test for authentication bypass vulnerabilities.
- Safe mode for detection-only scanning.
- Supports single target or bulk scanning with URL lists.

## CVEs Addressed

- CVE-2022-41127: Authentication bypass in TeamCity REST API.
- Other related vulnerabilities potentially based on version detection and misconfiguration.

## Usage

### Scan a single target

