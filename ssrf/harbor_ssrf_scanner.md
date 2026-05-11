# Harbor SSRF Scanner

## Overview
The Harbor SSRF Scanner detects Server-Side Request Forgery (SSRF) vulnerabilities in VMware Harbor, a widely-used container image registry system. SSRF vulnerabilities can be exploited to target internal servers, cloud metadata endpoints, or other internal resources.

## CVE Coverage
The scanner is designed to identify misconfigurations or exploitable endpoints across various versions of Harbor. It actively probes core API endpoints for SSRF vulnerabilities, making it suitable for bug bounty hunters and red team operators.

## Features
- Detects Harbor API endpoints vulnerable to SSRF.
- Active SSRF probing with safe or detection-only mode.
- CLI options for single/multiple targets, output to JSON, and concurrency control.
- ANSI-colored terminal output for better visibility.

## Usage

### Scan a Single Target
