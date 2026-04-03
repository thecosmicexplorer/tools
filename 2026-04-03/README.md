# Consul ACL Bypass Scanner (CVE-2026-00321)

This tool scans for instances of HashiCorp Consul that are vulnerable to the 
ACL bypass vulnerability (CVE-2026-00321). If exploited, this flaw enables 
unauthorized access to Consul's APIs and unauthorized operations, posing a 
significant risk to sensitive systems.

## Features

- Detects HashiCorp Consul instances through multiple HTTP paths and fingerprints.
- Extracts and evaluates detected version information against patched version (v1.16.0).
- Optionally probes the instance to confirm the vulnerability.
- Safe-mode scanning for detection-only checks.
- Supports single-target and bulk-target scans.
- ANSI color-coded output for terminal visibility.
- Exports findings as JSON for further analysis.

## Installation

1. Clone the repository:
   