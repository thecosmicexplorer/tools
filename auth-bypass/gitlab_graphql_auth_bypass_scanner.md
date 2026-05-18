# GitLab GraphQL API Authentication Bypass Scanner (CVE-2025-12345)

This tool scans for and attempts to exploit the GitLab CVE-2025-12345 vulnerability. The vulnerability allows
unauthenticated users to send GraphQL queries to exposed GitLab API endpoints, potentially resulting in
unauthorized access to sensitive data such as user details, project configurations, and access tokens.

## CVE Details

**CVE ID**: CVE-2025-12345  
**CVSS v3.1 Base Score**: 9.8 (Critical)  
**Affected Versions**: GitLab 13.0 to 16.4.1  
**Patched Versions**: Fixed in GitLab 16.4.2  

More details about this CVE can be found [here](https://nvd.nist.gov/vuln/detail/CVE-2025-12345).  

## Features
- Asynchronous HTTP-based scanning for high-speed bulk assessments.
- GitLab fingerprinting and version detection.
- Passive and active exploitation modes (`--safe` flag for detection only).
- Optional output to JSON files for reporting.
- Supports user-provided target lists and adjusts concurrency.  

## Usage

