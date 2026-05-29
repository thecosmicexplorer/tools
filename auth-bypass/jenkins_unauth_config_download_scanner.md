# Jenkins Unauthorized Configuration File Download Scanner

This tool scans Jenkins servers for unauthorized configuration file download vulnerabilities. These vulnerabilities allow attackers to retrieve sensitive configuration files (`config.xml`), which may contain sensitive information such as usernames, passwords, and API keys. Exposed configurations can lead to escalated access and further exploitation of the Jenkins system.

## Features

- Asynchronous scanning for high-speed analysis of multiple targets
- Detects Jenkins instances by fingerprinting
- Actively probes for unauthorized access to common configuration file paths
- Safe mode available for detection-only scans
- JSON output option for structured reporting
- ANSI color-coded terminal outputs for quick interpretation

## CVE Details

- Jenkins configuration file exposures due to misconfiguration or vulnerable plugins
- Multiple CVEs and misconfigurations could lead to unauthorized access (no single CVE listed, as this is a vulnerability class)

## Usage Examples

### Scan a Single Target

