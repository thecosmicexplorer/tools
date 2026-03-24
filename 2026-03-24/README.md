# Jenkins Unauthenticated RCE Scanner

This tool scans for unauthenticated Remote Code Execution (RCE) vulnerabilities in Jenkins Continuous Integration/Deployment (CI/CD) instances.

## CVEs Covered
This tool detects multiple RCE vulnerabilities in Jenkins, including common CVEs and related misconfigurations.

## Features
- Detects exposed Jenkins instances using headers and fingerprinting
- Extracts Jenkins version information
- Supports safe mode for detection-only scans
- Active probing for critical vulnerabilities like the Groovy script console
- Outputs results in JSON format

## Usage
### Scan a single target
