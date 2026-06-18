# Jenkins Script Console Remote Code Execution (RCE) Scanner

This tool scans for unauthenticated access to the Jenkins Script Console, which could lead
to remote code execution (RCE) due to insecure administrative access to Jenkins instances.
It identifies misconfigurations or exposures caused by lack of proper access controls.

## CVE Information

- **CVE-ID**: Multiple (Jenkins Script Console Misconfiguration)
- **CVSS 3.1 Base Score**: 9.8 (Critical)

### Vulnerability Details

The Jenkins Script Console is a powerful administrative tool in Jenkins that allows running arbitrary Groovy code on the server. When misconfigured, the Script Console may inadvertently become accessible without proper authentication. Attackers leveraging this misconfiguration can execute arbitrary operating system commands.

## Features

- Detects Jenkins installations and probes for exposed Script Console access.
- Extracts and identifies the Jenkins version.
- Determines if the version is potentially vulnerable based on version thresholds.
- Active probing feature to test RCE (disabled with `--safe` flag).
- Async-enabled for high concurrency scanning.

## Usage Examples

### Scan a single target for vulnerability

