# HashiCorp Consul ACL Bypass Scanner (CVE-2025-12367)

This is a security scanner for detecting an ACL bypass vulnerability in HashiCorp Consul (CVE-2025-12367). The vulnerability allows unauthorized attackers to bypass access control policies, potentially leading to sensitive data exposure and unauthorized operations.

## Technical Details

- **Vulnerability**: ACL policy bypass
- **CVE**: [CVE-2025-12367](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-12367)
- **Affected versions**: Consul < 1.14.4
- **Resolution**: Upgrade to Consul 1.14.4 or later.

## Features

- Detects HashiCorp Consul instances.
- Extracts Consul version to determine vulnerability status.
- Probes specific API endpoints for verifying ACL bypass vulnerability (optional in safe mode).
- Supports scanning a single target or batch targets from a file.
- Outputs results in JSON format (optional).
- Allows configuration of request concurrency.

## Usage Examples

### Scan a single target for ACL bypass vulnerability
