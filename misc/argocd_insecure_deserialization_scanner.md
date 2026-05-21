# ArgoCD Insecure Deserialization Scanner (CVE-2026-71345)

This tool scans for ArgoCD instances vulnerable to insecure deserialization via malicious Helm chart inputs (CVE-2026-71345). The vulnerability affects ArgoCD versions prior to 4.11.3, allowing attackers to execute arbitrary commands through crafted Helm chart payloads.

## Usage

### Scan a single ArgoCD instance
