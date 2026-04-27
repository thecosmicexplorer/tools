# AWS Instance Metadata SSRF Scanner

This tool scans for Server-Side Request Forgery (SSRF) vulnerabilities targeting AWS instance metadata
endpoints. Attackers exploit improperly configured applications to access sensitive data such as
AWS IAM credentials via the metadata service (IMDS).

## Relevant CVEs
- [CVE-2019-0164](https://nvd.nist.gov/vuln/detail/CVE-2019-0164): Amazon Web Services instance metadata
  service SSRF exploitation in EC2 instances.
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html): Server-Side Request Forgery (SSRF).

## Usage

### Example Commands
#### Scan a single target
