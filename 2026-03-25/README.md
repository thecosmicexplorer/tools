# Terraform State Exposure Scanner

Terraform State Exposure Scanner is an advanced security tool designed to identify publicly accessible Terraform state files (`terraform.tfstate`) that may inadvertently leak sensitive information such as API keys, secrets, and cloud credentials.

Terraform state files often include critical details about an infrastructure, including authentication credentials and resource configurations. Exposing these files online can allow attackers to exfiltrate and misuse sensitive data, leading to infrastructure compromise.

## Features
- Detect public accessibility of `terraform.tfstate` files on specified URLs or cloud storage endpoints.
- Optionally parse `.tfstate` files for leaked sensitive keys.
- Supports a safe mode to identify exposed files without parsing content.
- High-performance scanning with configurable concurrency.
- Outputs findings in color-coded terminal format for real-time insights.
- Save scan results in JSON format for further use and analysis.

## CVE Context
While not tied to a specific CVE directly, exposed Terraform state files are a common cause of accidental credential leaks in cloud infrastructure. 

### Usage Examples

#### Scan a Single Target
To check if a single endpoint has an exposed Terraform state file:
