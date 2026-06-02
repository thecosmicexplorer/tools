# Terraform State Exposure Scanner

Terraform State Exposure Scanner is a security tool designed to identify publicly accessible Terraform state files, 
which can often contain sensitive information such as access keys, tokens, private keys, and other crucial credentials.

This tool allows researchers and security professionals to quickly assess the status of Terraform state files and determine if they are exposed, 
and whether they contain any sensitive information in a safe and automated manner.

## Vulnerability Details

Terraform state files commonly store sensitive data in plain text, such as:
- Cloud provider credentials (e.g., AWS access keys)
- SSH private keys
- Access tokens and other secrets

If these files are publicly accessible, attackers can extract this data and compromise the affected environments. Organizations are advised to review their infrastructure to confirm that Terraform state files are securely stored.

## Features
- Detect publicly accessible Terraform state files at common paths (`terraform.tfstate`, `.terraform/terraform.tfstate`, etc.).
- Analyze detected state files for sensitive credentials, such as AWS keys and private keys (disabled in `--safe` mode).
- Support for scanning single targets or multiple targets from a file.
- Generate JSON reports of findings for integration into other tools or reports.
- Color-coded terminal output for easy identification of vulnerable targets.

## Usage

### Scan a single target
