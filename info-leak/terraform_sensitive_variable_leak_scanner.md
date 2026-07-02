# Terraform Sensitive Variable Leak Scanner

## Description
`terraform_sensitive_variable_leak_scanner.py` is a Python-based security tool for scanning Terraform configuration files (`.tf` and `.tfvars`) to identify sensitive variables that may contain hardcoded secrets. This tool helps you identify potential data leaks in your Infrastructure-as-Code (IaC) templates before they are pushed to repositories or shared.

## Features
- Detects sensitive variable patterns such as passwords, API keys, secrets, and tokens within `.tf` and `.tfvars` files.
- Scans individual Terraform files or entire directories recursively.
- Outputs findings with details like file name, line number, matching string, and regex pattern used for detection.
- Provides JSON output for easier integration with other tools.
- ANSI color-coded terminal output for better readability.

## Usage Examples

#### Scan a single Terraform file
