# Ansible Vault Password Leak Scanner

This tool scans for potential Ansible Vault password leaks caused by common misconfigurations or insecure patterns in Ansible playbooks or related files. 

Ansible Vault is an important feature for securely encrypting sensitive data such as passwords and credentials. However, simple mistakes, such as storing plaintext passwords or using unsafe CLI options, can lead to data leaks.

## Features

- Identifies potential Vault password leaks in Ansible playbooks, inventory files, and shell execution logs.
- Detects patterns commonly used when passwords are hardcoded or improperly stored.
- Offers "safe mode" for security-conscious scans without exposing sensitive file content.
- Supports bulk scanning with adjustable concurrency for processing large file sets.

## Usage Examples

### Scan a single file
