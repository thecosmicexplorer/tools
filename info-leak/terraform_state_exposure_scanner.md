# Terraform State File Exposure Scanner

This tool scans for exposed Terraform state files (`terraform.tfstate`) to detect sensitive information leaks such as cloud credentials, API keys, and tokens. It is designed for penetration testers, bug bounty hunters, and security professionals seeking to identify misconfigurations in infrastructure deployment pipelines.

Terraform state files can inadvertently be made public due to misconfigured web servers, open cloud storage buckets, or leaks in CI/CD pipelines. These files contain critical secrets and metadata about cloud resources such as AWS, Google Cloud, database credentials, encryption keys, and more.

## Usage

### Scan a single target
To scan a single URL:

