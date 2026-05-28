# Terraform AWS Keys Exposure Scanner

The **Terraform AWS Keys Exposure Scanner** is a security tool designed to detect exposed AWS access keys and secret keys 
inside Terraform state files. It is specifically developed for use in authorized red team assessments and bug bounty testing.

## Security Risk

Terraform state files (`terraform.tfstate`) may contain sensitive information, such as AWS credentials. If these files 
are stored in publicly accessible cloud storage or leaked through version control systems, they can expose critical 
credentials and severely compromise the affected systems.

**Key Risks:**
- Unauthorized access to AWS resources using exposed credentials.  
- Potential for privilege escalation or infrastructure manipulation.  

## Features
1. Detects publicly accessible Terraform state files.
2. Verifies exposed AWS Access Key IDs and Secret Access Keys (if `--safe` is not specified).
3. Outputs results in JSON format for follow-up analysis or reporting.

## Prerequisites

The following Python packages are required:
- `httpx>=0.25.1`

To install dependencies, run:
