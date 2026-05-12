# Terraform Sensitive Variable Leak Scanner

Terraform state files might inadvertently contain sensitive variables such as
API keys, passwords, and tokens. If these files are exposed or improperly
secured, they can lead to severe security breaches. This tool helps identify
such exposed state files and scans them for sensitive variables.

## Features
- Detects exposure of Terraform state files hosted locally or remotely.
- Scans for sensitive fields (e.g., API keys, secrets, tokens) within state files.
- Can be used in **safe mode** to only detect exposed files without inspecting data.
- Outputs results in JSON format for easier sharing and reporting.

## Installation
Requires Python 3.10+. Install dependencies:

