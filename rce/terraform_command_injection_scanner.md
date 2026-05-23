# Terraform Command Injection Scanner

## Overview
This tool scans Terraform configuration files (such as `.tf` and `.tfvars`) for vulnerabilities leading to command injection during CLI runs. Malicious input files can expose systems to remote code execution when processed by vulnerable versions of Terraform.

## CVEs Addressed
This tool detects issues in Terraform versions before v1.4.5 that fail to sanitize input configurations. Proper sanitization of interpolation and function calls is required to prevent unauthorized command execution.

## Features
- Scans for malicious patterns across `.tf` and `.tfvars` files
- Detects vulnerable Terraform versions and configuration files
- Outputs results to the console and optionally to a JSON file

## Installation
Ensure Python 3.10+ is installed. Clone this repository and run the scanner:
