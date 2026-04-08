# Terraform Environment Variable Leak Scanner

This tool scans for publicly accessible Terraform state files (`.tfstate`) and identifies the presence of sensitive environment variable leaks, such as AWS secrets, database credentials, and API tokens.

## How It Works

Terraform state files store information about infrastructure resources, and they can sometimes accidentally contain plaintext sensitive environment variables. If these files are improperly exposed online, they can lead to critical security risks, such as unauthorized access to cloud accounts or infrastructure. This scanner detects such exposed files and identifies leaked secrets.

## Features

- Detects publicly accessible Terraform state files.
- Identifies sensitive environment variables using a predefined list of common keys.
- Optionally performs a "safe mode" scan that does not actively inspect the file contents.
- Configurable concurrency for parallel scanning.
- Can save results in JSON format for further analysis.

## Installation

This tool is written in Python and requires Python 3.10 or later. You can install the required dependencies using `pip`:

