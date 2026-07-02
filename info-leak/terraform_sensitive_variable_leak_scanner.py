#!/usr/bin/env python3
"""
Terraform Sensitive Variable Leak Scanner
=========================================
Scans Terraform configuration files to detect hardcoded sensitive variables
that might be exposed in source code repositories or public locations.
This tool is designed to help prevent sensitive data leaks such as API keys,
credentials, private tokens, or secrets.

Security Context:
- Hardcoding sensitive values in Terraform variables or directly in configuration files
  can expose your secrets to unauthorized users if files are uploaded to public repositories
  or stored in insecure locations.
- Sensitive variables typically include patterns such as "password", "secret", "key",
  "token", and similar identifiers.

Features:
- Detects sensitive variable names in Terraform `.tf` and `.tfvars` files.
- Supports scanning individual files or directories recursively.
- Outputs findings in JSON format for further analysis.

Usage:
  # Scan a single Terraform file
  python terraform_sensitive_variable_leak_scanner.py --file main.tf

  # Scan an entire directory recursively
  python terraform_sensitive_variable_leak_scanner.py --directory ./terraform_project

  # Output scan results to a JSON file
  python terraform_sensitive_variable_leak_scanner.py --directory ./terraform_project --output findings.json

References:
  - https://www.terraform.io/docs/language/values/variables.html#declaring-an-input-variable
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
"""

import os
import re
import json
import sys
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Scanner Configuration ────────────────────────────────────────────────────

TOOL_NAME = "terraform_sensitive_variable_leak_scanner"
VERSION = "1.0.0"

# Common patterns for sensitive variables in Terraform configurations
SENSITIVE_VARIABLE_PATTERNS = [
    r'(?i)password\s*=\s*".*"', 
    r'(?i)secret\s*=\s*".*"', 
    r'(?i)key\s*=\s*".*"', 
    r'(?i)token\s*=\s*".*"', 
    r'(?i)aws_access_key_id\s*=\s*".*"', 
    r'(?i)aws_secret_access_key\s*=\s*".*"',
]

# ── Core Scanner Logic ────────────────────────────────────────────────────────

def scan_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Scan a single .tf or .tfvars file for sensitive variable patterns.

    :param filepath: The path of the file to scan.
    :return: A list of findings with sensitive variable details.
    """
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            lines = file.readlines()
          
        for line_num, line in enumerate(lines, start=1):
            for pattern in SENSITIVE_VARIABLE_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "match": line.strip(),
                        "pattern": pattern.strip(),
                        "severity": "CRITICAL"
                    })

    except (IOError, UnicodeDecodeError) as e:
        print(c(RED, f"[ERROR] Could not read file {filepath}: {e}"))

    return findings


async def scan_directory(directory: str) -> List[Dict[str, Any]]:
    """
    Recursively scan a directory for .tf and .tfvars files containing sensitive variables.

    :param directory: Path to the directory to scan.
    :return: List of findings across all scanned files.
    """
    findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith((".tf", ".tfvars")):
                filepath = os.path.join(root, file)
                findings.extend(scan_file(filepath))
    return findings


async def main():
    parser = argparse.ArgumentParser(description="Scan Terraform files for sensitive variables.")
    parser.add_argument("--file", type=str, help="Path to a Terraform `.tf` or `.tfvars` file.")
    parser.add_argument("--directory", type=str, help="Path to a directory containing Terraform files.")
    parser.add_argument("--output", type=str, help="Path to save scan results in JSON format.")
    args = parser.parse_args()

    if not args.file and not args.directory:
        print(c(RED, "[ERROR] Either --file or --directory must be specified."))
        parser.print_help()
        sys.exit(1)

    findings = []
    if args.file:
        findings.extend(scan_file(args.file))

    if args.directory:
        findings.extend(await scan_directory(args.directory))

    if findings:
        print(c(YELLOW, f"[HIGH] Found {len(findings)} sensitive variables!"))
        for finding in findings:
            print(c(RED, f"File: {finding['file']}, Line: {finding['line']}"))
            print(c(CYAN, f"  Match: {finding['match']}"))
            print(c(YELLOW, f"  Reason: Detected pattern `{finding['pattern']}`"))
    else:
        print(c(GREEN, "[INFO] No sensitive variables found."))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as outfile:
                json.dump(findings, outfile, indent=4)
            print(c(GREEN, f"[INFO] Results saved to {args.output}"))
        except IOError as e:
            print(c(RED, f"[ERROR] Failed to save results: {e}"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(RED, "\n[ERROR] Scan interrupted by user."))
        sys.exit(1)
