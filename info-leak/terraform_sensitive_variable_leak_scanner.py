#!/usr/bin/env python3
"""
Terraform Sensitive Variable Leak Scanner
=========================================
This tool scans Terraform state files for sensitive variables that may have been
inadvertently exposed in publicly accessible state files or during improper storage.

Vulnerability Description:
--------------------------
Terraform state files can contain sensitive information, including access keys,
tokens, and passwords, which may lead to security issues if exposed to unauthorized users.
This tool identifies such sensitive information in Terraform state files by looking for 
specific keywords and patterns.

Key Features:
  - Detects Terraform state file exposure by performing content fingerprint checks.
  - Identifies sensitive fields in state files, such as access keys and secrets.
  - Support for remote file scanning (HTTP(S) targets) as well as local file scanning.
  - Detection-only mode with the `--safe` flag for risk-free assessment.
  - Asynchronous implementation for scanning multiple URLs concurrently.
  - JSON output support for automated reporting.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage Examples:
---------------
# Scan a single remote Terraform state file
python terraform_sensitive_variable_leak_scanner.py --target https://example.com/terraform.tfstate

# Scan multiple Terraform state file URLs from a file
python terraform_sensitive_variable_leak_scanner.py --list targets.txt --output findings.json

# Scan a local Terraform state file
python terraform_sensitive_variable_leak_scanner.py --local /path/to/terraform.tfstate

# Perform detection-only scanning without evaluating sensitive variable values
python terraform_sensitive_variable_leak_scanner.py --list targets.txt --safe

References:
-----------
  - https://developer.hashicorp.com/terraform/language/state/sensitive-data
  - https://www.terraform.io/docs/state/index.html
  - https://blog.brunokrebs.com/access-sensitive-data-from-terraform-state
"""

import argparse
import asyncio
import httpx
import json
import os
import re
from pathlib import Path
from termcolor import colored

# Constants
DEFAULT_CONCURRENCY = 10
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 50

# Sensitive keys to search for in state files
SENSITIVE_KEYWORDS = [
    "access_key",
    "secret_key",
    "private_key",
    "client_secret",
    "api_key",
    "password",
    "token",
    "jwt",
]

# Color codes for terminal output
COLOR_CRITICAL = "red"
COLOR_HIGH = "yellow"
COLOR_INFO = "green"
COLOR_RESET = "white"

# Helper Functions
def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

async def fetch_file_content(client, target):
    """Fetch the contents of a local file or HTTP(S) resource."""
    if target.startswith(("http://", "https://")):
        try:
            response = await client.get(target, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            print(colored(f"Error fetching remote file: {target}\n{e}", COLOR_HIGH))
            return None
    else:
        try:
            with open(target, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(colored(f"Error reading local file: {target}\n{e}", COLOR_HIGH))
            return None

def analyze_state_file(content):
    """Analyze the content of a Terraform state file for sensitive variables."""
    findings = []
    for key in SENSITIVE_KEYWORDS:
        matches = re.findall(rf'"{key}":\s*"([^"]+)"', content)
        for value in matches:
            findings.append({"keyword": key, "value_snippet": value[:5] + "..."})
    return findings

def print_findings(target, findings):
    """Print detected findings to the terminal."""
    for finding in findings:
        print(
            colored(f"[CRITICAL] {target}: Detected sensitive key '{finding['keyword']}' with value '{finding['value_snippet']}'", COLOR_CRITICAL)
        )

async def scan_target(client, target, semaphore, safe_mode):
    """Scan a single target either local or remote."""
    async with semaphore:
        normalized_target = normalize_url(target) if target.startswith(("http://", "https://")) else target
        content = await fetch_file_content(client, normalized_target)
        if not content:
            print(colored(f"[INFO] {normalized_target} could not be accessed or is empty.", COLOR_INFO))
            return {"target": normalized_target, "status": "error", "findings": None}

        findings = []
        if not safe_mode:
            findings = analyze_state_file(content)
            if findings:
                print_findings(normalized_target, findings)
        
        status = "vulnerable" if findings else "safe"
        return {"target": normalized_target, "status": status, "findings": findings}

async def scan_targets(targets, concurrency, safe_mode):
    """Scan multiple targets concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient() as client:
        tasks = [scan_target(client, target, semaphore, safe_mode) for target in targets]
        results = await asyncio.gather(*tasks)
    return results

def load_targets_from_file(file_path):
    """Load targets from a text file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(colored(f"Error reading targets file: {file_path}\n{e}", COLOR_HIGH))
        return []

def write_results_to_file(results, output_file):
    """Write scan results to a JSON file."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(colored(f"Results saved to {output_file}", COLOR_INFO))
    except Exception as e:
        print(colored(f"Error writing output file: {output_file}\n{e}", COLOR_HIGH))

# Main Function
def main():
    parser = argparse.ArgumentParser(description="Terraform Sensitive Variable Leak Scanner")
    parser.add_argument("--target", help="Single target URL or file path to scan.")
    parser.add_argument("--list", help="File containing a list of targets to scan.")
    parser.add_argument("--local", help="Path to a local Terraform state file for scanning.")
    parser.add_argument("--output", help="File path to save scan results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no sensitive data inspection).")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max concurrent requests (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for remote scans.")

    args = parser.parse_args()
    targets = []

    if args.target:
        targets.append(args.target)
    if args.list:
        targets.extend(load_targets_from_file(args.list))
    if args.local:
        targets.append(args.local)

    if not targets:
        parser.error("No targets specified. Use --target, --list, or --local.")

    asyncio.run(scan(targets, args.concurrency, args.output, args.safe, args.no_verify))

async def scan(targets, concurrency, output_file, safe_mode, no_verify):
    results = await scan_targets(targets, concurrency, safe_mode)
    if output_file:
        write_results_to_file(results, output_file)

if __name__ == "__main__":
    main()
