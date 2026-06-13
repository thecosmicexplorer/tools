#!/usr/bin/env python3
"""
Terraform State File Exposure Scanner
======================================
Scans for exposed Terraform state files (TFState) to identify sensitive
information leaks such as cloud credentials, API keys, and other secrets.

Terraform state files (typically `terraform.tfstate`) can contain sensitive
data such as provider access keys, tokens, and other configuration details. If
these files are inadvertently exposed publicly through misconfigured web servers,
cloud storage buckets, or source code repositories, attackers can gain unauthorized
access to cloud resources and services.

Key risks:
  - Leaked AWS and Google Cloud credentials
  - Access to encryption keys, database credentials, and other secrets
  - Reconnaissance data: infrastructure architecture, resources, etc.

Usage:
  # Scan a single URL for exposed state files
  python terraform_state_exposure_scanner.py --target https://example.com/terraform.tfstate

  # Bulk scan from a list of URLs
  python terraform_state_exposure_scanner.py --list urls.txt --output results.json

  # Detection only—skips sensitive data extraction
  python terraform_state_exposure_scanner.py --target https://example.com/terraform.tfstate --safe

  # Adjust concurrency, disable TLS verification
  python terraform_state_exposure_scanner.py --list urls.txt --concurrency 50 --no-verify

References:
  - https://www.hashicorp.com/resources/terraform-state-management
  - https://nvd.nist.gov/vuln/detail/CVE-2021-4193
  - https://github.com/search?q=extension%3Atfstate+AWSAccessKeyId&type=code
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "terraform_state_exposure_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 25

PATTERN_SENSITIVE_KEYS = [
    r'"access_key"\s*:\s*"([^"]+)"',  # Captures AWS Access Keys
    r'"secret_key"\s*:\s*"([^"]+)"',  # Captures AWS Secret Keys
    r'"token"\s*:\s*"([^"]+)',        # Captures Tokens/Passwords
    r'"project_id"\s*:\s*"([^"]+)"',  # Captures Google Cloud Project IDs
    r'"client_email"\s*:\s*"([^"]+)"' # Captures Google Cloud Client emails
]

# ── Functions ────────────────────────────────────────────────────────────────

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fetch content from a URL asynchronously."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            return response.text
    except httpx.RequestError:
        pass
    return None

def extract_sensitive_data(contents: str) -> dict:
    """Parse the contents of a TFState file and extract sensitive data matching patterns."""
    leaks = {}
    for pattern in PATTERN_SENSITIVE_KEYS:
        matches = re.findall(pattern, contents)
        if matches:
            leaks[pattern] = matches
    return leaks

def format_leaks(leaks: dict) -> str:
    """Format sensitive data leaks for human-readable output."""
    output = ""
    for pattern, matches in leaks.items():
        description = {
            r'"access_key"\s*:\s*"([^"]+)"': "AWS Access Key",
            r'"secret_key"\s*:\s*"([^"]+)"': "AWS Secret Key",
            r'"token"\s*:\s*"([^"]+)': "Token/Password",
            r'"project_id"\s*:\s*"([^"]+)"': "Google Cloud Project ID",
            r'"client_email"\s*:\s*"([^"]+)"': "Google Cloud Client Email",
        }.get(pattern, "Sensitive Data")
        output += f"{c(YELLOW, description)}:\n"
        for match in matches:
            output += f"  {c(RED, match)}\n"
    return output

async def scan_target(url: str, safe: bool, sem: asyncio.Semaphore) -> dict:
    """Scan a single target URL for Terraform state exposure."""
    result = {"url": url, "status": "unknown", "leaks": {}}
    async with sem:
        async with httpx.AsyncClient(verify=not safe) as client:
            contents = await fetch_url(client, url)
            if contents is None:
                result["status"] = "unreachable"
                return result

            result["status"] = "exposed"
            if not safe:
                result["leaks"] = extract_sensitive_data(contents)
    return result

async def bulk_scan(args):
    """Scan a list of target URLs asynchronously."""
    sem = asyncio.Semaphore(args.concurrency)

    with open(args.list, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    
    tasks = [scan_target(url, args.safe, sem) for url in urls]
    results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    else:
        for result in results:
            print(f"{c(CYAN, result['url'])}: {c(GREEN, result['status'])}")
            if result["status"] == "exposed" and result["leaks"]:
                print(format_leaks(result["leaks"]))

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Terraform State File Exposure Scanner"
    )
    parser.add_argument("--target", help="URL of the target Terraform state file")
    parser.add_argument("--list", help="File containing a list of URLs to scan")
    parser.add_argument("--output", help="File to save JSON output")
    parser.add_argument("--concurrency", type=int, default=25, help="Concurrency level")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no data extraction)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")

    return parser.parse_args()

async def main():
    args = parse_args()
    if args.target:
        sem = asyncio.Semaphore(1)
        result = await scan_target(args.target, args.safe, sem)
        print(f"{c(CYAN, result['url'])}: {c(GREEN, result['status'])}")
        if result["status"] == "exposed" and result["leaks"]:
            print(format_leaks(result["leaks"]))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=4)
    elif args.list:
        await bulk_scan(args)
    else:
        print(c(RED, "Error: Specify either --target or --list"))
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
