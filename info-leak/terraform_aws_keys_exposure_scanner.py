#!/usr/bin/env python3
"""
Terraform AWS Keys Exposure Scanner
===================================
This tool scans for exposed AWS access keys and secret keys in Terraform state files, 
which often contain sensitive information inadvertently exposed due to misconfigurations.

Security Concern:
  - Terraform state files frequently store sensitive data, including AWS access and secret keys.
  - Exposed state files, when accessible over public URLs or misconfigured storage, pose high-severity risks, 
    enabling potential misuse of AWS resources.

Usage:
  # Scan a single Terraform state URL
  python terraform_aws_keys_exposure_scanner.py --target https://example.com/terraform.tfstate

  # Scan a list of URLs
  python terraform_aws_keys_exposure_scanner.py --list state_urls.txt --output results.json

  # Safe mode — detection only, no content fetching or sensitive string searches
  python terraform_aws_keys_exposure_scanner.py --list state_urls.txt --safe

References:
  - https://developer.hashicorp.com/terraform/language/state/sensitive-data
  - https://medium.com/@nsriram/exposing-aws-keys-and-secrets-through-terraform-states-a6db7e5d39c6
"""

import asyncio
import argparse
import json
import re
import sys
from urllib.parse import urlparse

import httpx

# ── Constants ────────────────────────────────────────────────────────────────

DETECTION_MARKERS = [
    '"version":',
    '"terraform_version":',
    '"resources":'
]

AWS_KEY_PATTERNS = {
    "AWS_ACCESS_KEY_ID": r"(?<![A-Z0-9])[A-Z0-9]{16,128}(?![A-Z0-9])",
    "AWS_SECRET_ACCESS_KEY": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{30,128}(?![A-Za-z0-9/+=])"
}

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 10  # seconds
DEFAULT_HEADERS = {
    "User-Agent": "TerraformAWSKeysExposureScanner/1.0 (security research tool)"
}

# ANSI color codes for status messages
COLORS = {
    "CRITICAL": "\033[31m",  # Red
    "INFO": "\033[32m",      # Green
    "RESET": "\033[0m",      # Reset
}


# ── Helper Functions ─────────────────────────────────────────────────────────

def print_colored(message: str, level: str = "INFO"):
    """Print a message with ANSI colors based on the log level."""
    color = COLORS.get(level, COLORS["RESET"])
    reset = COLORS["RESET"]
    print(f"{color}[{level}] {message}{reset}")


def normalize_url(url: str) -> str:
    """Ensure the URL has a valid scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def fetch_url(client: httpx.AsyncClient, url: str):
    """Fetch a URL and return the response text or None."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            return response.text
    except httpx.RequestError as ex:
        print_colored(f"Error fetching {url}: {str(ex)}", "CRITICAL")
    return None


def detect_terraform_state(content: str) -> bool:
    """Check if the content matches Terraform state file markers."""
    for marker in DETECTION_MARKERS:
        if marker in content:
            return True
    return False


def extract_aws_keys(content: str):
    """Extract AWS keys (Access Key IDs and Secret Access Keys) from text."""
    findings = {}
    for key_name, pattern in AWS_KEY_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[key_name] = list(set(matches))
    return findings


def write_output(results: list, output_path: str):
    """Write JSON results to a file."""
    try:
        with open(output_path, "w") as f:
            json.dump(results, f, indent=4)
        print_colored(f"Results written to {output_path}", "INFO")
    except IOError as e:
        print_colored(f"Error writing output file: {e}", "CRITICAL")


# ── Core Scanner ────────────────────────────────────────────────────────────

async def scan_state_url(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Scan a single Terraform state URL for AWS key exposure.
    If `safe_mode` is True, only detect Terraform state existence without scanning for keys.
    Returns detection and exposure details.
    """
    url = normalize_url(url)
    async with semaphore:
        result = {"url": url, "terraform_state_detected": False, "aws_keys_exposed": {}}
        content = await fetch_url(client, url)
        if not content:
            return result

        if detect_terraform_state(content):
            result["terraform_state_detected"] = True
            print_colored(f"Terraform state file detected: {url}", "INFO")

            if not safe_mode:
                keys = extract_aws_keys(content)
                if keys:
                    result["aws_keys_exposed"] = keys
                    print_colored(f"CRITICAL: Exposed AWS keys detected at {url}", "CRITICAL")
                else:
                    print_colored(f"No AWS keys detected in Terraform state file at {url}", "INFO")
        return result


async def scan_targets(targets: list, concurrency: int, safe_mode: bool, no_verify_ssl: bool):
    """
    Scan a list of targets for Terraform state files and AWS key exposure.
    Returns a list of results.
    """
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS, verify=not no_verify_ssl) as client:
        tasks = [scan_state_url(client, target, semaphore, safe_mode) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=False)
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Detects exposed AWS keys in publicly accessible Terraform state files."
    )
    parser.add_argument("--target", help="URL of a single Terraform state file to scan.")
    parser.add_argument("--list", help="File containing a list of state file URLs to scan.")
    parser.add_argument("--output", help="File to save results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Detection only, skip sensitive key checks.")
    parser.add_argument("--concurrency", type=int, default=10, 
                        help="Number of concurrent requests (default: 10).")
    parser.add_argument("--no-verify", action="store_true", 
                        help="Disable SSL certificate verification.")
    args = parser.parse_args()

    # Validate input
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except IOError as e:
            print_colored(f"Error reading target list file: {e}", "CRITICAL")
            sys.exit(1)

    if not targets:
        print_colored("No targets specified. Use --target or --list.", "CRITICAL")
        sys.exit(1)

    # Scan targets
    print_colored(f"Scanning {len(targets)} targets with concurrency {args.concurrency}...", "INFO")
    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe, args.no_verify))

    # Output results
    if args.output:
        write_output(results, args.output)
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
