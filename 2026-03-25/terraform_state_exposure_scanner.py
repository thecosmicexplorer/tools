#!/usr/bin/env python3
"""
Terraform State Exposure Scanner
================================
Scans for publicly accessible Terraform state files, which may leak sensitive
data such as cloud credentials, secrets, API keys, and infrastructure details.

Risks of exposed Terraform state files:
  - Plaintext secrets like AWS access keys
  - Resource provider credentials
  - Names of sensitive resources and configurations
  - Service endpoints that could lead to further attacks

This tool identifies public Terraform state files on endpoints and cloud storage
buckets, parses them for sensitive keys, and highlights leaked information.

Usage:
  # Scan a single target URL
  python terraform_state_exposure_scanner.py --target https://example.com/terraform.tfstate

  # Scan multiple targets from a file
  python terraform_state_exposure_scanner.py --list urls.txt --output findings.json

  # Safe mode — identifies exposed state files without parsing
  python terraform_state_exposure_scanner.py --safe --list urls.txt

References:
  - https://www.terraform.io/docs/state/index.html
  - https://www.hashicorp.com/security
"""

import argparse
import asyncio
import json
import re
from urllib.parse import urljoin

import httpx
from colorama import Fore, Style

# ── Detection and Parsing Rules ───────────────────────────────────────────────

TERRAFORM_STATE_INDICATORS = ['"version"', '"terraform_version"', '"resources"', '"outputs"']

# Keys typically found in Terraform state data that may contain sensitive info
SENSITIVE_KEYS = [
    "access_key", "secret_key", "token", "password", "username", "private_key", 
    "key_material", "client_secret", "api_key", "auth_token"
]

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20


# ── Helper Functions ──────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure the URL has the appropriate protocol and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_sensitive_data_from_tfstate(content: str):
    """Extract sensitive keys and values from a Terraform state file."""
    findings = {}
    try:
        parsed = json.loads(content)
        flat_items = {}

        # Flatten to handle potential nested key structures
        def flatten(data, prefix=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    flat_items[full_key] = value
                    flatten(value, full_key)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    item_key = f"{prefix}.{i}" if prefix else str(i)
                    flatten(item, item_key)

        flatten(parsed)

        # Extract sensitive keys
        for key, value in flat_items.items():
            lowered_key = key.lower()
            if any(sensitive_key in lowered_key for sensitive_key in SENSITIVE_KEYS):
                findings[key] = value
    except json.JSONDecodeError:
        return None
    return findings


# ── Scanner Logic ─────────────────────────────────────────────────────────────

async def check_terraform_state(client: httpx.AsyncClient, url: str, safe_mode: bool, semaphore: asyncio.Semaphore):
    """Checks if a URL exposes a Terraform state file."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            return None, f"Request failed ({str(e)})"

        if response.status_code == 200 and any(indicator in response.text for indicator in TERRAFORM_STATE_INDICATORS):
            if safe_mode:
                return {"url": url, "status": "exposed", "sensitive_data": None}, None
            else:
                sensitive_data = extract_sensitive_data_from_tfstate(response.text)
                if sensitive_data:
                    return {"url": url, "status": "leaks sensitive data", "sensitive_data": sensitive_data}, None
                return {"url": url, "status": "exposed", "sensitive_data": None}, None
        return None, "Not a Terraform state file or not accessible"


async def scan_targets(urls, safe_mode, concurrency, no_verify):
    """Scans a list of targets for Terraform state file exposure."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=(not no_verify)) as client:
        tasks = [check_terraform_state(client, normalize_url(url), safe_mode, semaphore) for url in urls]
        for task in asyncio.as_completed(tasks):
            result, error = await task
            if result:
                results.append(result)
                print(
                    f"{Fore.RED if 'sensitive_data' in result and result['sensitive_data'] else Fore.YELLOW}"
                    f"{result['url']} - {result['status']}{Style.RESET_ALL}"
                )
            elif error:
                print(f"{Fore.YELLOW}{error}{Style.RESET_ALL}")
    return results


# ── Command-Line Interface ────────────────────────────────────────────────────

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Terraform State Exposure Scanner")
    parser.add_argument("--target", type=str, help="Single URL to scan")
    parser.add_argument("--list", type=str, help="File containing a list of URLs to scan")
    parser.add_argument("--output", type=str, help="File to save scan results as JSON")
    parser.add_argument("--safe", action="store_true", help="Safe mode (no sensitive data parsing)")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    return parser.parse_args()


async def main():
    args = parse_arguments()

    # Validate input
    if not args.target and not args.list:
        print(f"{Fore.RED}Error: You must provide a --target or --list of targets.{Style.RESET_ALL}")
        sys.exit(1)

    # Gather URLs to scan
    urls = []
    if args.target:
        urls.append(args.target)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found - {args.list}{Style.RESET_ALL}")
            sys.exit(1)

    # Scan targets
    print(f"{Fore.CYAN}Starting scan of {len(urls)} target(s)...{Style.RESET_ALL}")
    results = await scan_targets(urls, args.safe, args.concurrency, args.no_verify)

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
