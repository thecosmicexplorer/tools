#!/usr/bin/env python3
"""
Terraform Environment Variable Leak Scanner
===========================================
This tool scans for publicly accessible Terraform state files (.tfstate) and identifies
the presence of sensitive environment variable leaks, such as AWS secrets, database credentials, 
and API tokens.

Vulnerability Details:
- Terraform state files often contain sensitive data, including plaintext environment variables.
- Public exposure of these files can lead to compromise of infrastructure, data breaches, 
  and unauthorized access.
- Regularly reported in security incidents and bug bounty programs as critical findings.

Detection Strategy:
- Attempts to detect publicly accessible Terraform state files.
- Scans for plaintext environment variable leaks using a list of known sensitive keys.
- Reports critical findings including file locations, cloud provider credentials, and tokens.

Usage:
  # Scan a single target
  python terraform_env_var_leak_scanner.py --target https://example.com/terraform.tfstate

  # Scan a list of targets
  python terraform_env_var_leak_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no content inspection
  python terraform_env_var_leak_scanner.py --list targets.txt --safe

  # Adjust concurrency (default=10)
  python terraform_env_var_leak_scanner.py --list targets.txt --concurrency 20

References:
  - https://www.hashicorp.com/blog/terraform-state-files-and-sensitive-data
  - https://hackerone.com/reports/475343
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78654 (example)

"""
import asyncio
import json
import re
import argparse
from urllib.parse import urlparse

import httpx
from colorama import Fore, Style

# ── Detection markers ─────────────────────────────────────────────────────────

TERRAFORM_FINGERPRINTS = [
    '"version"', '"terraform_version"',
    '"serial"', '"resources"', '"provider"',
]

# Keys commonly found in environment variable leaks
SENSITIVE_KEYS = [
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "DB_PASSWORD",
    "DB_USER",
    "GCP_SERVICE_ACCOUNT",
    "AZURE_CLIENT_SECRET",
    "DO_API_TOKEN",
    "HEROKU_API_KEY",
    "SLACK_API_TOKEN",
    "GITHUB_TOKEN",
    "VAULT_TOKEN",
    "KUBECONFIG",
]

# ── Default values ─────────────────────────────────────────────────────────────

SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme and does not end with a slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_sensitive_data(content: str):
    """Search for sensitive keys in the given content."""
    leaks_found = []
    for key in SENSITIVE_KEYS:
        if key in content:
            leaks_found.append(key)
    return leaks_found


def print_status(level: str, message: str):
    """Print status messages with color coding."""
    color_map = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "INFO": Fore.GREEN,
    }
    color = color_map.get(level, Style.RESET_ALL)
    print(f"{color}[{level}] {message}{Style.RESET_ALL}")


# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_terraform(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Detects whether the target URL exposes a Terraform state file (.tfstate).
    Returns dict with detection info if Terraform is detected, None otherwise.
    """
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                content = response.text
                for marker in TERRAFORM_FINGERPRINTS:
                    if marker in content:
                        return {
                            "url": url,
                            "status_code": response.status_code,
                            "content": content
                        }
        except Exception as e:
            print_status("INFO", f"Error accessing {url}: {e}")
        return None


async def scan_terraform(url: str, client: httpx.AsyncClient, safe: bool, semaphore: asyncio.Semaphore):
    """
    Check a URL for Terraform state file leaks. If a leak is identified,
    prints the critical issue and returns details.
    """
    detection_result = await detect_terraform(client, url, semaphore)
    if detection_result:
        print_status("HIGH", f"Terraform state file detected: {url}")
        if not safe:
            sensitive_data = get_sensitive_data(detection_result["content"])
            if sensitive_data:
                print_status("CRITICAL", f"Sensitive data leaked at {url}: {', '.join(sensitive_data)}")
            else:
                print_status("INFO", f"No sensitive data found in {url}")

        return {
            "url": url,
            "sensitive_data": get_sensitive_data(detection_result["content"]) if not safe else None,
        }
    return None


async def main(targets, output, concurrency, no_verify, safe):
    """Main asynchronous entry point for scanning."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = [scan_terraform(normalize_url(target), client, safe, semaphore) for target in targets]
        for result in await asyncio.gather(*tasks):
            if result:
                results.append(result)

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=4)
        print_status("INFO", f"Results saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terraform Environment Variable Leak Scanner")
    parser.add_argument("--target", help="URL of the target to scan")
    parser.add_argument("--list", help="File with list of target URLs")
    parser.add_argument("--output", help="File to save JSON output")
    parser.add_argument("--safe", action="store_true", help="Detection only, no sensitive data inspection")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("No targets specified. Use --target or --list.")

    target_list = []
    if args.target:
        target_list.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            target_list.extend(line.strip() for line in f if line.strip())

    asyncio.run(main(
        targets=target_list,
        output=args.output,
        concurrency=args.concurrency,
        no_verify=args.no_verify,
        safe=args.safe,
    ))
