#!/usr/bin/env python3
"""
Terraform State Exposure Scanner
================================
This tool scans for publicly exposed Terraform state files, which frequently contain sensitive
information such as access keys, secret keys, access tokens, and other credentials.

Sensitive data exposed in Terraform state files is a significant security risk, as it can be used
by attackers to gain unauthorized access to cloud resources or further exploit a system.

Features:
  - Detects publicly accessible Terraform state files by looking for expected paths and verifying their availability.
  - Identifies sensitive information in the exposed Terraform state, such as AWS credentials or sensitive variables.
  - Supports active probing to extract and analyze JSON content in Terraform state files.
  - Safe mode for detection-only scans (no active sensitive data inspection).

Potential Risks:
  - Exposed state files often contain sensitive data such as:
      - Provider credentials (e.g., AWS secret keys)
      - SSH keys
      - Other sensitive variables

Usage:
  # Scan a single URL for an exposed Terraform state file
  python terraform_state_exposure_scanner.py --target https://example.com

  # Scan a list of URLs from a file
  python terraform_state_exposure_scanner.py --list urls.txt --output exposed_results.json

  # Safe mode — detection only, without analyzing sensitive data in the exposed state file
  python terraform_state_exposure_scanner.py --list urls.txt --safe

References:
  - https://www.terraform.io/docs/state/index.html
  - https://www.hashicorp.com/security
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urlparse

import httpx

# ── Constants ────────────────────────────────────────────────────────────────

STATE_FILE_PATHS = [
    "/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/.tfstate",
    "/state/terraform.tfstate",
]

SENSITIVE_KEY_PATTERNS = [
    r'"access_key_id"\s*:\s*"(.*?)"',
    r'"secret_access_key"\s*:\s*"(.*?)"',
    r'"client_secret"\s*:\s*"(.*?)"',
    r'"password"\s*:\s*"(.*?)"',
    r'"private_key"\s*:\s*"(.*?)"',
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

# ANSI color codes for CLI output
COLORS = {
    "CRITICAL": "\033[31m",  # Red
    "HIGH": "\033[33m",      # Yellow
    "INFO": "\033[32m",      # Green
    "RESET": "\033[0m",      # Reset
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL starts with http/https and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def print_status(message: str, level: str = "INFO"):
    """Prints a message to the console with color coding."""
    print(f"{COLORS.get(level, '')}[{level}] {message}{COLORS['RESET']}")


async def fetch_url(client: httpx.AsyncClient, url: str):
    """Fetch the content of a URL with a timeout."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.RequestError as e:
        print_status(f"Error fetching {url}: {e}", "HIGH")
        return None


def extract_sensitive_data(content: str):
    """Search for sensitive information patterns in content."""
    extracted_data = []
    for pattern in SENSITIVE_KEY_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            extracted_data.extend(matches)
    return extracted_data


async def check_state_file(client: httpx.AsyncClient, base_url: str, path: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Check a potential Terraform state file at a specific path.
    If found, optionally analyze its content for sensitive data.
    """
    async with semaphore:
        url = base_url + path
        response = await fetch_url(client, url)
        if response and response.status_code == 200 and response.headers.get("Content-Type", "").startswith("application/json"):
            content = response.text
            sensitive_data = []

            if not safe_mode:
                sensitive_data = extract_sensitive_data(content)

            return {
                "path": path,
                "url": url,
                "status": "exposed",
                "sensitive_data": sensitive_data or None,
            }

        return {"path": path, "url": url, "status": "not_exposed"}


# ── Core scanner ────────────────────────────────────────────────────────────

async def scan_target(target: str, safe_mode: bool, semaphore: asyncio.Semaphore):
    """
    Scan a single target for exposed Terraform state files.
    """
    base_url = normalize_url(target)
    result = {"target": base_url, "exposed_files": []}

    print_status(f"Scanning {base_url}...", "INFO")

    async with httpx.AsyncClient(verify=False) as client:
        tasks = [
            check_state_file(client, base_url, path, semaphore, safe_mode)
            for path in STATE_FILE_PATHS
        ]
        responses = await asyncio.gather(*tasks)
        for response in responses:
            if response and response["status"] == "exposed":
                result["exposed_files"].append(response)

    if result["exposed_files"]:
        print_status(f"Exposed state file(s) found for {base_url}!", "CRITICAL")
    else:
        print_status(f"No exposed state files found for {base_url}.", "INFO")

    return result


async def main(args):
    """Main asynchronous entry point for the scanner."""
    semaphore = asyncio.Semaphore(args.concurrency)
    targets = []

    # Load targets from single URL or file
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    results = []
    tasks = [scan_target(target, args.safe, semaphore) for target in targets]
    results = await asyncio.gather(*tasks)

    # Write results to output file
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
            print_status(f"Results saved to {args.output}", "INFO")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Terraform State Exposure Scanner")
    parser.add_argument("--target", type=str, help="Single target URL to scan")
    parser.add_argument("--list", type=str, help="Path to file containing a list of URLs to scan")
    parser.add_argument("--output", type=str, help="Save output to JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no sensitive data analysis)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    # Disable SSL verification globally if --no-verify is set
    if args.no_verify:
        import httpx._config
        httpx._config.DEFAULT_CA_BUNDLE_PATH = None

    asyncio.run(main(args))
