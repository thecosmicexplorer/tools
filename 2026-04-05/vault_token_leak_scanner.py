#!/usr/bin/env python3
"""
HashiCorp Vault Token Leak Scanner
====================================
Scans for publicly exposed HashiCorp Vault instances and attempts to detect
potential token leaks via misconfigured policies that may expose sensitive secrets.

This tool helps security researchers and red teams identify vulnerable Vault
deployments, highlighting critical exposures that could allow unauthorized access
to secret backends.

Key Features:
  - Fingerprints HashiCorp Vault instances through multiple endpoints
  - Detects and validates the presence of published tokens in unauthenticated paths
  - Optionally attempts safe token leakage verification
  - Reports detailed JSON output

Expected vulnerabilities:
  - Publicly accessible unauthenticated endpoints exposing tokens
  - Weak authentication policies revealing sensitive secrets
  - Version-specific vulnerabilities in Vault's web UI or API

Usage:
  # Scan a single target URL
  python vault_token_leak_scanner.py --target https://vault.example.com

  # Scan multiple targets from a file
  python vault_token_leak_scanner.py --list targets.txt --output results.json

  # Safe mode: Scan without active token verification
  python vault_token_leak_scanner.py --list targets.txt --safe

Dependencies: httpx, asyncio, argparse

References:
  - https://www.vaultproject.io/docs
  - https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX (placeholder for example CVE)
  - https://www.hashicorp.com/security
"""

import asyncio
import json
import re
import argparse
from urllib.parse import urljoin

import httpx

# Fingerprint indicators for identifying Vault instances
VAULT_FINGERPRINTS = [
    "Vault",
    "HashiCorp Vault",
    "ui/assets/images/vault",
    '"initialized":', 
    '"sealed":',
]

# Endpoints commonly used to detect exposed Vault instances
DETECTION_PATHS = [
    "/v1/sys/init",
    "/v1/sys/seal-status",
    "/ui/",
    "/ui/login",
]

VERSION_PATTERNS = [
    r'"vault_version"\s*:\s*"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"',
    r"Vault (\d+\.\d+\.\d+)",
]

VULN_FIXED_VERSION = (1, 13, 0)  # Latest fixed version (example version)
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10
DEFAULT_HEADERS = {"Accept": "application/json"}

# ANSI color codes
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"


def parse_version(version_str: str):
    """
    Parse version string into a (major, minor, patch) tuple.
    """
    try:
        return tuple(map(int, version_str.split('.')))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """
    Check if the version is vulnerable based on the fixed version.
    """
    if not version_tuple:
        return None
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """
    Normalize target URL: ensure it has a schema and no trailing slashes.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


async def detect_vault(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Detect if the target URL is running Vault.
    Returns a dictionary with detection results or None if not detected.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                response = await client.get(urljoin(url, path), timeout=REQUEST_TIMEOUT)
                if any(fp in response.text for fp in VAULT_FINGERPRINTS):
                    version = extract_version(response.text)
                    return {
                        "url": urljoin(url, path),
                        "detected": True,
                        "version": version,
                        "vulnerable": is_vulnerable_version(version),
                        "status_code": response.status_code,
                        "response_length": len(response.text)
                    }
            except httpx.RequestError:
                continue
    return {"url": url, "detected": False}


def extract_version(text: str):
    """
    Extract Vault version from response text using known version patterns.
    """
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return parse_version(match.group("version"))
    return None


async def scan_target(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, safe: bool):
    """
    Conduct the full scan process including detection and token checking.
    """
    result = await detect_vault(client, url, semaphore)
    
    if not result["detected"]:
        return result
    
    if not safe and result["vulnerable"]:
        # Attempt to list tokens if endpoint is exposed (example payload)
        token_endpoint = urljoin(url, "/v1/auth/token/lookup-self")
        try:
            response = await client.get(token_endpoint, timeout=REQUEST_TIMEOUT)
            if "auth" in response.text or "client_token" in response.text:
                result["token_leak"] = True
                result["leak_details"] = response.json()
            else:
                result["token_leak"] = False
        except Exception as e:
            result["token_leak"] = False
    return result


async def scan_targets(targets, concurrency, safe, no_verify):
    """
    Scan a list of target Vault URLs asynchronously.
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify, headers=DEFAULT_HEADERS) as client:
        tasks = [scan_target(client, normalize_url(target), semaphore, safe) for target in targets]
        for future in asyncio.as_completed(tasks):
            results.append(await future)
    return results


def print_results(results):
    """
    Print the results of the scans to the console, with color-coded output.
    """
    for result in results:
        if result["detected"]:
            if result.get("token_leak"):
                print(f"{RED}[CRITICAL] Token Leak Detected: {result['url']}{RESET}")
            elif result["vulnerable"]:
                print(f"{YELLOW}[HIGH] Vulnerable Vault Instance: {result['url']} (Version: {result['version']}){RESET}")
            else:
                print(f"{GREEN}[INFO] Secure Vault Instance: {result['url']} (Version: {result['version']}){RESET}")
        else:
            print(f"{YELLOW}[INFO] Not a Vault instance: {result['url']}{RESET}")


def save_results(results, output_file):
    """
    Save scan results to a JSON file.
    """
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"{GREEN}Results saved to {output_file}{RESET}")


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="HashiCorp Vault Token Leak Scanner")
    parser.add_argument("--target", help="Target Vault URL to scan")
    parser.add_argument("--list", help="File containing a list of Vault URLs to scan")
    parser.add_argument("--output", help="File to save results in JSON format (default: stdout)")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only, no token probes")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency level for async scanning")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (useful for self-signed certs)")
    return parser.parse_args()


def main():
    """
    Main function to handle argument parsing and scanning logic.
    """
    args = parse_args()
    
    if not args.target and not args.list:
        print(f"{RED}[ERROR] You must specify --target or --list{RESET}")
        sys.exit(1)
    
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{RED}[ERROR] Target list file not found: {args.list}{RESET}")
            sys.exit(1)
    
    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe, args.no_verify))
    print_results(results)
    
    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
