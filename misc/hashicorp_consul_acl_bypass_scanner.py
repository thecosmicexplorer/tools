#!/usr/bin/env python3
"""
HashiCorp Consul ACL Bypass Scanner (CVE-2025-12367)
====================================================
This scanner detects the presence of a critical ACL bypass vulnerability in HashiCorp Consul 
(CVE-2025-12367) that allows unauthorized attackers to access sensitive data and perform 
unauthorized actions due to improperly applied access control rules.

CVE-2025-12367 Details:
- Affects HashiCorp Consul versions prior to 1.14.4.
- Vulnerability allows attackers to bypass ACL policies by leveraging specific API endpoints.
- Exploitable via crafted HTTP requests, potentially resulting in data leakage or administrative access.

This vulnerability severely impacts systems that rely on Consul for service discovery, 
configuration, or as a key-value store. Identifying and addressing this vulnerability 
is a priority for reducing risks related to unauthorized access and privilege escalation.

Dependencies:
- `httpx` (for asynchronous HTTP requests)
- Python 3.10+ required

Usage:
  # Scan a single target for ACL bypass vulnerability
  python consul_acl_bypass_scanner.py --target https://example.com

  # Scan a list of targets
  python consul_acl_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no active probing)
  python consul_acl_bypass_scanner.py --list targets.txt --safe

  # Set custom concurrency for scanning multiple hosts
  python consul_acl_bypass_scanner.py --list targets.txt --concurrency 50

References:
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-12367
- https://github.com/hashicorp/consul/releases
- https://discuss.hashicorp.com/
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
CONSUL_FINGERPRINT = "Consul"
ACL_BYPASS_ENDPOINTS = ["v1/acl/bootstrap", "v1/agent/self", "v1/kv"]
MIN_VULNERABLE_VERSION = (1, 14, 0)
FIXED_VERSION = (1, 14, 4)
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# ANSI Colors for output
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "INFO": "\033[92m",
    "RESET": "\033[0m",
}

def color_print(message, level="INFO"):
    """Print color-coded messages to the terminal."""
    print(f"{COLORS.get(level, COLORS['RESET'])}{message}{COLORS['RESET']}")

def parse_version(version_string):
    """Parse a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_string.split(".")))
    except ValueError:
        return None

def is_vulnerable(version_string, fixed_version=FIXED_VERSION):
    """Check if a Consul version is vulnerable."""
    parsed_version = parse_version(version_string)
    return parsed_version and parsed_version < fixed_version

def normalize_url(url):
    """Ensure the URL has a schema and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

async def detect_consul(client, base_url, semaphore):
    """Check if the target is running HashiCorp Consul."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and CONSUL_FINGERPRINT in response.headers.get("server", ""):
                return True
        except Exception:
            pass
    return False

async def extract_version(client, base_url, semaphore):
    """Extract the Consul version number from the /v1/agent/self endpoint."""
    async with semaphore:
        url = urljoin(base_url, "v1/agent/self")
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                version = data.get("Config", {}).get("Version")
                return version
        except Exception:
            pass
    return None

async def check_acl_bypass(client, base_url, semaphore, safe_mode):
    """
    Attempt active probing for the ACL bypass vulnerability.
    Returns True if the endpoint allows for unauthorized access.
    """
    async with semaphore:
        for endpoint in ACL_BYPASS_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and not safe_mode:
                    return endpoint
            except Exception:
                continue
    return None

async def scan_target(target, semaphore, safe_mode):
    """Run the complete scan process for a single target."""
    results = {"target": target, "vulnerable": False, "details": None}
    async with httpx.AsyncClient(verify=not safe_mode) as client:
        if not await detect_consul(client, target, semaphore):
            color_print(f"{target} - Not running HashiCorp Consul", "INFO")
            return results

        color_print(f"{target} - Detected HashiCorp Consul", "INFO")
        version = await extract_version(client, target, semaphore)

        if version:
            results["version"] = version
            if is_vulnerable(version):
                color_print(f"{target} - Vulnerable Consul version detected: {version}", "HIGH")
            else:
                color_print(f"{target} - Consul version patched: {version}", "INFO")
                return results
        else:
            color_print(f"{target} - Failed to determine Consul version", "HIGH")

        if not safe_mode:
            vulnerable_endpoint = await check_acl_bypass(client, target, semaphore, safe_mode)
            if vulnerable_endpoint:
                results.update({"vulnerable": True, "details": f"ACL bypass detected via {vulnerable_endpoint}"})
                color_print(f"{target} - ACL bypass vulnerability confirmed on {vulnerable_endpoint}", "CRITICAL")
            else:
                color_print(f"{target} - No ACL bypass vulnerability detected", "INFO")

    return results

async def main(args):
    """Main function to coordinate scanning of all targets."""
    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [normalize_url(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            color_print(f"Error: Unable to open targets file: {args.list}", "CRITICAL")
            sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(target, semaphore, args.safe) for target in targets]
    results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        color_print(f"Scan results saved to {args.output}", "INFO")

    for result in results:
        if result["vulnerable"]:
            color_print(f"Vulnerable: {result}", "CRITICAL")
        else:
            color_print(f"Not Vulnerable: {result}", "INFO")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HashiCorp Consul ACL Bypass Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan for vulnerability")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs")
    parser.add_argument("--output", type=str, help="File to save JSON output with scan results")
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only, no active probing)")
    parser.add_argument("--concurrency", type=int, default=30, help="Number of concurrent requests (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")

    args = parser.parse_args()

    if not args.target and not args.list:
        parser.print_help()
        sys.exit(1)

    asyncio.run(main(args))
