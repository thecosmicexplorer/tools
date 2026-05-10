#!/usr/bin/env python3
"""
Grafana Authentication Bypass Scanner
=====================================
This script scans for potential authentication bypass vulnerabilities related to
misconfigurations or known issues in Grafana, which could allow unauthorized users
to gain access to the Grafana dashboard.

Vulnerability Details:
- Affects Grafana instances with misconfigured or improperly secured authentication
  setups, such as disabled authentication, improperly configured anonymous access,
  or authentication plugins that allow bypasses.
- Impact includes unauthorized access to sensitive dashboards, queries, and
  administrative controls.

Supported Checks:
- Detect Grafana instances and check for the presence of anonymous access
- Identify Grafana version and assess known CVEs affecting the version
- Probes specific CVEs if enabled (requires --safe flag to be disabled)

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target for Grafana authentication bypass issues
  python grafana_auth_bypass_scanner.py --target https://example.com

  # Scan a list of targets
  python grafana_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Perform detection-only scanning (no probing for known exploits)
  python grafana_auth_bypass_scanner.py --list targets.txt --safe

  # Increase concurrency for taking on larger lists of targets
  python grafana_auth_bypass_scanner.py --list targets.txt --concurrency 50

References:
  - https://grafana.com/docs/grafana/latest/auth/overview/
  - https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=grafana
"""

import argparse
import asyncio
import json
import re
from urllib.parse import urljoin

import httpx

# Constants
GRAFANA_FINGERPRINT = ["<title>Grafana</title>", "/public/build/grafana."]  # Signs of a Grafana login page or instance
VULN_MAPPING = {
    # Example: CVE-YYYY-NNNNN: 'Fixed in x.y.z+: Details'
    "CVE-2021-43798": ("8.3.0", "Path traversal allowing unauthorized access to local files."),
    "CVE-2022-21673": ("8.3.0", "Misconfigured cookie password leads to DoS or remote code execution."),
    "CVE-2022-39328": ("Before 9.2.4", "Incorrect access control affecting Azure AD OAuth integration."),
}
REQUEST_TIMEOUT = 8  # Timeout for HTTP requests
SEMAPHORE_LIMIT = 30  # Maximum concurrent requests

# CLI Output Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def normalize_url(url):
    """Ensure the URL has a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def parse_version(version_string):
    """Parse version string into a tuple for comparison."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None

def is_vulnerable(version, affected_version):
    """Determine if the current version is vulnerable to a specific CVE."""
    parsed_version = parse_version(version)
    parsed_affected_version = parse_version(affected_version)
    if parsed_version and parsed_affected_version:
        return parsed_version < parsed_affected_version
    return None

async def detect_grafana(client, url, semaphore):
    """Detect if the target is a Grafana instance."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                if any(fingerprint in response.text for fingerprint in GRAFANA_FINGERPRINT):
                    return True
        except Exception:
            pass
    return False

async def get_grafana_version(client, url, semaphore):
    """Extract version information from a Grafana instance."""
    async with semaphore:
        try:
            response = await client.get(urljoin(url, "/login"), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                match = re.search(r"Grafana\s+v(\d+\.\d+\.\d+)", response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception:
            pass
    return None

async def check_anonymous_access(client, url, semaphore):
    """Check if anonymous access is enabled by querying public API."""
    async with semaphore:
        try:
            response = await client.get(urljoin(url, "/api/org"), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                return True
        except Exception:
            pass
    return False

async def scan_target(client, url, semaphore, safe_mode, no_verify):
    """Perform all checks on a single target."""
    result = {
        "target": url,
        "is_grafana": False,
        "version": None,
        "anonymous_access": False,
        "vulnerabilities": [],
    }

    # Normalize URL and start with Grafana detection
    url = normalize_url(url)
    result["is_grafana"] = await detect_grafana(client, url, semaphore)
    if not result["is_grafana"]:
        return result

    # Extract Grafana version
    version = await get_grafana_version(client, url, semaphore)
    result["version"] = version

    # Check for anonymous access
    if not no_verify:
        result["anonymous_access"] = await check_anonymous_access(client, url, semaphore)

    # Identify vulnerabilities if version is found
    if version and not safe_mode:
        for cve, (affected_version, description) in VULN_MAPPING.items():
            if is_vulnerable(version, affected_version):
                result["vulnerabilities"].append({
                    "cve": cve,
                    "affected_version": affected_version,
                    "description": description,
                })

    return result

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.list:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        else:
            urls = [args.target]

        tasks = [scan_target(client, url, semaphore, args.safe, args.no_verify) for url in urls]
        results = await asyncio.gather(*tasks)

    # Output results
    if args.output:
        with open(args.output, "w") as json_file:
            json.dump(results, json_file, indent=4)
    else:
        for result in results:
            if result["is_grafana"]:
                vuln_status = (
                    f"{RED}CRITICAL{RESET}" if result["vulnerabilities"] else f"{GREEN}INFO{RESET}"
                )
                print(f"[{vuln_status}] Found Grafana Instance: {result['target']}")
                if result["version"]:
                    print(f"  Grafana Version: {result['version']}")
                if result["anonymous_access"]:
                    print(f"  {YELLOW}Anonymous Access: ENABLED{RESET}")
                if result["vulnerabilities"]:
                    print("  Vulnerabilities:")
                    for vuln in result["vulnerabilities"]:
                        print(f"    - {vuln['cve']}: {vuln['description']} (Fixed in {vuln['affected_version']})")
            else:
                print(f"[{GREEN}INFO{RESET}] Not a Grafana instance: {result['target']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Grafana Authentication Bypass Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File containing a list of targets to scan")
    parser.add_argument("--output", type=str, help="File to write JSON output")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, no active probing")
    parser.add_argument("--concurrency", type=int, default=30, help="Limit for concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(f"{RED}[ERROR]{RESET} You must specify either --target or --list.")
        parser.print_help()
        sys.exit(1)

    asyncio.run(main(args))
