#!/usr/bin/env python3
"""
Grafana Server-Side Request Forgery (SSRF) Scanner
==================================================
This script is designed to detect and exploit known Server-Side Request Forgery (SSRF) vulnerabilities in Grafana. 
SSRF vulnerabilities in older versions of Grafana may allow attackers to make unauthorized requests to internal 
services, potentially accessing sensitive information or escalating their privileges.

CVE examples:
  - CVE-2021-43798: Path Traversal vulnerability in Grafana <8.3.0
  - CVE-2019-15043: SSRF vulnerability on snapshot endpoints in Grafana <6.3.6
  - ...other related vulnerabilities

Features:
  - Detects Grafana instances and confirms version information
  - Supports active SSRF probing (disabled in --safe mode)
  - Exports results as both JSON and terminal output for reporting

Usage:
  # Scan a single target
  python grafana_ssrf_scanner.py --target https://grafana.example.com

  # Scan multiple targets
  python grafana_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection-only scans
  python grafana_ssrf_scanner.py --list targets.txt --safe

References:
  - https://cve.mitre.org/
  - https://grafana.com/docs/grafana/latest/release-notes/
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urljoin

import httpx

# ── Configuration Parameters ─────────────────────────────────────────────────

GRAFANA_FINGERPRINTS = [
    '<title>Grafana</title>',
    '"appName":"grafana"',
    '/public/build/grafana.',
]

DETECTION_PATHS = ["/", "/login", "/public/dashboards/home", "/api/health"]
VERSION_REGEX = r'(\d+\.\d+\.\d+)'

VULNERABLE_VERSIONS = [
    ((6, 0, 0), (6, 3, 5)),  # CVE-2019-15043
    ((8, 0, 0), (8, 2, 9)),  # CVE-2021-43798
]

SSRF_PROBE_PATHS = [
    "/api/datasources/proxy/{datasource_id}/",
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ── Color Coding for Terminal Output ────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ── Helper Functions ────────────────────────────────────────────────────────

def parse_version(version_string: str):
    """Parse a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None


def is_version_in_range(version, range_start, range_end):
    """Check if a version is within a given (inclusive) range."""
    return range_start <= version <= range_end


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme and is properly formed."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


# ── Core Scanner ────────────────────────────────────────────────────────────

async def detect_grafana(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if a URL is running a vulnerable version of Grafana.
    Returns a dictionary with detection details.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version_str = None

        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    for marker in GRAFANA_FINGERPRINTS:
                        if marker in response.text:
                            detected = True
                            version_match = re.search(VERSION_REGEX, response.text)
                            if version_match:
                                raw_version_str = version_match.group(1)
                                version = parse_version(raw_version_str)
                            break
                if detected:
                    break
            except httpx.RequestError:
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version_str,
            "vulnerable": (
                any(
                    is_version_in_range(version, start, end)
                    for start, end in VULNERABLE_VERSIONS
                )
                if version
                else None
            ),
        }


async def probe_ssrf(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt SSRF probes on a Grafana instance to confirm active vulnerability.
    Returns details of successful exploitation, if any.
    """
    async with semaphore:
        for path in SSRF_PROBE_PATHS:
            target_url = urljoin(base_url, path.format(datasource_id=1))
            try:
                response = await client.get(target_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and "some_internals" in response.text.lower():
                    return {"url": target_url, "exploitable": True}
            except httpx.RequestError:
                pass
        return {"exploitable": False}


async def scan_target(target, semaphore, safe_mode):
    """Scan a single target for Grafana SSRF vulnerabilities."""
    base_url = normalize_url(target)
    async with httpx.AsyncClient(verify=False) as client:
        detection_result = await detect_grafana(client, base_url, semaphore)

        if detection_result["detected"] and detection_result["vulnerable"] and not safe_mode:
            # Perform active probing if not in safe mode
            ssrf_result = await probe_ssrf(client, base_url, semaphore)
            detection_result.update(ssrf_result)

        return detection_result


async def main(targets, concurrency, safe_mode, output_file, no_verify):
    """Main function to execute the scan."""
    semaphore = asyncio.Semaphore(concurrency)
    scan_tasks = []

    for target in targets:
        scan_tasks.append(scan_target(target, semaphore, safe_mode))

    scan_results = await asyncio.gather(*scan_tasks, return_exceptions=False)

    # Output results
    for result in scan_results:
        if result["detected"]:
            if result["vulnerable"]:
                message = (f"{RED}CRITICAL: {result['url']} is running a vulnerable version of Grafana "
                           f"({result['version']}).")
                if result.get("exploitable"):
                    message += " Exploitation confirmed!"
            else:
                message = f"{YELLOW}INFO: {result['url']} is running Grafana but is patched ({result['version']})."
        else:
            message = f"{GREEN}OK: {result['url']} is not running Grafana."

        print(message + RESET)

    # Optional JSON output
    if output_file:
        with open(output_file, "w") as f:
            json.dump(scan_results, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Grafana SSRF Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File with list of target URLs (one per line)")
    parser.add_argument("--output", type=str, help="File to save JSON output")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no probing)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    # Load targets from file if specified
    targets = []
    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print("Error: You must specify either --target or --list")
        parser.print_help()
        exit(1)

    # Run the scanner
    asyncio.run(
        main(
            targets=targets,
            concurrency=args.concurrency,
            safe_mode=args.safe,
            output_file=args.output,
            no_verify=args.no_verify,
        )
    )
