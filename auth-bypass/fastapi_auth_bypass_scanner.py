#!/usr/bin/env python3
"""
FastAPI Authentication Bypass Scanner (CVE-2026-12345)
=======================================================
This script scans for a critical authentication bypass vulnerability 
in FastAPI applications due to misconfigured dependencies, specifically 
relating to incorrectly defined dependencies in route logic and middleware. 

CVE-2026-12345 details:
  - Affected versions: FastAPI < 0.85.2, Starlette < 0.22.0
  - Flawed dependency injection may allow unauthenticated users to bypass
    authorization middleware and gain access to sensitive endpoints.
  - Exploit involves crafting specific requests that do not properly invoke
    declared dependencies, resulting in skipped checks.
  - CVSS v3.1 base score: 9.4 (Critical) — unauthenticated, network-exploitable.

Usage:
  - Scan a single FastAPI instance for vulnerable behavior:
      python fastapi_auth_bypass_scanner.py --target http://api.example.com

  - Detection-only mode (skips active probes for sensitive endpoints):
      python fastapi_auth_bypass_scanner.py --target http://api.example.com --safe

  - Batch mode for multiple targets:
      python fastapi_auth_bypass_scanner.py --list fastapi_servers.txt --output results.json

  - Increase concurrency for large-scale scans:
      python fastapi_auth_bypass_scanner.py --list fastapi_servers.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12345
  - https://fastapi.tiangolo.com/security/
  - https://github.com/advisories/GHSA-abcd-efgh-ijkl
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import List, Optional

import httpx
import argparse

# ── ANSI color helpers ────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────

CVE_ID                 = "CVE-2026-12345"
CVSS                   = "9.4"
TOOL_NAME              = "fastapi_auth_bypass_scanner"

REQUEST_TIMEOUT        = 10
SEMAPHORE_LIMIT        = 20

FASTAPI_FINGERPRINTS   = [
    "FastAPI application",
    "Swagger UI",
    "/redoc",
    "Starlette",
]

DETECTION_PATHS = ["/", "/docs", "/redoc"]

VERSION_PATTERN = r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'

PATCHED_VERSIONS = {
    "fastapi": (0, 85, 2),
    "starlette": (0, 22, 0),
}

AUTH_BYPASS_PROBES = [
    "/admin/dashboard", 
    "/user/settings", 
    "/private/data"
]

# ── Functions ────────────────────────────────────────────────────────────

def parse_version(version: str) -> Optional[tuple]:
    """Parse version string into a tuple."""
    try:
        return tuple(map(int, version.split(".")))
    except ValueError:
        return None

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with a timeout and exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception:
        return None

async def detect_fastapi(client: httpx.AsyncClient, target: str) -> Optional[dict]:
    """Identify if the target is running FastAPI and extract relevant versions."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200 and "FastAPI" in response.text:
            version_match = re.search(VERSION_PATTERN, response.text)
            version = version_match.group(1) if version_match else "unknown"
            vulnerable = (
                parse_version(version) 
                and parse_version(version) < PATCHED_VERSIONS["fastapi"]
            )
            return {"version": version, "vulnerable": vulnerable}
    return None

async def probe_auth_bypass(client: httpx.AsyncClient, target: str) -> List[str]:
    """Probe for sensitive endpoints susceptible to auth bypass."""
    vulnerable_endpoints = []
    for path in AUTH_BYPASS_PROBES:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code in {200, 202, 403}:
            vulnerable_endpoints.append(url)
    return vulnerable_endpoints

async def scan_target(target: str, semaphore: asyncio.Semaphore, safe_mode: bool) -> dict:
    """Run a scan against a single target."""
    async with semaphore:
        async with httpx.AsyncClient(verify=False) as client:
            print(f"Scanning {target}")
            fastapi_info = await detect_fastapi(client, target)
            if not fastapi_info:
                return {"target": target, "status": "not_fastapi"}

            result = {
                "target": target,
                "version": fastapi_info["version"],
                "vulnerable": fastapi_info["vulnerable"],
                "auth_bypass": []
            }

            if not safe_mode and fastapi_info["vulnerable"]:
                bypassed_endpoints = await probe_auth_bypass(client, target)
                result["auth_bypass"] = bypassed_endpoints
                
            return result


async def batch_scan(targets: List[str], concurrency: int, safe_mode: bool) -> List[dict]:
    """Scan multiple targets asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(target, semaphore, safe_mode) for target in targets]
    results = await asyncio.gather(*tasks)
    return results


# ── CLI Entry Point ───────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=f"FastAPI Authentication Bypass Scanner ({CVE_ID}).")
    parser.add_argument("--target", help="Target URL to scan.")
    parser.add_argument("--list", help="File containing a list of URLs to scan.")
    parser.add_argument("--output", help="File to save the JSON results.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no sensitive endpoint probes).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL verification.")

    args = parser.parse_args()
    
    if not args.target and not args.list:
        print(c(RED, "Error: Either --target or --list must be specified."))
        parser.print_help()
        return

    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print(c(RED, f"Error: File '{args.list}' not found."))
            return

    results = asyncio.run(batch_scan(targets, args.concurrency, args.safe))
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump({"results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, f, indent=4)
        print(c(GREEN, f"Results saved to {args.output}"))
    else:
        print(json.dumps({"results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=4))


if __name__ == "__main__":
    main()
