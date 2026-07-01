#!/usr/bin/env python3
"""
Azure Function Key Leak Scanner
================================
Scans for Azure Function apps that are misconfigured to allow anonymous access, exposing potentially sensitive function keys. Identified keys can be used to invoke Azure Functions or abuse API endpoints.

Details:
  - Azure Function apps provide serverless compute where HTTP-triggered functions can process requests.
  - Each function has associated keys (host/function-level) to restrict access.
  - Misconfigurations or intentional setups can leave these keys exposed to unauthenticated access via default endpoints.
  - If keys are exposed, they can be used to invoke functions or further abuse cloud resources.

Impact:
  - Unauthorized execution of Azure Functions.
  - Potential for privilege escalation or misuse of cloud resources.
  - CVSS varies depending on function configurations and privileges.

Usage:
  # Scan a single Function App for key exposures
  python azure_function_key_leak_scanner.py --target https://my-function-app.azurewebsites.net

  # Detection only — no key enumeration
  python azure_function_key_leak_scanner.py --target https://my-function-app.azurewebsites.net --safe

  # Scan a list of targets from a file
  python azure_function_key_leak_scanner.py --list targets.txt --output findings.json

  # Adjust concurrency and disable SSL verification for bulk scans
  python azure_function_key_leak_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts
  - https://docs.microsoft.com/en-us/azure/app-service/manage-locks
"""

import aiofiles
import argparse
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "azure_function_key_leak_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Common Function App paths for detection and key extraction
DETECTION_PATHS = [
    "/",
    "/api/",
    "/admin/host/status"
]
KEY_ENDPOINTS = [
    "/admin/functions/{function}/keys",  # Specific function-level keys
    "/admin/host/keys",                 # Host-level keys
]

HEADERS = {
    "User-Agent": f"{TOOL_NAME}/1.0 (security scanner)"
}

# ── Utilities ────────────────────────────────────────────────────────────────

def parse_version(version: str) -> tuple:
    """Convert string 'major.minor.patch' version to a tuple of ints."""
    return tuple(map(int, version.split(".")))

def is_version_vulnerable(version: str, safe_version: str) -> bool:
    """Compare versions to determine if 'version' is insecure."""
    return parse_version(version) < parse_version(safe_version)

# ── Async Functions ──────────────────────────────────────────────────────────

async def fetch(session: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL and handle exceptions."""
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        print(c(RED, f"[ERROR] {url} - {str(e)}"))
        return None

async def scan_single_target(session: httpx.AsyncClient, target: str, safe: bool = False) -> dict:
    """Scan a single Azure Function App for key leaks."""
    result = {"target": target, "vulnerabilities": [], "info": []}
    
    # Initial detection
    detected = False
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch(session, url)
        if response:
            if "Azure-Functions" in response.headers.get("Server", ""):
                detected = True
                result["info"].append({"path": url, "status_code": response.status_code})
                break
    
    if not detected:
        print(c(YELLOW, f"[INFO] {target} - Not an Azure Function App"))
        result["info"].append({"error": "Not an Azure Function App"})
        return result

    print(c(GREEN, f"[INFO] {target} - Detected as an Azure Function App"))

    if safe:
        return result  # Detection-only scan

    # Active probing
    for endpoint in KEY_ENDPOINTS:
        probe_url = f"{target.rstrip('/')}{endpoint.format(function='testfunction')}"
        response = await fetch(session, probe_url)
        if response and response.status_code == 200:
            try:
                keys = response.json()
                result["vulnerabilities"].append({
                    "endpoint": probe_url,
                    "keys": keys
                })
                print(c(RED, f"[CRITICAL] {target} - Keys exposed at {probe_url}"))
            except json.JSONDecodeError:
                print(c(YELLOW, f"[WARN] {target} - Non-JSON response at {probe_url}"))
    return result

async def scan_multiple_targets(targets: list, output: Optional[str], safe: bool, concurrency: int, verify: bool):
    """Scan multiple targets concurrently; save results if output specified."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async with httpx.AsyncClient(verify=verify, timeout=REQUEST_TIMEOUT) as session:
        async def bounded_scan(target):
            async with semaphore:
                result = await scan_single_target(session, target, safe)
                results.append(result)
        
        await asyncio.gather(*(bounded_scan(target) for target in targets))
    
    if output:
        async with aiofiles.open(output, "w") as f:
            await f.write(json.dumps(results, indent=2))

    return results

# ── Main Program ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Azure Function Key Leak Scanner")
    parser.add_argument("--target", help="Target URL of the Azure Function App")
    parser.add_argument("--list", help="Path to file containing list of target URLs")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no key probes)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency limit for bulk scans")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: Provide either --target or --list argument"))
        sys.exit(1)

    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(c(RED, f"Error: File not found - {args.list}"))
            sys.exit(1)
    
    print(c(BOLD, f"*** Starting {TOOL_NAME} ***"))
    start_time = datetime.now(timezone.utc)

    asyncio.run(scan_multiple_targets(
        targets=targets,
        output=args.output,
        safe=args.safe,
        concurrency=args.concurrency,
        verify=not args.no_verify
    ))
    
    duration = datetime.now(timezone.utc) - start_time
    print(c(BOLD, f"*** Scan completed in {duration.total_seconds():.2f} seconds ***"))

if __name__ == "__main__":
    main()
