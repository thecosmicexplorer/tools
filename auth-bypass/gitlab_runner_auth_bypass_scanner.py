#!/usr/bin/env python3
"""
GitLab Runner Authentication Bypass Scanner (CVE-2026-78901)
============================================================
This script identifies GitLab Runner instances vulnerable to an authentication bypass
(CVE-2026-78901, CVSS 9.6). The vulnerability allows attackers to interact with
GitLab Runner APIs without proper authentication, potentially exposing sensitive
data or enabling privilege escalation.

CVE-2026-78901 details:
  - Affected versions: GitLab Runner < 15.17.0
  - Vulnerability: Missing or improper authentication checks on certain runner endpoints.
  - Impact: Unauthorized API access, which may include CI/CD pipeline configuration, 
    tokens, and logs, leading to sensitive data exposure or privilege escalation.
  - Patch: Fixed in GitLab Runner 15.17.0 (June 2026).

Usage:
  - Single instance scan:
      python gitlab_runner_auth_bypass_scanner.py --target http://runner.example.com:8080

  - Batch mode scan:
      python gitlab_runner_auth_bypass_scanner.py --list runners.txt --output results.json

  - Run detection-only mode:
      python gitlab_runner_auth_bypass_scanner.py --target http://runner.example.com:8080 --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78901
  - https://gitlab.com/gitlab-org/security/-/issues/12345
"""

import asyncio
import json
import re
from argparse import ArgumentParser
from datetime import datetime
from typing import List, Optional, Dict

import httpx

# ── ANSI Color Definitions ───────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

def colorize(text: str, color: str) -> str:
    """Apply ANSI color to the text."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID          = "CVE-2026-78901"
TOOL_NAME       = "gitlab_runner_auth_bypass_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

# Known paths to test for the vulnerability
DETECTION_PATHS = [
    "/api/v4/runners",
    "/api/v4/jobs",
    "/api/v4/runners/all"
]

# Response headers or content patterns to identify GitLab Runner
GITLAB_RUNNER_FINGERPRINTS = [
    "GitLab-Runner",
    "content-type: application/json",
]

VERSION_REGEX = r"GitLab-Runner/(\d+\.\d+\.\d+)"
PATCHED_VERSION = (15, 17, 0)  # CVE is patched in 15.17.0

# ── Helper Functions ──────────────────────────────────────────────────────────

def parse_cli_args() -> ArgumentParser:
    """Define and parse command-line arguments."""
    parser = ArgumentParser(description="GitLab Runner Authentication Bypass Scanner (CVE-2026-78901)")
    parser.add_argument("--target", type=str, help="Target URL of a GitLab Runner instance.")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs.")
    parser.add_argument("--output", type=str, help="File to save JSON scan results.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no active probing).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level for scanning.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")
    return parser

def parse_version(version_str: str) -> Optional[tuple]:
    """Convert a version string (e.g., '15.16.1') to a tuple of integers."""
    try:
        return tuple(map(int, version_str.split(".")))
    except ValueError:
        return None

def is_version_vulnerable(version: str) -> bool:
    """Check if the provided version is vulnerable."""
    version_tuple = parse_version(version)
    if not version_tuple:
        return False
    return version_tuple < PATCHED_VERSION

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with exception handling."""
    try:
        return await client.get(url, timeout=REQUEST_TIMEOUT)
    except (httpx.RequestError, httpx.HTTPStatusError):
        return None

async def detect_gitlab_runner(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is running a GitLab Runner, and extract its version."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        
        if response and response.status_code in {200, 401, 403}:
            for fingerprint in GITLAB_RUNNER_FINGERPRINTS:
                if fingerprint.lower() in (response.headers.get("server", "")).lower() or response.text.lower():
                    match = re.search(VERSION_REGEX, response.headers.get("server", ""))
                    if match:
                        return match.group(1)
    return None

async def probe_bypass(client: httpx.AsyncClient, target: str) -> Dict:
    """Test the authentication bypass vulnerability on the target."""
    results = {"vulnerable": False, "details": None}
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200:
            results["vulnerable"] = True
            results["details"] = url
            break
    return results

async def scan_target(target: str, semaphore: asyncio.Semaphore, args) -> Dict:
    """Scan a single target for the vulnerability."""
    result = {
        "target": target,
        "vulnerable": False,
        "version": None,
        "details": None,
    }
    async with semaphore:
        async with httpx.AsyncClient(verify=not args.no_verify) as client:
            version = await detect_gitlab_runner(client, target)
            result["version"] = version
            
            if version and is_version_vulnerable(version):
                if not args.safe:
                    probe_results = await probe_bypass(client, target)
                    result.update(probe_results)
                else:
                    result["vulnerable"] = True
    return result

async def scan_targets(targets: List[str], args) -> List[Dict]:
    """Scan multiple targets concurrently."""
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(target, semaphore, args) for target in targets]
    return await asyncio.gather(*tasks)

def load_targets_from_file(file_path: str) -> List[str]:
    """Load target URLs from a file."""
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

# ── Main Execution ────────────────────────────────────────────────────────────

def main():
    args = parse_cli_args().parse_args()

    if not (args.target or args.list):
        print(colorize("Error: You must provide either --target or --list.", RED))
        return

    if args.target and args.list:
        print(colorize("Error: Specify only one of --target or --list.", RED))
        return

    targets = [args.target] if args.target else load_targets_from_file(args.list)

    print(colorize(f"Scanning {len(targets)} target(s)...", YELLOW))
    results = asyncio.run(scan_targets(targets, args))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(colorize(f"Results saved to {args.output}", GREEN))
    else:
        for result in results:
            status = colorize("VULNERABLE", RED) if result["vulnerable"] else colorize("NOT VULNERABLE", GREEN)
            print(f"{result['target']}: {status}")
            if result["details"]:
                print(f"  Details: {result['details']}")

if __name__ == "__main__":
    main()
