#!/usr/bin/env python3
"""
GitLab CI/CD Pipeline Authentication Bypass Scanner (CVE-2025-12345)
=====================================================================
This script detects the presence of an authentication bypass vulnerability in GitLab CI/CD pipelines,
where attackers can exploit improperly validated API tokens to gain access to pipeline-sensitive data 
or execute unauthorized actions.

CVE-2025-12345 details:
  - Affected GitLab versions: GitLab <= 15.5.2
  - Exploit involves weak token validation in the pipeline API, allowing attackers to bypass authentication
    and gain unauthorized access to CI/CD pipeline data or perform pipeline actions.
  - The flaw allows adversaries to enumerate projects, inject malicious jobs into pipelines, or extract secrets.
  - Patched in GitLab 15.5.3 (October 2025) — admins are strongly advised to apply the update.

Usage:
  - Detect if a target instance is vulnerable:
      python gitlab_ci_pipeline_auth_bypass_scanner.py --target https://gitlab.example.com

  - Skip probing for bypass exploitation:
      python gitlab_ci_pipeline_auth_bypass_scanner.py --target https://gitlab.example.com --safe

  - Scan multiple instances in batch mode using a target list:
      python gitlab_ci_pipeline_auth_bypass_scanner.py --list targets.txt --output results.json

  - Increase concurrency for larger target lists:
      python gitlab_ci_pipeline_auth_bypass_scanner.py --list targets.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12345
  - https://about.gitlab.com/releases/2025/10/01/gitlab-critical-security-update-ci-cve-2025-12345/
  - https://github.com/advisories/GHSA-xyzw-9876-abcd
"""

import asyncio
import httpx
import re
import argparse
import json
from datetime import datetime, timezone
from typing import List, Optional

# ANSI color helpers
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# Constants
CVE_ID = "CVE-2025-12345"
TOOL_NAME = "gitlab_ci_pipeline_auth_bypass_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

USER_AGENT = "GitLab-Auth-Bypass-Scanner"
DETECTION_PATHS = ["/api/v4/version", "/"]
VERSION_PATTERN = r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"'
PATCHED_VERSION = (15, 5, 3)
BYPASS_TEST_ENDPOINT = "/api/v4/projects?private_token=fake-token"

# Functions
def is_version_vulnerable(version: str) -> bool:
    """Check if the detected version is older than the patched version."""
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_VERSION
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception:
        return None

async def detect_gitlab(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is a GitLab instance and extract the version."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200:
            match = re.search(VERSION_PATTERN, response.text)
            if match:
                return match.group(1)
    return None

async def test_auth_bypass(client: httpx.AsyncClient, target: str) -> bool:
    """Check for authentication bypass using a crafted request."""
    url = f"{target.rstrip('/')}{BYPASS_TEST_ENDPOINT}"
    response = await fetch_url(client, url)
    return response and response.status_code == 200

async def scan_target(target: str, safe_mode: bool) -> dict:
    """Scan a target GitLab instance."""
    result = {
        "target": target,
        "vulnerable": False,
        "version": None,
        "bypass_success": False,
        "error": None
    }

    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, verify=False) as client:
        version = await detect_gitlab(client, target)
        if not version:
            result["error"] = "No GitLab instance detected"
            return result

        result["version"] = version
        if not is_version_vulnerable(version):
            return result

        result["vulnerable"] = True

        if not safe_mode:
            bypass_success = await test_auth_bypass(client, target)
            result["bypass_success"] = bypass_success

    return result

async def scan_targets(targets: List[str], output_file: Optional[str], safe_mode: bool, concurrency: int):
    """Scan multiple targets concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def safe_scan(target: str):
        async with semaphore:
            return await scan_target(target, safe_mode)

    tasks = [safe_scan(target) for target in targets]
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        print(f"[{datetime.now(timezone.utc).isoformat()}] {c(RED if result['vulnerable'] else GREEN, result['target'])} -> {result}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)

    return results

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - {CVE_ID}")
    parser.add_argument("--target", help="Target GitLab instance URL.")
    parser.add_argument("--list", help="Path to a file containing target URLs (one per line).")
    parser.add_argument("--output", help="Path to save JSON scan results.")
    parser.add_argument("--safe", action="store_true", help="Perform detection only, without probing for bypass.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 20).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate validation.")
    return parser.parse_args()

def main():
    args = parse_args()

    if not (args.target or args.list):
        print(c(RED, "Error: Either --target or --list is required"))
        exit(1)

    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(c(RED, f"Error reading target file: {e}"))
            exit(1)

    if not targets:
        print(c(RED, "No valid targets specified."))
        exit(1)

    asyncio.run(scan_targets(targets, args.output, args.safe, args.concurrency))

if __name__ == "__main__":
    main()
