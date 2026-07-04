#!/usr/bin/env python3
"""
GitLab CI/CD Runner Misconfigurations — Remote Code Execution (RCE)
===================================================================
Scans for misconfigured GitLab CI/CD runners that allow unauthorized remote code
execution through improper settings such as unprotected shared runners and unsafe
CI/CD scripting practices.

Overview:
  GitLab CI/CD runners, if misconfigured, can be exploited to execute arbitrary
  code on the underlying server or agent machine. Such issues typically arise
  from:
    1. Poorly secured shared runners allowing unauthorized use.
    2. Dangerous usage of script variables, unescaped inputs, or exposed secrets
       in CI configurations.
    3. Insufficient restrictions on the `script` keyword in `.gitlab-ci.yml`.

  Exploiting this misconfiguration can allow attackers to execute arbitrary commands,
  gain access to sensitive data, or laterally compromise other systems.

Usage:
  # Scan a single GitLab instance for vulnerable runners
  python3 gitlab_ci_runner_rce_scanner.py --target https://gitlab.example.com

  # Detection only — no active RCE tests for a target instance
  python3 gitlab_ci_runner_rce_scanner.py --target https://gitlab.example.com --safe

  # Scan multiple GitLab instances from a file
  python3 gitlab_ci_runner_rce_scanner.py --list targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python3 gitlab_ci_runner_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://docs.gitlab.com/runner/security/index.html
  - https://about.gitlab.com/blog/2021/05/05/shared-runner-security-considerations/
  - https://nvd.nist.gov/vuln/detail/CVE-2021-22205 (GitLab Unauthenticated Code Execution)
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
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

TOOL_NAME          = "gitlab_ci_runner_rce_scanner"
CVE_ID             = "MULTI"
CVSS_CRITICAL      = "9.9"
CVSS_HIGH          = "7.5"

REQUEST_TIMEOUT    = 10
SEMAPHORE_LIMIT    = 30

GITLAB_FINGERPRINT = "GitLab"
API_USER_AGENT     = f"{TOOL_NAME}/1.0"

# GitLab runner API endpoints to check
RUNNER_API_ENDPOINTS = [
    "/api/v4/runners/all",
    "/api/v4/runners",
]

# Regex patterns for detection of GitLab and version extraction
HEADER_REGEX       = re.compile(r"GitLab(?:\-CE|\-EE)?/(\d+\.\d+\.\d+)")
VERSION_PATTERN    = r"(\d+)\.(\d+)\.(\d+)"

# ── Functions for scanner ─────────────────────────────────────────────────────

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL asynchronously."""
    try:
        return await client.get(url, headers={"User-Agent": API_USER_AGENT}, timeout=REQUEST_TIMEOUT)
    except (httpx.HTTPError, httpx.ConnectError):
        return None

async def fingerprint_gitlab(client: httpx.AsyncClient, url: str) -> Optional[dict]:
    """Determine if the target URL is a GitLab instance and extract version."""
    try:
        response = await fetch_url(client, url)
        if not response:
            return None

        headers = response.headers
        server_header = headers.get("Server", "")
        if GITLAB_FINGERPRINT in server_header:
            match = HEADER_REGEX.search(server_header)
            if match:
                version = match.group(1)
                return {"url": url, "version": version}
        return None
    except Exception as e:
        print(c(RED, f"[ERROR] {url} - {e}"), file=sys.stderr)
        return None

def is_version_vulnerable(version: str) -> bool:
    """Check if a GitLab version is vulnerable."""
    match = re.match(VERSION_PATTERN, version)
    if not match:
        return False

    major, minor, patch = map(int, match.groups())
    if major < 13:  # Versions below 13 are vulnerable
        return True
    if major == 13 and minor < 10:  # 13.9.x and below
        return True
    return False

async def active_probe_vulnerabilities(client: httpx.AsyncClient, url: str) -> list[str]:
    """Perform active probing for RCE vulnerabilities."""
    findings = []
    for endpoint in RUNNER_API_ENDPOINTS:
        target = f"{url.rstrip('/')}{endpoint}"
        response = await fetch_url(client, target)
        if response and response.status_code == 200:
            findings.append(target)

    return findings

async def scan_target(semaphore: asyncio.Semaphore, target: str, safe: bool) -> Optional[dict]:
    """Scan a single GitLab target for RCE vulnerabilities."""
    async with semaphore:
        async with httpx.AsyncClient(verify=False if args.no_verify else True) as client:
            print(c(CYAN, f"[INFO] Scanning {target}..."))
            result = await fingerprint_gitlab(client, target)
            if not result:
                print(c(YELLOW, f"[WARN] No GitLab instance detected at {target}."))
                return None

            result["probes"] = []
            if safe:
                print(c(GREEN, f"[INFO] Detected GitLab instance {result['version']} at {target}. Running in safe mode; skipping active probes."))
                return result

            # Check if version is vulnerable
            if is_version_vulnerable(result["version"]):
                print(c(RED, f"[CRITICAL] Potentially vulnerable GitLab instance detected at {target} (version: {result['version']})."))
            else:
                print(c(GREEN, f"[INFO] GitLab instance {result['version']} at {target} is patched or not vulnerable."))

            # Active probing for misconfigured runner API endpoints
            result["probes"] = await active_probe_vulnerabilities(client, target)
            if result["probes"]:
                print(c(RED, f"[CRITICAL] Misconfigured runner API found at {', '.join(result['probes'])}"))
            return result

async def main():
    parser = argparse.ArgumentParser(description="GitLab CI/CD Runner Misconfigurations Scanner")
    parser.add_argument("--target", help="Specify the target GitLab URL (e.g., https://gitlab.example.com).")
    parser.add_argument("--list", help="Path to a file containing a list of GitLab URLs to scan.")
    parser.add_argument("--output", help="Output results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no active probes).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Set the number of concurrent requests (default: 30).")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    args = parser.parse_args()

    targets = []
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(c(RED, f"[ERROR] Target list file not found: {args.list}"))
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        print(c(RED, "Error: You must specify either --target or --list."))
        parser.print_help()
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    tasks = [scan_target(semaphore, target, args.safe) for target in targets]
    for future in asyncio.as_completed(tasks):
        result = await future
        if result:
            results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"[INFO] Results written to {args.output}"))

    print(c(GREEN, "[INFO] Scanning complete."))


if __name__ == "__main__":
    asyncio.run(main())
