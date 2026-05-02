#!/usr/bin/env python3
"""
TeamCity Authentication Bypass Scanner
=======================================
This scanner detects TeamCity CI/CD instances and checks for known authentication bypass vulnerabilities, including improper access control on the REST API endpoints. It provides active probing for vulnerabilities with options for detection-only scanning.

Vulnerabilities targeted:
  - Authentication bypass for REST API endpoints
  - Potential misconfiguration allowing backend access without authentication
  - Version-specific known vulnerabilities in TeamCity

Usage:
------
  # Scan a single target
  python teamcity_auth_bypass_scanner.py --target https://teamcity.example.com

  # Scan a list of targets
  python teamcity_auth_bypass_scanner.py --list targets.txt --output teamcity_findings.json

  # Detection-only scan mode (no active probes)
  python teamcity_auth_bypass_scanner.py --list targets.txt --safe

References:
-----------
  - https://www.jetbrains.com/teamcity/
  - https://nvd.nist.gov/vuln/detail/CVE-2022-41127
  - https://cve.mitre.org/
"""

import asyncio
import json
import re
import httpx
import argparse
from datetime import datetime
from urllib.parse import urljoin

# ── Version details ───────

TEAMCITY_DETECTION_STRINGS = [
    "TeamCity Build Management",
    "<title>TeamCity</title>",
    "/app/login",
    "TeamCity :: Welcome!",
    "/httpAuth",
]

# Paths that fingerprint a TeamCity instance
TEAMCITY_DETECTION_PATHS = [
    "/",
    "/login.html",
    "/httpAuth/app/rest/server",
    "/app/rest/server/",
]

# Version extraction patterns
VERSION_PATTERNS = [
    r"<a[^>]*id=['\"]footerVersion['\"][^>]*>(TeamCity [0-9]+\.[0-9]+\.[0-9]+)</a>",
    r'"version"\s*:\s*"(\d+\.\d+\.\d+)"',
]

VULN_FIXED_VERSION_CVE_2022_41127 = (2022, 10, 2)  # Example: CVE vulnerability fixed in 2022.10.2

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

COLOR_CRITICAL = "\033[91m"
COLOR_HIGH = "\033[93m"
COLOR_INFO = "\033[92m"
COLOR_RESET = "\033[0m"


# ── Helper functions ───────

def parse_version(version_text: str) -> tuple:
    """
    Parse version string and return a tuple of integers.
    """
    try:
        return tuple(map(int, version_text.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple: tuple) -> bool:
    """
    Determine if the version is vulnerable to CVE-2022-41127.
    """
    if version_tuple is None:
        return None
    return version_tuple < VULN_FIXED_VERSION_CVE_2022_41127


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def colorize(text: str, severity: str) -> str:
    """
    Return colorized text for terminal output.
    """
    if severity == "CRITICAL":
        return f"{COLOR_CRITICAL}{text}{COLOR_RESET}"
    elif severity == "HIGH":
        return f"{COLOR_HIGH}{text}{COLOR_RESET}"
    elif severity == "INFO":
        return f"{COLOR_INFO}{text}{COLOR_RESET}"
    return text


# ── Scanner core logic ─────

async def detect_teamcity(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect TeamCity server and extract version details.
    """
    async with semaphore:
        version = None
        detected = False

        for path in TEAMCITY_DETECTION_PATHS:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code < 400:
                    for marker in TEAMCITY_DETECTION_STRINGS:
                        if marker in response.text:
                            detected = True
                            version = parse_version(response.text)
                            break
                if detected:
                    break
            except (httpx.RequestError, asyncio.TimeoutError):
                pass

        return {"url": base_url, "detected": detected, "version": version}


async def probe_auth_bypass(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Probe for authentication bypass by accessing restricted REST API endpoints.
    Returns a dict with vulnerability details.
    """
    async with semaphore:
        try:
            test_endpoint = urljoin(base_url, "/httpAuth/app/rest/users")
            response = await client.get(test_endpoint, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "Content-Type" in response.headers and "application/json" in response.headers["Content-Type"].lower():
                return {"url": base_url, "vulnerable": True, "endpoint": test_endpoint}
        except (httpx.RequestError, asyncio.TimeoutError):
            pass
        return {"url": base_url, "vulnerable": False}


async def scan_target(target: str, safe_mode: bool, semaphore: asyncio.Semaphore, output: list):
    """
    Scan a single target for detection and vulnerabilities.
    """
    async with httpx.AsyncClient(verify=False) as client:
        url = normalize_url(target)

        # Detect TeamCity instance
        detection = await detect_teamcity(client, url, semaphore)
        if not detection["detected"]:
            print(colorize(f"{url} is not a TeamCity instance.", "INFO"))
            return

        version = detection["version"]
        if version:
            vulnerability = is_vulnerable_version(version)
            version_str = '.'.join(map(str, version))
            print(
                f"{colorize(url, 'INFO')} - Detected TeamCity version {version_str}. "
                f"{colorize('Vulnerable!' if vulnerability else 'Secure!', 'HIGH' if vulnerability else 'INFO')}"
            )
        else:
            print(f"{colorize(url, 'INFO')} - Version information could not be determined.")

        output.append(detection)

        # Probe authentication bypass vulnerability if not in safe mode
        if not safe_mode:
            probe_results = await probe_auth_bypass(client, url, semaphore)
            if probe_results["vulnerable"]:
                print(
                    f"{colorize(url, 'CRITICAL')} - Authentication bypass vulnerability "
                    f"detected on {probe_results['endpoint']}!"
                )
            else:
                print(f"{colorize(url, 'INFO')} - No authentication bypass detected.")
            output.append(probe_results)


async def main(args):
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    semaphore = asyncio.Semaphore(args.concurrency)
    output_data = []

    tasks = [scan_target(target, args.safe, semaphore, output_data) for target in targets]
    await asyncio.gather(*tasks)

    # Output results to JSON file if `--output` is provided
    if args.output:
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TeamCity Authentication Bypass Vulnerability Scanner")
    parser.add_argument("--target", help="Target URL to scan.")
    parser.add_argument("--list", help="File containing a list of URLs to scan.")
    parser.add_argument("--output", help="Output findings to JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection only; no probes or active testing.")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")
    args = parser.parse_args()

    asyncio.run(main(args))
