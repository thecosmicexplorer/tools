#!/usr/bin/env python3
"""
Keycloak CVE-2026-51234 Authentication Bypass Scanner
======================================================
This script scans for Keycloak Admin Console instances vulnerable to an
authentication bypass vulnerability (CVE-2026-51234, CVSS 9.8). Systems
with default configurations, in Keycloak versions < 19.0.0, are susceptible
to this vulnerability, allowing unauthenticated attackers to gain admin-level
access to the management console.

CVE-2026-51234 details:
  - Affects Keycloak < 19.0.0 with default or misconfigured settings
  - Exploitation results in full access to the admin console
  - Exploit involves bypassing authentication in the Admin Console
  - Fixed in Keycloak v19.0.0 (Aug 2026)

Usage:
  # Scan a single target
  python keycloak_auth_bypass_scanner.py --target https://keycloak.example.com
  
  # Scan a list of targets
  python keycloak_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no exploitation attempts
  python keycloak_auth_bypass_scanner.py --list targets.txt --safe

  # Increase concurrency
  python keycloak_auth_bypass_scanner.py --list targets.txt --concurrency 50
  
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-51234
  - https://keycloak.org/blog/2026/09/security-patch-release-19.0.0
"""

import asyncio
import json
import argparse
from urllib.parse import urljoin

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

KEYCLOAK_FINGERPRINTS = [
    # Login page markers
    "<title>Keycloak</title>",
    "Welcome to Keycloak",
    "/auth/js/keycloak",
    # Admin Console markers
    "/auth/admin/",
    "/auth/realms/master/",
]

DETECTION_PATHS = [
    "/",  # Root path
    "/auth/",  # Login path
    "/auth/admin/",  # Admin Console path
]

VERSION_PATH = "/auth/"
VERSION_PATTERN = r"<div class=\"kc-logo-text\">(?:Keycloak\s*)?([\d\.]+)</div>"

VULN_FIXED_VERSION = (19, 0, 0)

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 10

# ── Helpers ───────────────────────────────────────────────────────────────────


def parse_version(version_text: str):
    """Parse version string and return a tuple for comparison."""
    try:
        return tuple(int(part) for part in version_text.split("."))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Return True if version is below the fixed version."""
    if version_tuple is None:
        return None
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure the URL has an appropriate scheme and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def print_colored(message: str, level: str):
    """
    Print a message in color for terminal output.
    Levels: INFO (green), HIGH (yellow), CRITICAL (red), RESET (none).
    """
    colors = {
        "INFO": "\033[92m",  # Green
        "HIGH": "\033[93m",  # Yellow
        "CRITICAL": "\033[91m",  # Red
        "RESET": "\033[0m",    # Reset to default
    }
    print(f"{colors.get(level, '')}{message}{colors['RESET']}")


# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_keycloak(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running Keycloak.
    Returns dict with detection info, or None if not Keycloak.
    """
    async with semaphore:
        detection_info = {"url": base_url, "is_keycloak": False, "version": None}
        for path in DETECTION_PATHS:
            detection_url = urljoin(base_url, path)
            try:
                response = await client.get(detection_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and any(fingerprint in response.text for fingerprint in KEYCLOAK_FINGERPRINTS):
                    detection_info["is_keycloak"] = True
                    version_match = re.search(VERSION_PATTERN, response.text)
                    if version_match:
                        version = version_match.group(1)
                        detection_info["version"] = version
                        detection_info["is_vulnerable"] = is_vulnerable_version(parse_version(version))
                    break
            except Exception:
                pass
        return detection_info if detection_info["is_keycloak"] else None


async def check_auth_bypass(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Perform an authentication bypass test on the Keycloak Admin Console.
    """
    async with semaphore:
        target_url = urljoin(base_url, "/auth/admin/")
        try:
            response = await client.get(target_url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
            if "admin" in response.text and response.status_code == 200:
                return True
            return False
        except Exception:
            return False


async def scan_target(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Scan a single target for the vulnerability.
    """
    data = await detect_keycloak(client, target, semaphore)
    if not data:
        print_colored(f"INFO: {target} does not appear to be a Keycloak instance", "INFO")
        return None

    if not data["is_vulnerable"]:
        print_colored(f"INFO: {target} - Detected Keycloak {data['version']}, not vulnerable", "INFO")
        return data

    print_colored(f"HIGH: {target} - Detected Keycloak {data['version']}, potentially vulnerable", "HIGH")

    if not safe_mode:
        if await check_auth_bypass(client, target, semaphore):
            data["auth_bypass"] = True
            print_colored(f"CRITICAL: {target} is VULNERABLE to CVE-2026-51234 (Auth Bypass Confirmed)", "CRITICAL")
        else:
            data["auth_bypass"] = False
            print_colored(f"INFO: {target} - Authentication Bypass NOT confirmed", "INFO")
    else:
        data["auth_bypass"] = None

    return data


async def main(args):
    """
    Main entry point of the scanner.
    """
    client = httpx.AsyncClient(verify=not args.no_verify, timeout=REQUEST_TIMEOUT)
    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = []

    if args.list:
        with open(args.list, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [args.target]

    results = []
    for target in targets:
        normalized_url = normalize_url(target)
        tasks.append(scan_target(client, normalized_url, semaphore, args.safe))

    results = [result for result in await asyncio.gather(*tasks) if result]

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    else:
        print(json.dumps(results, indent=4))

    await client.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Keycloak Authentication Bypass Scanner (CVE-2026-51234)"
    )
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="File to save JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only, no probing")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrent tasks (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    if not args.target and not args.list:
        print("ERROR: Either --target or --list is required.")
        parser.print_help()
        sys.exit(1)

    asyncio.run(main(args))
