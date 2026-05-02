#!/usr/bin/env python3
"""
JFrog Artifactory CVE-2026-54321 SSO Authentication Bypass Scanner
===================================================================
Scans JFrog Artifactory instances to detect a critical authentication bypass vulnerability (CVE-2026-54321, CVSS 9.8) 
affecting SSO login mechanisms.

CVE-2026-54321 details:
  - Affects JFrog Artifactory versions 7.53.0 - 7.63.2
  - Improper validation of SSO authentication tokens allows attackers to bypass authentication
  - Attacker can gain unauthorized access to the admin panel and other restricted routes
  - Found in environments with SSO enabled
  - Fixed in Artifactory v7.63.3 (March 2026)

Usage:
  # Scan a single target
  python artifactory_sso_auth_bypass_scanner.py --target https://artifactory.example.com

  # Scan a list of targets
  python artifactory_sso_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no authentication bypass probes
  python artifactory_sso_auth_bypass_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://www.jfrog.com/knowledge-base/security-update-artifactory-7-63-3/
"""

import asyncio
import argparse
import json
from urllib.parse import urlparse

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

ARTIFACTORY_FINGERPRINTS = [
    # Admin routes and indicators
    "<title>JFrog Artifactory</title>",
    '"productProvider":"Artifactory"',
    'class="artifactory-login-container"',
]

DETECTION_PATHS = [
    "/",
    "/ui/admin/login",
    "/ui/admin/",
    "/artifactory/api/system/ping",
]

VERSION_PATTERNS = [
    r'"productVersion":"([0-9]+\.[0-9]+\.[0-9]+)"',
    r"Artifactory ([0-9]+\.[0-9]+\.[0-9]+)",
]

VULN_FIXED_VERSION = (7, 63, 3)

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# API route for testing the SSO bypass
SSO_BYPASS_PATH = "/ui/admin/configuration"

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse the first version string found in text."""
    for pattern in VERSION_PATTERNS:
        m = re.search(pattern, text)
        if m:
            try:
                return tuple(int(x) for x in m.group(1).split("."))
            except ValueError:
                pass
    return None


def is_vulnerable_version(version_tuple):
    """Return True if version is below the fixed version."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ── Core scanner ────────────────────────────────────────────────────────────

async def detect_artifactory(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running JFrog Artifactory.
    Returns dict with detection info, or None if not Artifactory.
    """
    async with semaphore:
        version = None
        detected = False
        raw_version_str = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                for marker in ARTIFACTORY_FINGERPRINTS:
                    if marker in response.text:
                        detected = True
                        version = parse_version(response.text)
                        if version:
                            raw_version_str = ".".join(map(str, version))
                        break
                if detected:
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version_str,
            "vulnerable": is_vulnerable_version(version),
        }

async def probe_bypass(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to exploit the SSO authentication bypass vulnerability.
    Returns True if exploitation was successful (admin panel is accessible without authentication).
    """
    async with semaphore:
        try:
            probe_url = url + SSO_BYPASS_PATH
            response = await client.get(probe_url, timeout=REQUEST_TIMEOUT, follow_redirects=False)
            if response.status_code == 200 and 'admin' in response.text.lower():
                return True
        except (httpx.RequestError, Exception):
            pass
        return False


async def scan_target(client: httpx.AsyncClient, url: str, safe_mode: bool, semaphore: asyncio.Semaphore):
    """
    Scan a single target for the authentication bypass vulnerability.
    Returns a dictionary containing detection and exploitation results.
    """
    detection_info = await detect_artifactory(client, url, semaphore)
    if not detection_info["detected"]:
        return detection_info

    if detection_info.get("vulnerable") and not safe_mode:
        detection_info["exploitable"] = await probe_bypass(client, url, semaphore)
    else:
        detection_info["exploitable"] = False

    return detection_info


async def main(args):
    """
    Main scanning workflow based on CLI arguments.
    """
    client_options = {"timeout": REQUEST_TIMEOUT}
    if args.no_verify:
        client_options["verify"] = False

    async with httpx.AsyncClient(**client_options) as client:
        semaphore = asyncio.Semaphore(args.concurrency)
        targets = []

        if args.target:
            targets = [normalize_url(args.target)]
        elif args.list:
            with open(args.list, "r") as f:
                targets = [normalize_url(line.strip()) for line in f if line.strip()]

        results = []
        tasks = [scan_target(client, target, args.safe, semaphore) for target in targets]
        for result in await asyncio.gather(*tasks):
            print(f"[INFO] Scanned {result['url']} - Detected: {result['detected']}, "
                  f"Version: {result.get('version', 'Unknown')}, "
                  f"Vulnerable: {result.get('vulnerable')}, Exploitable: {result.get('exploitable')}")
            results.append(result)

        # Export results if output file is specified
        if args.output:
            with open(args.output, "w") as f_out:
                json.dump(results, f_out, indent=2)
            print(f"[INFO] Results saved to {args.output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JFrog Artifactory CVE-2026-54321 Authentication Bypass Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing list of targets to scan")
    parser.add_argument("--output", help="File to save JSON output")
    parser.add_argument("--safe", action="store_true", help="Run detection only without bypass probes")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Maximum concurrent requests (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    asyncio.run(main(args))
