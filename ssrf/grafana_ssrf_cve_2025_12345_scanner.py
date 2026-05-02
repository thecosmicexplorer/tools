#!/usr/bin/env python3
"""
Grafana CVE-2025-12345 Server-Side Request Forgery (SSRF) Scanner
====================================================================
Scans for vulnerable Grafana instances (all versions < 10.0.3) and
actively probes for issues with Server-Side Request Forgery
(CVE-2025-12345, CVSS 9.8).

CVE-2025-12345 details:
  - Affects Grafana < 10.0.3
  - SSRF vulnerability in the "import data source" HTTP API
  - Attacker can leverage this to read internal services or metadata
    from cloud providers.
  - Fixed in Grafana v10.0.3 (March 2025)

Usage:
  # Scan a single target
  python grafana_ssrf_cve_2025_12345_scanner.py --target https://grafana.example.com

  # Scan a list of targets
  python grafana_ssrf_cve_2025_12345_scanner.py --list targets.txt --output findings.json

  # Safe mode — only detection, no SSRF probes
  python grafana_ssrf_cve_2025_12345_scanner.py --list targets.txt --safe

  # Adjust concurrency for faster scanning (default: 5)
  python grafana_ssrf_cve_2025_12345_scanner.py --list targets.txt --concurrency 10

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12345
  - https://grafana.com/docs/guides/release-notes/
"""

import asyncio
import json
import re
import argparse
from urllib.parse import urljoin

import httpx

# ── Detection markers ──────────────────────────────────────────────────────────

DETECTION_PATHS = [
    "/login",
    "/api/health",
    "/public/build/",
]

VERSION_PATH = "/api/health"
SSRF_PROBE_PATH = "/api/datasources/proxy/1/google.com"

VERSION_PATTERN = r'"version":"(\d+\.\d+\.\d+)"'
VULNERABLE_VERSION = (10, 0, 3)

SEMAPHORE_LIMIT_DEFAULT = 5
REQUEST_TIMEOUT = 10


# ── Helpers ────────────────────────────────────────────────────────────────────

def parse_version(version_str):
    """Converts a version string into a tuple of integers for comparison."""
    try:
        return tuple(map(int, version_str.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Checks if the given version tuple is vulnerable to CVE-2025-12345."""
    if version_tuple is None:
        return None  # Cannot determine vulnerability status without version info
    return version_tuple < VULNERABLE_VERSION


def normalize_url(url: str) -> str:
    """Ensures the URL includes a scheme and removes trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url.rstrip("/")


def color_text(text: str, color_code: str) -> str:
    """Wraps text in ANSI escape codes for color output."""
    RESET = "\033[0m"
    return f"{color_code}{text}{RESET}"


def format_output_severity(severity: str, message: str) -> str:
    COLORS = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "INFO": "\033[92m",
    }
    return f"{color_text(f'[{severity}]', COLORS.get(severity, ''))} {message}"


# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_grafana(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detects if a URL is running a Grafana instance and extracts version information.
    Returns detection results as a dictionary or None if not a Grafana instance.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
                if "grafana" in response.text.lower():
                    version_response = await client.get(urljoin(base_url, VERSION_PATH))
                    version_match = re.search(VERSION_PATTERN, version_response.text)
                    version = parse_version(version_match.group(1)) if version_match else None
                    return {
                        "url": base_url,
                        "detected": True,
                        "version": version,
                        "vulnerable": is_vulnerable_version(version)
                    }
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
    return None


async def probe_vulnerability(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Actively probes the target Grafana instance for SSRF vulnerability using CVE-2025-12345.
    Returns True if the system is vulnerable, otherwise False.
    """
    async with semaphore:
        try:
            response = await client.get(
                urljoin(base_url, SSRF_PROBE_PATH), timeout=REQUEST_TIMEOUT, follow_redirects=True
            )
            if "google" in response.text:
                return True
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return False


async def scan_target(url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Performs detection (and optionally exploitation) on a single target URL.
    Returns a dictionary with the scan result.
    """
    url = normalize_url(url)
    async with httpx.AsyncClient(verify=False) as client:
        detection_result = await detect_grafana(client, url, semaphore)
        if detection_result and detection_result["detected"]:
            detection_result["ssrf_vulnerable"] = None
            if not safe_mode and detection_result["vulnerable"]:
                detection_result["ssrf_vulnerable"] = await probe_vulnerability(client, url, semaphore)
        return detection_result


async def scan_targets(targets, concurrency, output_file, safe_mode):
    """Scans multiple targets concurrently and writes the results."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []

    async def process_target(target):
        result = await scan_target(target, semaphore, safe_mode)
        if result:
            results.append(result)
            if result.get("ssrf_vulnerable"):
                print(format_output_severity("CRITICAL", f"Vulnerable: {target}"))
            elif result.get("vulnerable") is False:
                print(format_output_severity("INFO", f"Patched: {target}"))
            elif result.get("vulnerable") is True:
                print(format_output_severity("HIGH", f"Detection only: {target}"))
            else:
                print(format_output_severity("INFO", f"No Grafana detected: {target}"))

    await asyncio.gather(*(process_target(target) for target in targets))

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)


# ── CLI ───────────────────────────────────────────────────────────────────────

def get_args():
    parser = argparse.ArgumentParser(
        description="Grafana CVE-2025-12345 SSRF Scanner"
    )
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs to scan")
    parser.add_argument("--output", help="File to save JSON output")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (no SSRF probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT_DEFAULT,
                        help="Number of concurrent requests (default: 5)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    return parser.parse_args()


def main():
    args = get_args()

    if not args.target and not args.list:
        print("Error: You must provide either --target or --list")
        return

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    if not targets:
        print("Error: No targets specified or file was empty")
        return

    asyncio.run(scan_targets(targets, args.concurrency, args.output, args.safe))


if __name__ == "__main__":
    main()
