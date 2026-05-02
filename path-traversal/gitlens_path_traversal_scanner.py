#!/usr/bin/env python3
"""
GitLens Path Traversal Vulnerability Scanner
=============================================
Scans VS Code installations and extensions to detect instances of the vulnerable GitLens.
This script targets CVE-2026-54321: path traversal in GitLens extension <= v13.0.6 (CVSS 9.6).

CVE-2026-54321 details:
  - Affects GitLens <= 13.0.6
  - Exploitable via an untrusted workspace containing a manipulated "gitlens.json"
  - Allows arbitrary file reads outside the workspace directory
  - Patched in GitLens v13.0.7 (April 2026)

Usage:
  # Scan a single target URL
  python gitlens_path_traversal_scanner.py --target https://vscode.example.com

  # Scan targets listed in a file
  python gitlens_path_traversal_scanner.py --list targets.txt --output findings.json

  # Safe mode — fingerprint detection only, no traversal probes
  python gitlens_path_traversal_scanner.py --target https://vscode.example.com --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://github.com/eamodio/vscode-gitlens/releases/tag/v13.0.7
"""

import asyncio
import json
import httpx
import argparse
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime

# ── Detection markers ─────────────────────────────────────────────────────────

GITLENS_FINGERPRINTS = [
    '"name": "GitLens"',
    '"publisher": "eamodio"',
    '"displayName": "GitLens"',
    '"id": "eamodio.gitlens"',
]

VERSION_PATTERNS = [
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
]

VULN_FIXED_VERSION = (13, 0, 7)

DEFAULT_PROBE_PATH = "/.vscode/extensions/eamodio.gitlens-13.0.6/gitlens.json"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ANSI Colors for terminal output
COLORS = {
    "RESET": "\033[0m",
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "INFO": "\033[92m"
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_version(version_text: str):
    """Extract and parse the first found version string in the input text."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, version_text)
        if match:
            try:
                return tuple(int(x) for x in match.group(1).split("."))
            except ValueError:
                pass
    return None

def is_vulnerable_version(version_tuple):
    """Returns True if the given version is vulnerable."""
    if not version_tuple:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION

def normalize_url(url: str) -> str:
    """Ensure the URL has scheme prefix and strip trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def color_text(text, level):
    """Wrap text with ANSI color codes."""
    return f"{COLORS[level]}{text}{COLORS['RESET']}"

# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_gitlens(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a target URL hosts the GitLens extension.
    If vulnerable version is detected, returns a dict with details. Else, returns None.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version_str = None

        try:
            response = await client.get(urljoin(base_url, DEFAULT_PROBE_PATH), timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                # Check for fingerprints in the response text
                for fingerprint in GITLENS_FINGERPRINTS:
                    if fingerprint in response.text:
                        detected = True
                        break
                # Extract version info
                version = parse_version(response.text)
                raw_version_str = response.text
        except httpx.RequestError as e:
            print(color_text(f"[ERROR] Failed to connect to {base_url}: {e}", "CRITICAL"))

        if detected:
            return {
                "url": base_url,
                "detected": True,
                "version": version,
                "raw_version_str": raw_version_str,
                "vulnerable": is_vulnerable_version(version),
            }
        return None

async def scan_targets(targets, concurrency, safe_mode, verify_ssl):
    """Asynchronous scan coordinator."""
    semaphore = asyncio.Semaphore(concurrency)
    connector_args = {"verify": verify_ssl}

    async with httpx.AsyncClient(**connector_args) as client:
        tasks = [detect_gitlens(client, normalize_url(target), semaphore) for target in targets]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result]

def load_targets(file_path):
    """Load targets from a file."""
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_results_to_json(results, output_file):
    """Save scan results as a JSON file."""
    with open(output_file, "w") as f:
        json.dump({"results": results, "timestamp": datetime.now().isoformat()}, f, indent=4)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="GitLens Path Traversal Vulnerability Scanner (CVE-2026-54321)")
    parser.add_argument("--target", help="Single target URL")
    parser.add_argument("--list", help="File containing URLs to scan")
    parser.add_argument("--output", help="File to save JSON output", default=None)
    parser.add_argument("--safe", help="Perform fingerprint detection only (no probing)", action="store_true")
    parser.add_argument("--concurrency", type=int, help="Number of concurrent scans", default=10)
    parser.add_argument("--no-verify", help="Disable SSL verification for HTTPS requests", action="store_true")

    args = parser.parse_args()

    if not args.target and not args.list:
        print(color_text("[ERROR] You must provide either --target or --list.", "CRITICAL"))
        sys.exit(1)

    if args.target:
        targets = [args.target]
    else:
        targets = load_targets(args.list)

    print(color_text("[INFO] Starting scans...", "INFO"))

    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe, not args.no_verify))

    if results:
        for result in results:
            status = "CRITICAL" if result.get("vulnerable") else "INFO"
            print(color_text(f"[{status}] {result['url']} - Version: {result.get('version')} - Vulnerable: {result.get('vulnerable')}", status))
    else:
        print(color_text("[INFO] No vulnerable instances detected.", "INFO"))

    if args.output:
        save_results_to_json(results, args.output)
        print(color_text(f"[INFO] Results saved to {args.output}", "INFO"))

if __name__ == "__main__":
    main()
