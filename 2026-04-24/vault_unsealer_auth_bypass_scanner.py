#!/usr/bin/env python3
"""
HashiCorp Vault CVE-2026-48293 Authentication Bypass Scanner
===============================================================
Scans for misconfigured or vulnerable HashiCorp Vault instances allowing
unauthenticated access to the Unseal API endpoint (CVE-2026-48293, CVSS 9.8).

CVE-2026-48293 details:
  - Affects Vault versions < 1.12.5
  - Misconfigured installations may allow public access to unseal API endpoints
  - This bypass can lead to unauthorized access and compromise of Vault secrets
  - Patched in Vault version 1.12.5 (March 2026)

This tool detects exposed Vault endpoints, identifies the Vault version, and
performs optional probes to confirm if the unseal endpoint is accessible
without authentication.

Usage:
  # Scan a single target
  python vault_unsealer_auth_bypass_scanner.py --target https://vault.example.com

  # Scan a list of targets
  python vault_unsealer_auth_bypass_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no active probes
  python vault_unsealer_auth_bypass_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48293
  - https://github.com/hashicorp/vault/blob/main/CHANGELOG.md
"""

import asyncio
import argparse
import json
import os
import re
from urllib.parse import urljoin

import httpx

# Constants
VAULT_FINGERPRINTS = [
    "HashiCorpVault",
    "\"initialized\":true",
    "\"sealed\":true",
    "\"sealed\":false",
]

DETECTION_PATHS = [
    "/v1/sys/health",
    "/v1/sys/seal-status",
]

VERSION_PATTERNS = [
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
]

VULN_FIXED_VERSION = (1, 12, 5)

UNSEAL_ENDPOINT = "/v1/sys/unseal"
REQUEST_BODY = {
    "key": "fake-key"
}
SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 8

# ── Helper Functions ──────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Parses a semantic version string into a tuple of integers."""
    try:
        return tuple(map(int, version_str.split('.')))
    except ValueError:
        return None

def is_vulnerable_version(version_tuple):
    """Checks if a Vault version is vulnerable."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION

def normalize_url(url: str):
    """Ensures the given URL has a scheme and strips trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def color_text(text: str, color: str):
    """Returns text wrapped in ANSI color codes."""
    colors = {
        "RED": "\033[31m",
        "YELLOW": "\033[33m",
        "GREEN": "\033[32m",
        "RESET": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['RESET']}"

# ── Core Scanner ──────────────────────────────────────────────────────────────

async def detect_vault(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detects whether a URL is running a Vault server.
    Returns dict with detection info, or None if not a Vault instance.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.is_success:
                    for marker in VAULT_FINGERPRINTS:
                        if marker in response.text:
                            version = parse_version_from_response(response.text)
                            result = {
                                "url": base_url,
                                "detected": True,
                                "version": version,
                                "vulnerable": is_vulnerable_version(version),
                            }
                            return result
            except Exception:
                continue
    return {"url": base_url, "detected": False}

def parse_version_from_response(response_text):
    """Extract and return the first found version string from response text."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, response_text)
        if match:
            return parse_version(match.group(1))
    return None

async def try_unseal_probe(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Probes the Unseal API endpoint for authentication bypass.
    Returns True if the endpoint is accessible without authentication.
    """
    async with semaphore:
        url = urljoin(base_url, UNSEAL_ENDPOINT)
        try:
            response = await client.post(url, json=REQUEST_BODY, timeout=REQUEST_TIMEOUT)
            if response.status_code == 400 and "invalid key" in response.text.lower():
                return True
        except Exception:
            pass
    return False

async def scan_target(client, target, semaphore, safe_mode):
    """Scans a single target and returns the result."""
    try:
        target = normalize_url(target)
        result = await detect_vault(client, target, semaphore)
        if result["detected"] and not safe_mode:
            result["unseal_bypass"] = await try_unseal_probe(client, target, semaphore)
        return result
    except Exception as e:
        return {"url": target, "error": str(e)}

# ── Main Scanner Runner ───────────────────────────────────────────────────────

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=(not args.no_verify), timeout=REQUEST_TIMEOUT) as client:
        if args.target:
            targets = [args.target]
        elif args.list:
            with open(args.list) as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            print("No target or target list provided. Use --help for usage.")
            sys.exit(1)

        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

        # Output results
        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
        else:
            # Print results to console
            print("\nScan Results:\n")
            for result in results:
                if "error" in result:
                    print(color_text(f"[!] Error: {result['url']} - {result['error']}", "RED"))
                else:
                    status = "VULNERABLE" if result.get("unseal_bypass") else ("SAFE" if not result["vulnerable"] else "DETECTED")
                    color = "RED" if status == "VULNERABLE" else "YELLOW" if status == "DETECTED" else "GREEN"
                    print(color_text(f"[{status}] {result['url']} - Version: {result.get('version') or 'Unknown'}", color))

# ── Argument Parsing ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan for CVE-2026-48293 HashiCorp Vault authentication bypass.")
    parser.add_argument("--target", type=str, help="Single target URL to scan")
    parser.add_argument("--list", type=str, help="File containing list of targets, one per line")
    parser.add_argument("--output", type=str, help="JSON file to save results")
    parser.add_argument("--safe", action="store_true", help="Detection only, no probing of Unseal API")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for HTTPS requests")
    args = parser.parse_args()

    asyncio.run(main(args))
