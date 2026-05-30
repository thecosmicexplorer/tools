#!/usr/bin/env python3
"""
Active Directory Federation Services (AD FS) SSRF Scanner
=========================================================
This scanner identifies potential Server-Side Request Forgery (SSRF) vulnerabilities in Active Directory Federation Services (AD FS), 
specifically targeting misconfigured endpoints and open metadata exchange URLs. SSRF vulnerabilities can allow attackers to exploit 
the server to make unauthorized requests or exfiltrate sensitive information.

Vulnerability Details:
  - Affects various configurations of the AD FS service.
  - Can be exploited through openredirection attacks or unrestricted metadata exchange endpoints.
  - May allow access to privileged resources or back-end systems.

Usage:
  # Scan a single AD FS endpoint with active probing enabled:
  python active_directory_ssrf_scanner.py --target https://example-adfs.com

  # Scan a list of AD FS endpoints using detection-only mode:
  python active_directory_ssrf_scanner.py --list targets.txt --safe

  # Save results to a JSON file:
  python active_directory_ssrf_scanner.py --list targets.txt --output adfs_ssrf_findings.json

References:
  - https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/
  - https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-18133/Microsoft-Active-Directory-Federation-Services.html
"""

import asyncio
import argparse
import json
from urllib.parse import urlparse, urlencode

import httpx
import re

# ── Detection constants ──────────────────────────────────────────────────────

ADFS_FINGERPRINTS = [
    "<title>ADFS</title>",
    "AD FS Help Pages",
    "Sign in to your account",
]

# Common endpoints in AD FS
DETECTION_PATHS = [
    "/",
    "/adfs/ls/",
    "/adfs/IdpInitiatedSignOn.aspx",
    "/adfs/services/trust/mex",
]

# Common open endpoints used in SSRF attacks
PROBE_PATHS = [
    "/adfs/services/trust/mex",
    "/adfs/services/proxy",
    "/adfs/auth/token",
]

# ── Configuration ─────────────────────────────────────────────────────────────

SEMAPHORE_LIMIT = 30  # Max simultaneous connections
REQUEST_TIMEOUT = 8
PROBE_PAYLOAD = "http://example.com"  # Test payload for SSRF probes

class Colors:
    CRITICAL = "\033[91m"  # Red
    HIGH = "\033[93m"      # Yellow
    INFO = "\033[92m"      # Green
    RESET = "\033[0m"      # Reset

# ── Helpers ──────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Normalize URL to ensure it uses HTTPS and avoid trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def format_message(severity: str, message: str) -> str:
    """Format message with ANSI color."""
    color_map = {
        "CRITICAL": Colors.CRITICAL,
        "HIGH": Colors.HIGH,
        "INFO": Colors.INFO,
    }
    return f"{color_map.get(severity, Colors.RESET)}[{severity}]{Colors.RESET} {message}"

# ── Core Scanner ─────────────────────────────────────────────────────────────

async def detect_adfs(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running AD FS.
    Returns a detection dictionary if successful.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            url = normalize_url(base_url) + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                for fingerprint in ADFS_FINGERPRINTS:
                    if fingerprint in response.text:
                        return {
                            "url": base_url,
                            "detected": True,
                            "endpoint": url,
                        }
            except (httpx.RequestError, Exception):
                pass
    return {"url": base_url, "detected": False}

async def probe_ssrf(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Actively probe the AD FS endpoint for SSRF vulnerabilities.
    Requires the target to be detected as AD FS in prior detection.
    """
    async with semaphore:
        for path in PROBE_PATHS:
            probe_url = normalize_url(base_url) + path
            try:
                if safe_mode:
                    response = await client.get(probe_url, timeout=REQUEST_TIMEOUT)
                else:
                    probe_payload = probe_url + "?" + urlencode({"url": PROBE_PAYLOAD})
                    response = await client.get(probe_payload, timeout=REQUEST_TIMEOUT)

                if response.status_code in {200, 302}:  # Indicative of open redirect or accessible metadata.
                    return {
                        "url": probe_url,
                        "vulnerable": True,
                        "safe_mode": safe_mode,
                        "status_code": response.status_code,
                    }
            except (httpx.RequestError, Exception):
                pass

    return {
        "url": base_url,
        "vulnerable": False,
    }

# ── CLI Entry Point ──────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Active Directory Federation Services (AD FS) SSRF Scanner")
    parser.add_argument("--target", type=str, help="URL of the AD FS instance to scan")
    parser.add_argument("--list", type=str, help="List of AD FS instances to scan (newline-separated)")
    parser.add_argument("--output", type=str, help="Save findings to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (no SSRF probing)")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for HTTP requests")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        print("No targets provided. Use --target or --list.")
        return

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        findings = []
        for target in targets:
            detection_info = await detect_adfs(client, target, semaphore)
            if detection_info["detected"]:
                print(format_message("INFO", f"Detected AD FS at {target}"))
                probe_info = await probe_ssrf(client, target, semaphore, args.safe)
                if probe_info["vulnerable"]:
                    print(format_message("CRITICAL", f"Potential SSRF vulnerability at {probe_info['url']}"))
                findings.append({"detection": detection_info, "probe": probe_info})
            else:
                print(format_message("HIGH", f"No AD FS detected at {target}"))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
