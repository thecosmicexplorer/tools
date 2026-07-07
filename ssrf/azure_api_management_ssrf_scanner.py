#!/usr/bin/env python3
"""
Azure API Management SSRF Scanner
=================================
This tool scans Azure API Management (APIM) instances for potential Server-Side Request Forgery (SSRF) vulnerabilities. 
APIM is a popular service used to create and manage APIs. Misconfigurations, improper validation, or exploitable proxy setups 
can lead to SSRF, allowing attackers to make HTTP requests on behalf of the APIM instance.

Example SSRF vulnerabilities in APIM:
- Abuse of open proxy endpoints to query sensitive internal services (e.g., Azure Instance Metadata Service).
- Exploitation of unvalidated or improperly sanitized API parameters.
- Exploitation of misconfigured backend targets.

Usage:
  # Scan a single APIM instance for SSRF vulnerabilities
  python azure_api_management_ssrf_scanner.py --target https://api.example.com

  # Perform a detection-only scan (no active SSRF testing)
  python azure_api_management_ssrf_scanner.py --target https://api.example.com --safe

  # Bulk scan from a file containing APIM URLs
  python azure_api_management_ssrf_scanner.py --list apim_targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python azure_api_management_ssrf_scanner.py --list apim_targets.txt --concurrency 50 --no-verify

References:
- https://docs.microsoft.com/en-us/azure/api-management/
- https://lab.wallarm.com/server-side-request-forgery-ssrf-under-a-frozen-surface/
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional, Dict, List

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

TOOL_NAME       = "azure_api_management_ssrf_scanner"
VULNERABILITY   = "Server-Side Request Forgery (SSRF)"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# API Management fingerprints — these indicate the presence of APIM
APIM_FINGERPRINTS = [
    "Ocp-Apim-Trace",
    "Apim-Request-Id",
    "Microsoft-Azure-API-Management",
    "Ocp-Apim-Subscription-Key",
]

# SSRF Probe URLs — commonly targeted sensitive endpoints
SSRF_PROBE_URLS = [
    "http://169.254.169.254/metadata/instance?api-version=2021-06-01",  # Azure IMDS
    "http://169.254.169.254/latest/meta-data/",                        # AWS IMDS
    "http://127.0.0.1/",                                               # Localhost probe
    "http://localhost/",                                               # Synonym for localhost
    "http://0.0.0.0/",                                                 # Catch-all local IP
    "https://example.com/",                                            # Benign external URL for baseline testing
]

# Headers used for SSRF trigger attempts
SSRF_HEADERS = {
    "Host": "169.254.169.254",  # IMDS detection
    "X-Forwarded-For": "127.0.0.1", 
    "X-Forwarded-Host": "localhost", 
}

# ── Async helpers ─────────────────────────────────────────────────────────────

async def fetch(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                timeout: int = REQUEST_TIMEOUT, verify_ssl: bool = True) -> Optional[httpx.Response]:
    """Make an HTTP/HTTPS request and return the response."""
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify_ssl) as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
            else:
                response = await client.post(url, headers=headers)
            return response
    except (httpx.HTTPError, asyncio.TimeoutError) as exc:
        print(c(YELLOW, f"Warning: Request error for {url} — {exc}"))
        return None


async def fingerprint_apim(base_url: str, verify_ssl: bool) -> Optional[str]:
    """Check if the target URL is an Azure API Management instance."""
    try:
        response = await fetch(url=f"{base_url}/", verify_ssl=verify_ssl)
        if response and any(fp in response.headers for fp in APIM_FINGERPRINTS):
            return response.headers.get("Microsoft-Azure-API-Management", "unknown version")
    except Exception as e:
        print(c(YELLOW, f"Error checking fingerprint for {base_url}: {e}"))
    return None


async def probe_ssrf(base_url: str, verify_ssl: bool, safe_mode: bool) -> List[str]:
    """Attempt to trigger SSRF vulnerabilities with common payloads."""
    findings = []
    if safe_mode:
        print(c(YELLOW, f"Safe mode enabled: No SSRF probes sent to {base_url}"))
        return findings  # Detection-only mode

    tasks = []
    for payload in SSRF_PROBE_URLS:
        url = f"{base_url}/echo"  # Example endpoint for external echo testing
        headers = dict(SSRF_HEADERS)
        tasks.append(fetch(url=url, headers=headers, verify_ssl=verify_ssl))

    responses = await asyncio.gather(*tasks, return_exceptions=True)
    for response in responses:
        if isinstance(response, httpx.Response) and response.status_code == 200:
            print(c(RED, f"CRITICAL: Possible SSRF via {response.url}"))
            findings.append(str(response.url))
        elif isinstance(response, Exception):
            print(c(YELLOW, f"Error occurred during SSRF probe: {response}"))

    return findings


# ── Main logic ────────────────────────────────────────────────────────────────

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    targets = [args.target] if args.target else open(args.list).read().splitlines()
    tasks = []

    async def process_target(target: str):
        async with semaphore:
            apim_version = await fingerprint_apim(base_url=target, verify_ssl=not args.no_verify)
            if apim_version:
                print(c(GREEN, f"INFO: {target} appears to be an Azure API Management instance (version: {apim_version})"))
                ssrf_findings = await probe_ssrf(base_url=target, verify_ssl=not args.no_verify, safe_mode=args.safe)
                return {"target": target, "apim_version": apim_version, "ssrf_findings": ssrf_findings}
            else:
                print(c(YELLOW, f"WARNING: {target} does not appear to be an Azure APIM instance."))
                return {"target": target, "apim_version": None, "ssrf_findings": []}

    for target in targets:
        tasks.append(process_target(target))

    results = await asyncio.gather(*tasks)

    # Save results to JSON if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump({"scan_date": datetime.now(timezone.utc).isoformat(), "results": results}, f, indent=4)
        print(c(GREEN, f"INFO: Results saved to {args.output}"))

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Azure API Management SSRF scanner.")
    parser.add_argument("--target", type=str, help="Target URL to scan.")
    parser.add_argument("--list", type=str, help="File with newline-separated URLs to scan.")
    parser.add_argument("--output", type=str, help="Output file to save the JSON results.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no active probing).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent workers (default: 30).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: Either --target or --list must be specified."))
        sys.exit(1)

    asyncio.run(main(args))
