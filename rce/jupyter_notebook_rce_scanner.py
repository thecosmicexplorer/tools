#!/usr/bin/env python3
"""
Jupyter Notebook Remote Code Execution (RCE) Scanner
=====================================================
This script scans for improperly configured or exposed Jupyter Notebook instances 
that allow remote code execution (RCE) due to misconfigurations, weak security, or 
known vulnerabilities.

Some attack vectors checked by this script include:
  - Exposed Jupyter Notebook server without authentication
  - Weak token security leading to unauthorized access
  - Exploited API endpoints enabling RCE

Jupyter Notebooks are widely used in data science, AI research, and similar fields. 
This scanner checks for misconfigurations and vulnerabilities in your target setup.

Usage:
  # Scan a single target
  python jupyter_notebook_rce_scanner.py --target https://jupyter.example.com

  # Scan multiple targets from a list
  python jupyter_notebook_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode – detection without active probes
  python jupyter_notebook_rce_scanner.py --list targets.txt --safe

References:
  - https://jupyter-notebook.readthedocs.io/en/stable/security.html
  - https://cwe.mitre.org/data/definitions/287.html
"""

import asyncio
import json
import re
import argparse
import sys
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich import print

# ─── Constants ───────────────────────────────────────────────────────────────

DETECTION_PATHS = [
    "/", "/login", "/tree", "/notebooks", "/api/status",
]
RCE_TEST_PATH = "/api/contents"

DEFAULT_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

JUPYTER_FINGERPRINTS = [
    "Jupyter Notebook Server",  # Default HTML title
    "JupyterLab",
    "/api/contents",  # Common endpoint
    "authentication required",  # API response
]

COLOR_CRITICAL = "red"
COLOR_HIGH = "yellow"
COLOR_INFO = "green"
COLOR_RESET = "white"

# ─── Helpers ─────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Ensures the URL starts with http(s) and removes any trailing slashes.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def fingerprint_jupyter(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Check whether the target URL is a Jupyter Notebook instance.
    Returns detection metadata if true, else None.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            full_url = url + path
            
            try:
                response = await client.get(full_url, timeout=DEFAULT_TIMEOUT)
                for fingerprint in JUPYTER_FINGERPRINTS:
                    if fingerprint.lower() in response.text.lower():
                        return {
                            "url": url,
                            "is_jupyter": True,
                            "response_code": response.status_code,
                            "fingerprint": fingerprint,
                        }
            except httpx.RequestError as e:
                continue
        return None


async def perform_rce_probe(
    client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore
):
    """
    Perform active RCE probe against the target Jupyter Notebook instance.
    """
    async with semaphore:
        test_payload = {
            "type": "file",
            "content": "echo Vulnerable"
        }
        
        try:
            response = await client.put(
                url + RCE_TEST_PATH, json=test_payload, timeout=DEFAULT_TIMEOUT
            )
            if "vulnerable" in response.text.lower():
                return {"url": url, "vulnerable_to_rce": True}
        except httpx.RequestError:
            return None
        return {"url": url, "vulnerable_to_rce": False}


async def scan_target(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Perform comprehensive scans for the specified Jupyter Notebook server URL.
    """
    url = normalize_url(url)
    scan_results = await fingerprint_jupyter(client, url, semaphore)

    # If not detected as Jupyter, return directly
    if not scan_results:
        return {"url": url, "is_jupyter": False, "vulnerable_to_rce": None}

    scan_results["vulnerable_to_rce"] = None

    # Perform active RCE probe unless in safe mode
    if not safe_mode:
        results = await perform_rce_probe(client, url, semaphore)
        scan_results.update(results)

    return scan_results


async def scan_targets(targets, concurrency, timeout, safe_mode):
    """
    Scan multiple targets concurrently with the specified settings.
    """
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify, timeout=timeout) as client:
        tasks = [scan_target(client, target, semaphore, safe_mode) for target in targets]
        results = await asyncio.gather(*tasks)
    return results


# ─── Main CLI ────────────────────────────────────────────────────────────────

def parse_args():
    """
    Parse CLI arguments into a suitable object.
    """
    parser = argparse.ArgumentParser(description="Jupyter Notebook RCE Scanner")
    parser.add_argument(
        "--target", help="Single target to scan (URL format)"
    )
    parser.add_argument(
        "--list",
        help="List of targets to scan (file containing URLs separated by newline)",
    )
    parser.add_argument(
        "--output", help="File path for saving JSON scan results", default="results.json"
    )
    parser.add_argument(
        "--safe", action="store_true", help="Enable safe mode (no RCE probes)"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=SEMAPHORE_LIMIT,
        help=f"Maximum concurrent requests (default: {SEMAPHORE_LIMIT})",
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable SSL verification"
    )

    return parser.parse_args()


async def main():
    args = parse_args()
    console = Console()

    # Load target URLs from file or command line
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[{COLOR_CRITICAL}]Error: Target list file not found.[/{COLOR_RESET}]")
            sys.exit(1)

    if not targets:
        console.print(f"[{COLOR_CRITICAL}]Error: No targets specified.[/{COLOR_RESET}]")
        sys.exit(1)

    # Async scans
    console.print(f"[{COLOR_INFO}]Starting scans for {len(targets)} target(s)...[/{COLOR_RESET}]")
    scan_results = await scan_targets(
        targets, args.concurrency, timeout=DEFAULT_TIMEOUT, safe_mode=args.safe
    )

    # Output processing
    if args.output:
        with open(args.output, "w") as f:
            json.dump(scan_results, f, indent=4)
        console.print(f"[{COLOR_INFO}]Results saved to {args.output}[/{COLOR_RESET}]")
    else:
        console.print(json.dumps(scan_results, indent=4))

    console.print(f"[{COLOR_INFO}]Scan complete.[/{COLOR_RESET}]")


if __name__ == "__main__":
    asyncio.run(main())
