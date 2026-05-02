#!/usr/bin/env python3
"""
Flask Debug Mode Scanner
=========================
Scans for Flask web applications running in debug mode, which can expose a remote code execution risk 
due to Werkzeug's development server console. The scanner identifies misconfigured apps by hunting 
for the "Werkzeug Debugger" interface and probing for debugging endpoints.

Vulnerability details:
  - Affects Flask apps running with `debug=True` in production
  - Debugger console enables arbitrary code execution via its interactive shell
  - Commonly exposed `/console` endpoint and HTML interface
  - Misconfigurations frequently observed on poorly secured public deployments
  - Recommended mitigation: Set `debug=False` for production deployments

Usage:
  # Scan a single target
  python flask_debug_mode_scanner.py --target https://example-flask-app.com

  # Scan a list of targets
  python flask_debug_mode_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no active debug console probes
  python flask_debug_mode_scanner.py --list targets.txt --safe

References:
  - https://flask.palletsprojects.com/en/latest/tutorial/deploy/
  - https://nvd.nist.gov/vuln/search (search "Flask debug RCE")
  - https://owasp.org/www-project-top-ten/
"""

import asyncio
import json
import os
import argparse
import httpx
import re
from datetime import datetime
from urllib.parse import urljoin

# ── Detection markers ─────────────────────────────────────────────────────────

DETECTION_MARKERS = [
    "Werkzeug Debugger",
    "console.ws",
    "debugger.js",
    "Interactive debugger",
    "flask-debug-toolbar",
]

DEBUG_ENDPOINTS = [
    "/console",
    "/_debug_toolbar/",
]

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_GREEN = "\033[32m"
ANSI_RESET = "\033[0m"

# ── Helper Functions ─────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL always has a scheme and strip trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def print_status(level: str, message: str):
    """Print colored status message to terminal."""
    levels = {
        "CRITICAL": ANSI_RED,
        "HIGH": ANSI_YELLOW,
        "INFO": ANSI_GREEN,
    }
    color = levels.get(level, ANSI_RESET)
    print(f"{color}[{level}]: {message}{ANSI_RESET}")

# ── Core Scanner ──────────────────────────────────────────────────────────────

async def detect_debug_mode(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a Flask app is running in debug mode.
    Returns dict with detection info, or None if not detected.
    """
    async with semaphore:
        detected = False
        debug_endpoint = None
        detection_url = None

        try:
            # Check common debug endpoints
            for endpoint in DEBUG_ENDPOINTS:
                url = urljoin(base_url, endpoint)
                resp = await client.get(url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200 and any(marker in resp.text for marker in DETECTION_MARKERS):
                    detected = True
                    debug_endpoint = endpoint
                    detection_url = url
                    break

            # Check for debug markers in the main page
            if not detected:
                resp = await client.get(base_url, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200 and any(marker in resp.text for marker in DETECTION_MARKERS):
                    detected = True
                    debug_endpoint = None
                    detection_url = base_url

            return {
                "url": base_url,
                "debug_mode": detected,
                "endpoint": debug_endpoint,
                "detection_url": detection_url,
            } if detected else None

        except (httpx.RequestError, httpx.TimeoutException):
            print_status("INFO", f"Request to {base_url} failed.")
            return None

async def scan_targets(targets, concurrency, safe_mode, output_file, no_verify):
    """Scan a list of targets for exposed debug mode."""
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = [detect_debug_mode(client, normalize_url(target), semaphore) for target in targets]
        results = await asyncio.gather(*tasks)

        findings = [result for result in results if result]
        for finding in findings:
            debug_flag = "CRITICAL" if finding["debug_mode"] else "INFO"
            endpoint_info = f" at endpoint {finding['endpoint']}" if finding["endpoint"] else ""
            print_status(debug_flag, f"Debug mode detected on {finding['url']}{endpoint_info}")

        if output_file:
            with open(output_file, "w") as f:
                json.dump(findings, f, indent=4)
            print_status("INFO", f"Wrote results to {output_file}")

# ── CLI Argument Parsing ────────────────────────────────────────────────────

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Flask Debug Mode Scanner")
    parser.add_argument("--target", type=str, help="Single URL to scan.")
    parser.add_argument("--list", type=str, help="File containing list of URLs to scan.")
    parser.add_argument("--output", type=str, help="Write scan results to a specified JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection only, no active probing.")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification.")
    return parser.parse_args()

# ── Main Execution ───────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Validate input source
    if not args.target and not args.list:
        print_status("CRITICAL", "Error: You must specify --target or --list.")
        sys.exit(1)
    
    # Compile list of targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print_status("CRITICAL", f"Error: File {args.list} not found.")
            sys.exit(1)

    # Run scanner
    print_status("INFO", f"Scanning {len(targets)} target(s)...")
    asyncio.run(
        scan_targets(targets, args.concurrency, args.safe, args.output, args.no_verify)
    )
    print_status("INFO", "Scan completed.")

if __name__ == "__main__":
    main()
