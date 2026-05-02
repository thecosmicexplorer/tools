#!/usr/bin/env python3
"""
Django Debug Mode SSRF Scanner
===============================
Scans for Django web applications running with DEBUG mode enabled and probes for
potential server-side request forgery (SSRF) vulnerabilities.

Vulnerability details:
  - DEBUG mode in Django returns verbose error pages containing internal IP addresses and URLs.
  - Potential SSRF vulnerability arises due to the exposure of sensitive internal endpoints that attackers can exploit.
  - Exposes sensitive stack trace information which further aids attackers in exploitation.

Detection capabilities:
  - Identifies Django applications running with DEBUG mode enabled.
  - Probes endpoints that might yield SSRF vulnerabilities.
  - Offers safe mode for detection-only scans without active probing.

Usage:
  # Scan a single target
  python django_debug_mode_ssrf_scanner.py --target https://example.com

  # Scan a list of targets
  python django_debug_mode_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection-only
  python django_debug_mode_ssrf_scanner.py --target https://example.com --safe

References:
  - https://docs.djangoproject.com/en/stable/ref/settings/#debug
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  - https://nvd.nist.gov/vuln/search/results?form_type=AdvancedSearch&results_type=overview&query=Django

"""

import asyncio
import json
import re
import argparse
from datetime import datetime
from urllib.parse import urlparse

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

DJANGO_DEBUG_MARKERS = [
    # Common strings in DEBUG mode error pages
    "It worked!",  # Default debug page message
    "You're seeing this error because you have DEBUG = True",
    "django.db.backends",
    "Request Method:",  # Debug error page
    "Settings:",  # Debug error page
    "Environment:",  # Debug error page
    "exceptionreporter-filter",
    "System Check Identified No Issues",
]

# Additional paths to fingerprint debug mode or configuration exposure
DETECTION_PATHS = [
    "/",
    "/admin/",  # Default admin page
    "/debug/",  # Custom debug paths
    "/debug/error",  # Made-up path for testing error responses
]

# ── Active probes ─────────────────────────────────────────────────────────────
# Safe probe returning instance context.
URL_PROBE = "/debug/context"
FAKE_SSRF_PAYLOAD = "http://127.0.0.1:22/"

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

ANSI_COLORS = {
    'RESET': '\033[0m',
    'RED': '\033[91m',
    'YELLOW': '\033[93m',
    'GREEN': '\033[92m',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def color_text(color, text):
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['RESET']}"


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def format_output(findings, output_file=None):
    """Output findings to console and optionally save to JSON file."""
    if output_file:
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=4)
    for item in findings:
        status = color_text('GREEN', 'INFO')
        if item['risk_level'] == 'HIGH':
            status = color_text('YELLOW', 'HIGH')
        elif item['risk_level'] == 'CRITICAL':
            status = color_text('RED', 'CRITICAL')

        print(f"[{status}] {item['url']} - {item['description']}")


async def fetch_url(client, url, semaphore):
    """Fetch a URL and return the response text."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            return response.text or ""
        except httpx.RequestError:
            return ""


# ── Core scanner ──────────────────────────────────────────────────────────────

async def scan_target(client, target, semaphore, safe_mode=False):
    """
    Scan a single target URL for Django DEBUG mode and SSRF vulnerabilities.
    Returns a dictionary with scan results.
    """
    async with semaphore:
        normalized_url = normalize_url(target)
        findings = []
        is_debug_mode = False

        for path in DETECTION_PATHS:
            url = f"{normalized_url}{path}"
            response_text = await fetch_url(client, url, semaphore)
            if any(marker in response_text for marker in DJANGO_DEBUG_MARKERS):
                is_debug_mode = True
                findings.append({
                    "url": url,
                    "risk_level": "HIGH",
                    "description": "DEBUG mode detection. Sensitive information exposed.",
                })
                break  # Debug mode identified, no need to scan further paths
        
        if is_debug_mode and not safe_mode:
            probe_url = f"{normalized_url}{URL_PROBE}?url={FAKE_SSRF_PAYLOAD}"
            probe_response = await fetch_url(client, probe_url, semaphore)
            if FAKE_SSRF_PAYLOAD in probe_response:
                findings.append({
                    "url": probe_url,
                    "risk_level": "CRITICAL",
                    "description": "Potential SSRF vulnerability detected via active probe.",
                })

        return findings


async def scan(targets, safe_mode=False, concurrency=SEMAPHORE_LIMIT):
    """Perform scanning on a list of target URLs."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [scan_target(client, target, semaphore, safe_mode) for target in targets]
        all_findings = await asyncio.gather(*tasks)

        for findings in all_findings:
            results.extend(findings)

    return results


# ── CLI setup and execution ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Django Debug Mode SSRF Scanner")
    parser.add_argument("--target", help="URL of the target to scan.")
    parser.add_argument("--list", help="File containing list of target URLs.")
    parser.add_argument("--output", help="Save findings to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT,
                        help="Number of concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate validation.")

    args = parser.parse_args()

    # Configure client settings
    client_options = {}
    if args.no_verify:
        client_options['verify'] = False

    # Load targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print(color_text('RED', "[CRITICAL] No targets specified. Use --target or --list."))
        return

    # Run the scanner
    results = asyncio.run(scan(targets, safe_mode=args.safe, concurrency=args.concurrency))
    format_output(results, args.output)


if __name__ == "__main__":
    main()
