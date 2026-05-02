#!/usr/bin/env python3
"""
Jenkins Configuration Exposure Scanner
======================================
This scanner detects instances of Jenkins exposed to the internet, checks for insecure configuration file exposure, 
and optionally probes whether sensitive configuration files can be retrieved (e.g., credentials, security configurations).

Vulnerability Details:
  - Affects Jenkins instances with improper configuration allowing access to sensitive files.
  - Commonly exposed paths include /scripts/, /config.xml, /secrets/, /credentials/, and other sensitive directories.
  - Insecure configurations can leak sensitive information, enabling further exploitation, such as privilege escalation.

Usage:
  # Scan a single Jenkins target
  python jenkins_config_exposure_scanner.py --target https://jenkins.example.com

  # Scan a list of Jenkins targets
  python jenkins_config_exposure_scanner.py --list targets.txt --output findings.json

  # Perform safe detection without attempting to download sensitive files
  python jenkins_config_exposure_scanner.py --list targets.txt --safe

  # Adjust concurrency level
  python jenkins_config_exposure_scanner.py --list targets.txt --concurrency 50

References:
  - https://www.jenkins.io/doc/book/security/
  - https://nvd.nist.gov/vuln/detail/CVE-2021-21650
  - https://owasp.org/www-project-top-ten/
"""

import asyncio
import json
import os
import argparse
import re
from datetime import datetime
from urllib.parse import urljoin

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

JENKINS_FINGERPRINTS = [
    # Patterns specific to Jenkins login pages
    "Welcome to Jenkins!",
    "Jenkins instance appears to be offline",
    "Dashboard [Jenkins]",
]

DETECTION_PATHS = [
    "/", 
    "/login",  
    "/api/json",  
]

EXPOSED_CONFIG_PATHS = [
    "/config.xml",
    "/secrets/master.key",
    "/secrets/hudson.util.Secret",
    "/users",
    "/script/",
]

VULN_FIXED_CHAR_RE = r"<\?xml version="

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ANSI Colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def json_output(results, output_file):
    """Write scan results to JSON output file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)


# ── Scanner functions ─────────────────────────────────────────────────────────

async def detect_jenkins(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is likely running Jenkins.
    Returns dict with detection info, or None if not detected.
    """
    async with semaphore:
        detected = False
        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if any(fp.lower() in response.text.lower() for fp in JENKINS_FINGERPRINTS):
                    detected = True
                    server_version = response.headers.get("x-jenkins")
                    return {
                        "url": base_url,
                        "detected": detected,
                        "server_version": server_version,
                        "path_checked": path,
                    }
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
        return None


async def probe_sensitive_files(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Probe sensitive file paths on a detected Jenkins server.
    Returns a list of exposed files with response details.
    """
    async with semaphore:
        exposed_files = []
        for path in EXPOSED_CONFIG_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    exposed_files.append({
                        "file": path,
                        "status_code": response.status_code,
                        "content_snippet": response.text[:150]
                    })
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue
        return exposed_files


async def scan_target(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore, safe_mode=False):
    """
    Scan a single Jenkins target for configuration exposure vulnerabilities.
    """
    result = {"target": target, "detected": False, "issues": []}
    normalized_url = normalize_url(target)

    detection_info = await detect_jenkins(client, normalized_url, semaphore)
    if detection_info and detection_info["detected"]:
        result["detected"] = True
        result["server_version"] = detection_info.get("server_version")
        if not safe_mode:
            exposed_files = await probe_sensitive_files(client, normalized_url, semaphore)
            result["issues"] = exposed_files

    return result


# ── Main ────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Jenkins Configuration Exposure Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan.")
    parser.add_argument("--list", type=str, help="Path to a file with a list of target URLs.")
    parser.add_argument("--output", type=str, help="File path to save JSON results.")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no probes).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Maximum concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification.")

    args = parser.parse_args()

    # Input validation
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{RED}[ERROR] Failed to read targets list: {e}{RESET}")
            sys.exit(1)

    if not targets:
        print(f"{RED}[ERROR] No targets provided.{RESET}")
        sys.exit(1)

    concurrency = args.concurrency
    semaphore = asyncio.Semaphore(concurrency)

    verify_ssl = not args.no_verify

    async with httpx.AsyncClient(verify=verify_ssl) as client:
        tasks = [scan_target(client, target, semaphore, safe_mode=args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Output results
    if args.output:
        json_output(results, args.output)
        print(f"{GREEN}[INFO] Results written to {args.output}{RESET}")
    else:
        for result in results:
            color = RED if result["issues"] else GREEN
            print(f"{color}- {result['target']}: {'Vulnerable' if result['issues'] else 'Safe'}{RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{RED}[ERROR] Scan interrupted by user.{RESET}")
