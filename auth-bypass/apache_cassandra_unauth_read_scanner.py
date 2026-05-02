#!/usr/bin/env python3
"""
Apache Cassandra CVE-2022-46781 Unauthenticated Read Access Scanner
======================================================================
Scans for Apache Cassandra database servers and verifies if they are vulnerable
to unauthenticated arbitrary data read access due to the lack of proper authentication.

CVE-2022-46781 details:
  - Affects Apache Cassandra versions <= 3.0.26, 3.11.12, 4.0.6
  - Unauthenticated access to a certain exposed HTTP endpoint allows data enumeration
  - Exploitation may result in unauthorized access to sensitive information
  - Fixed in later releases by requiring authentication headers in these calls
  
Usage:
  # Scan a single target
  python apache_cassandra_unauth_read_scanner.py --target http://cassandra.example.com

  # Scan a list of targets
  python apache_cassandra_unauth_read_scanner.py --list targets.txt --output findings.json

  # Perform detection only (without sending vulnerable probes)
  python apache_cassandra_unauth_read_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-46781
  - https://cassandra.apache.org/security/CVE-2022-46781
"""

import asyncio
import json
import re
import httpx
import argparse
from urllib.parse import urljoin
from colorama import Fore, Style

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8
VULN_FIXED_VERSION_3 = (3, 0, 27)
VULN_FIXED_VERSION_311 = (3, 11, 13)
VULN_FIXED_VERSION_4 = (4, 0, 7)

DETECTION_PATHS = [
    "/",
    "/metrics",
    "/api/v1/cluster/topology",
]
VERSION_PATH = "/version"

def parse_version(version_str):
    """Parse version strings (e.g., '4.0.5') into a comparable tuple."""
    try:
        return tuple(map(int, re.match(r"(\d+)\.(\d+)\.(\d+)", version_str).groups()))
    except (AttributeError, ValueError):
        return None

def is_vulnerable_version(version):
    """Determine if the version is vulnerable based on known fixed versions."""
    if version is None:
        return None  # Unidentifiable version
    major, minor, patch = version
    if major == 3 and minor == 0 and version < VULN_FIXED_VERSION_3:
        return True
    if major == 3 and minor == 11 and version < VULN_FIXED_VERSION_311:
        return True
    if major == 4 and minor == 0 and version < VULN_FIXED_VERSION_4:
        return True
    return False

async def detect_cassandra(client, base_url, semaphore):
    """Detect Apache Cassandra server and extract version."""
    async with semaphore:
        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if "cassandra" in response.text.lower() or "org.apache.cassandra" in response.text:
                    version_info_resp = await client.get(urljoin(base_url, VERSION_PATH), timeout=REQUEST_TIMEOUT)
                    version = parse_version(version_info_resp.text)
                    return {"detected": True, "version": version, "base_url": base_url}
            except httpx.HTTPError:
                continue
        return {"detected": False, "version": None, "base_url": base_url}

async def probe_vulnerability(client, base_url, semaphore):
    """Attempt to trigger unauthenticated read access to sensitive data."""
    async with semaphore:
        vulnerable = False
        url = urljoin(base_url, "/api/v1/cluster/topology")
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "datacenter" in response.text.lower():
                vulnerable = True
        except httpx.HTTPError:
            pass
        return {"base_url": base_url, "vulnerable": vulnerable}

async def scan_target(target, semaphore, safe_mode):
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        detection_result = await detect_cassandra(client, target, semaphore)
        if detection_result["detected"]:
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Detected Apache Cassandra at {target}")
            detection_result["vulnerable"] = None
            if detection_result["version"]:
                if is_vulnerable_version(detection_result["version"]):
                    print(f"{Fore.YELLOW}[HIGH]{Style.RESET_ALL} Version {detection_result['version']} might be vulnerable")
                    if not safe_mode:
                        vuln_result = await probe_vulnerability(client, target, semaphore)
                        detection_result["vulnerable"] = vuln_result["vulnerable"]
                        if detection_result["vulnerable"]:
                            print(f"{Fore.RED}[CRITICAL]{Style.RESET_ALL} {target} is VULNERABLE to CVE-2022-46781!")
                        else:
                            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {target} is NOT vulnerable")
                else:
                    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Target is running a patched version")
            else:
                print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} Could not determine version for {target}")
        else:
            print(f"{Fore.RED}[INFO]{Style.RESET_ALL} {target} does not appear to be running Apache Cassandra")
        return detection_result

async def main():
    parser = argparse.ArgumentParser(description="Apache Cassandra CVE-2022-46781 Unauthorized Read Access Scanner")
    parser.add_argument("--target", help="The target URL to scan (e.g., http://example.com)")
    parser.add_argument("--list", help="Path to a file containing a list of target URLs to scan")
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--safe", action="store_true", help="Perform detection only, no active vulnerability probe")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    args = parser.parse_args()

    semaphore = asyncio.Semaphore(args.concurrency)
    targets = []

    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to read list file: {e}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    results = []
    tasks = [scan_target(target, semaphore, args.safe) for target in targets]
    for future in asyncio.as_completed(tasks):
        results.append(await future)

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Results saved to {args.output}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to save results: {e}")

if __name__ == "__main__":
    asyncio.run(main())
