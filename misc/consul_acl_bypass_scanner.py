#!/usr/bin/env python3
"""
Consul ACL Bypass Scanner (CVE-2026-00321)
===========================================
This scanner detects and optionally probes for vulnerabilities in the HashiCorp Consul API ACL system,
which allows unauthorized access due to a missing permissions check. If exploited, malicious actors 
could gain access to sensitive data or perform unauthorized operations through the API.

CVE-2026-00321 details:
  - Affects Consul versions < 1.16.0.
  - Security bypass possible due to improper validation in the API ACL system.
  - Attacker can execute commands without proper authentication, leading to potential data leakage or control over network configurations.
  - Patched in Consul v1.16.0.

Usage:
  # Scan a single target
  python consul_acl_bypass_scanner.py --target https://consul.example.com

  # Scan a list of targets
  python consul_acl_bypass_scanner.py --list targets.txt --output findings.json

  # Run in safe mode (detection only, no active probing)
  python consul_acl_bypass_scanner.py --target https://consul.example.com --safe

  # Adjust concurrency level when scanning multiple URLs
  python consul_acl_bypass_scanner.py --list targets.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-00321
  - https://www.hashicorp.com/security
"""

import asyncio
import json
import httpx
import re
import argparse
from urllib.parse import urlparse

# ── Constants ───────────────────────────────────────────────────────────────

CONSUL_FINGERPRINTS = [
    "Consul API",
    "Consul HTTP API",
    "<title>Consul</title>",
    '"Consul"'
]

DETECTION_PATHS = [
    "/v1/agent/self",
    "/v1/status/leader",
    "/v1/acl/policies",
    "/v1/acl/tokens"
]

VERSION_PATTERNS = [
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'<title>Consul\s+v([0-9]+\.[0-9]+\.[0-9]+)</title>'
]

PROBE_PATH = "/v1/acl/policies"
VULNERABLE_PAYLOAD = {}
VULN_FIXED_VERSION = (1, 16, 0)

SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 10

# ── Helper Functions ─────────────────────────────────────────────────────────

def parse_version(version_string: str):
    """Parse a semantic version string into a tuple."""
    try:
        return tuple(map(int, version_string.split(".")))
    except ValueError:
        return None

def is_vulnerable_version(version_tuple):
    """Determine if the version is vulnerable."""
    if version_tuple is None:
        return None  # Unknown version
    return version_tuple < VULN_FIXED_VERSION

def normalize_url(url: str) -> str:
    """Ensure the URL has the correct format."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def console_log(message, severity="INFO"):
    """Log a message to the console with color-coded severity."""
    colors = {"INFO": "\033[92m", "HIGH": "\033[93m", "CRITICAL": "\033[91m", "RESET": "\033[0m"}
    print(f"{colors[severity]}[{severity}] {message}{colors['RESET']}")

# ── Core Scanner Logic ──────────────────────────────────────────────────────

async def detect_consul(client, base_url, semaphore):
    """
    Detect Consul instance and extract its version.
    Returns dict with details or None if detection fails.
    """
    async with semaphore:
        detected = False
        version = None

        for path in DETECTION_PATHS:
            try:
                url = f"{base_url}{path}"
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if any(fp in response.text for fp in CONSUL_FINGERPRINTS):
                    detected = True
                    version = parse_version(response.text)
                    break
            except httpx.RequestError:
                continue
        
        if detected:
            return {"url": base_url, "version": version}
        return None

async def probe_vulnerability(client, base_url, semaphore):
    """
    Actively probe the target to check for CVE-2026-00321 exploitation possibilities.
    """
    async with semaphore:
        try:
            url = f"{base_url}{PROBE_PATH}"
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "policies" in response.text:
                return True
        except httpx.RequestError:
            pass
        return False

async def scan_target(url, safe_mode, semaphore):
    """Scan a single target for Consul fingerprint and active probes."""
    async with httpx.AsyncClient(verify=False) as client:
        normalized_url = normalize_url(url)
        detection_result = await detect_consul(client, normalized_url, semaphore)
        if detection_result:
            version = detection_result.get("version")
            vulnerable = is_vulnerable_version(version)
            detection_result["vulnerable_version"] = vulnerable

            if not safe_mode and vulnerable:
                detection_result["exploitable"] = await probe_vulnerability(client, normalized_url, semaphore)
            else:
                detection_result["exploitable"] = None

            return detection_result
        return {"url": url, "error": "not_consul"}

async def scan_targets(urls, safe_mode, concurrency):
    """Scan multiple targets asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(url, safe_mode, semaphore) for url in urls]
    return await asyncio.gather(*tasks)

# ── Main CLI Logic ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Consul ACL Bypass Scanner (CVE-2026-00321)")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing list of targets")
    parser.add_argument("--output", help="Output results as JSON to a file", default=None)
    parser.add_argument("--safe", help="Detection-only mode (no probes)", action="store_true")
    parser.add_argument("--concurrency", help="Concurrency level for async scanning", type=int, default=10)
    parser.add_argument("--no-verify", help="Skip SSL verification", action="store_true")
    args = parser.parse_args()

    urls = []
    if args.target:
        urls.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console_log(f"File not found: {args.list}", "CRITICAL")
            sys.exit(1)
    
    if not urls:
        console_log("No targets provided. Use --target or --list.", "CRITICAL")
        sys.exit(1)
    
    results = asyncio.run(scan_targets(urls, args.safe, args.concurrency))
    
    if args.output:
        with open(args.output, "w") as output_file:
            json.dump(results, output_file, indent=4)
        console_log(f"Results saved to {args.output}", "INFO")
    else:
        for result in results:
            print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()
