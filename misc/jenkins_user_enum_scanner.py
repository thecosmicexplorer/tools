#!/usr/bin/env python3
"""
Jenkins User Enumeration Scanner
=================================
This tool helps detect username enumeration vulnerabilities in Jenkins CI/CD servers.
Jenkins, being a popular automation server, commonly exposes sensitive endpoints
that attackers can abuse to enumerate valid user accounts, especially on misconfigured
instances. This scanner targets several known endpoints and heuristics for identifying 
the vulnerability.

Vulnerability Details:
  - Multiple historical CVEs and techniques allow attackers to identify existing Jenkins users 
    without authentication.
  - Potential attack vectors include the login page, API responses, error messages, and autocomplete
    hints.
  - Useful for gathering credentials during penetration tests or bug bounty assessments.

Dependencies:
  - `httpx` (required for asynchronous HTTP requests)
  - Python 3.10+

Usage:
  # Scan a single target URL
  python jenkins_user_enum_scanner.py --target https://jenkins.example.com

  # Scan multiple target URLs from a file
  python jenkins_user_enum_scanner.py --list targets.txt --output findings.json

  # Use safe mode to avoid probing for enumeration
  python jenkins_user_enum_scanner.py --list targets.txt --safe

  # Set custom concurrency for batch scanning
  python jenkins_user_enum_scanner.py --list targets.txt --concurrency 50

References:
  - https://www.jenkins.io/security/
  - https://nvd.nist.gov/vuln/detail/CVE-2018-1000110
  - https://portswigger.net/daily-swig/jenkins-administrator-account-found-open-to-enumeration
"""

import asyncio
import argparse
import httpx
import json
import re
import sys
from urllib.parse import urljoin

# Constants
DEFAULT_USERNAMES = [
    "admin",
    "administrator",
    "jenkins",
    "test",
    "root",
    "demo",
]
ENUM_ENDPOINTS = [
    "/asynchPeople/",
    "/login",
    "/user/%s/",
]
USER_REGEX_TEMPLATE = r">%s</a>|%s"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# ANSI colors
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "GREEN": "\033[92m",
}

# Helper Functions
def normalize_url(url):
    """Ensure the URL contains a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def display_message(level, message):
    """Print a message with ANSI colors for visual context."""
    color = COLORS.get(level, COLORS["RESET"])
    print(f"{color}{message}{COLORS['RESET']}")

async def detect_jenkins(client, base_url, semaphore):
    """Check if a target URL is using Jenkins."""
    async with semaphore:
        try:
            response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "Jenkins" in response.text:
                display_message("INFO", f"[INFO] Detected Jenkins at {base_url}")
                return True
        except Exception:
            pass
    return False

async def enumerate_usernames(client, base_url, semaphore, username_list, safe_mode):
    """
    Attempt user enumeration by probing endpoints and analyzing responses.
    
    Returns:
        - List of enumerated usernames.
    """
    valid_users = []
    async with semaphore:
        for username in username_list:
            for endpoint in ENUM_ENDPOINTS:
                url = urljoin(base_url, endpoint.replace("%s", username))
                try:
                    response = await client.get(url, timeout=REQUEST_TIMEOUT)
                    if safe_mode:
                        # Only detect if username appears in response
                        if re.search(USER_REGEX_TEMPLATE % (username, username), response.text):
                            valid_users.append(username)
                            display_message("INFO", f"[INFO] Detected user: {username} at {url}")
                    else:
                        # Direct probing using error responses
                        if response.status_code in [200, 404]:
                            valid_users.append(username)
                            display_message("HIGH", f"[HIGH] Enumerated user: {username}")
                except Exception:
                    pass
    return valid_users

# Main Scanner Logic
async def run_scanner(targets, options):
    results = []
    semaphore = asyncio.Semaphore(options.concurrency)
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = []
        for target in targets:
            base_url = normalize_url(target)
            tasks.append(scan_target(client, base_url, semaphore, options))
        results = await asyncio.gather(*tasks)
    return results

async def scan_target(client, base_url, semaphore, options):
    """
    Scan a single Jenkins instance for username enumeration vulnerabilities.
    
    Returns:
        - Dictionary containing scan results for the target.
    """
    result = {"target": base_url, "jenkins_detected": False, "enumerated_users": []}
    try:
        is_jenkins = await detect_jenkins(client, base_url, semaphore)
        result["jenkins_detected"] = is_jenkins
        if is_jenkins:
            valid_users = await enumerate_usernames(client, base_url, semaphore, options.username_list, options.safe)
            result["enumerated_users"] = valid_users
    except Exception as exc:
        display_message("RED", f"[CRITICAL] Error scanning {base_url}: {str(exc)}")
    return result

# CLI Argument Parsing
def parse_args():
    parser = argparse.ArgumentParser(description="Jenkins User Enumeration Scanner")
    parser.add_argument("--target", type=str, help="Target URL")
    parser.add_argument("--list", type=str, help="File with list of target URLs")
    parser.add_argument("--output", type=str, help="Output results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection only (no enumeration probing)")
    parser.add_argument("--concurrency", type=int, default=30, help="Concurrency level (default: 30)")
    parser.add_argument("--usernames", type=str, help="Custom username list (comma-separated)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    return parser.parse_args()

def load_targets(file_path):
    """Load target URLs from a file."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as exc:
        display_message("RED", f"[CRITICAL] Failed to load targets: {str(exc)}")
        sys.exit(1)

# Entry Point
if __name__ == "__main__":
    args = parse_args()

    if not (args.target or args.list):
        display_message("RED", "[CRITICAL] You must specify either --target or --list")
        sys.exit(1)
    
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        targets = load_targets(args.list)

    username_list = DEFAULT_USERNAMES
    if args.usernames:
        username_list = args.usernames.split(",")

    options = {
        "safe": args.safe,
        "concurrency": args.concurrency,
        "username_list": username_list,
        "no_verify": args.no_verify,
    }

    results = asyncio.run(run_scanner(targets, options))

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            display_message("INFO", f"[INFO] Results saved to {args.output}")
        except Exception as exc:
            display_message("RED", f"[CRITICAL] Failed to save results: {str(exc)}")
    else:
        print(json.dumps(results, indent=4))
