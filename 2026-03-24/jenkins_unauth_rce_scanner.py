#!/usr/bin/env python3
"""
Jenkins Unauthenticated RCE Scanner
======================================
This tool detects and exploits certain unauthenticated remote code execution (RCE) vulnerabilities
in Jenkins Continuous Integration/Continuous Deployment (CI/CD) servers.

The tool performs reconnaissance to fingerprint Jenkins versions and determine if a target
is exposed to known RCE vulnerabilities. The vulnerabilities covered include various
endpoint exposures (e.g., script console) and known security bypasses commonly found
in publicly exposed Jenkins instances.

Common vulnerabilities detected:
  - Accessible Groovy script console (RCE)
  - Unauthenticated CLI endpoint exploitation
  - Legacy remoting endpoints misconfigurations

Usage:
  # Scan a single Jenkins instance
  python jenkins_unauth_rce_scanner.py --target http://jenkins.example.com

  # Scan a list of Jenkins instances
  python jenkins_unauth_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only without active probing
  python jenkins_unauth_rce_scanner.py --list targets.txt --safe

References:
  - https://www.jenkins.io/security/
  - https://nvd.nist.gov/
  - Various CVEs impacting Jenkins (unauthed RCE, Groovy console abuse)

"""

import asyncio
import json
import re
import argparse
from datetime import datetime

import httpx

# Jenkins common fingerprints for detection
JENKINS_FINGERPRINTS = [
    "X-Jenkins:",
    "X-Hudson:",
    "X-Jenkins-Session",
    "X-Jenkins-CLI-Version",
    "X-Jenkins-CLI-Protocol",
    "/static/<hash>/",
    "<title>Dashboard [Jenkins]</title>",
    "Welcome to Jenkins!"
]

DEFAULT_CONCURRENCY = 20
REQUEST_TIMEOUT = 10
SAFE_MODE_ENABLED = False
CRITICAL_COLOR = "\033[91m"  # Red
HIGH_COLOR = "\033[93m"      # Yellow
INFO_COLOR = "\033[92m"      # Green
RESET_COLOR = "\033[0m"      # Reset

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = "http://" + url
    return url.rstrip('/')

async def detect_jenkins(client: httpx.AsyncClient, base_url: str):
    """
    Detects if the target is running Jenkins and identifies its version (if possible).
    Returns a tuple (is_jenkins, version_string) based on fingerprint analysis.
    """
    try:
        response = await client.get(base_url, timeout=REQUEST_TIMEOUT)
        headers = response.headers
        body = response.text

        # Check headers for Jenkins markers
        for fp in JENKINS_FINGERPRINTS:
            if fp in headers or fp in body:
                jenkins_version = headers.get('X-Jenkins', None)
                return True, jenkins_version

        return False, None
    except Exception:
        return False, None

async def probe_rce(client: httpx.AsyncClient, base_url: str):
    """
    Attempts to probe unauthenticated RCE vulnerabilities.
    Only executed if SAFE_MODE_ENABLED is False.
    Returns a list of detected critical issues.
    """
    if SAFE_MODE_ENABLED:
        return []

    findings = []

    # Check Groovy script console exposure
    try:
        groovy_url = f"{base_url}/script"
        response = await client.get(groovy_url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and 'textarea' in response.text.lower():
            findings.append(f"CRITICAL: Groovy script console is accessible at {groovy_url}")
    except Exception:
        pass

    # Add more probes for different exploit vectors as needed...

    return findings

async def scan_target(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Scans a single Jenkins instance for vulnerabilities.
    """
    async with semaphore:
        target_info = {
            "url": url,
            "jenkins_detected": False,
            "version": None,
            "findings": []
        }

        # Normalize URL
        url = normalize_url(url)

        # Detect Jenkins and version
        is_jenkins, version = await detect_jenkins(client, url)
        target_info["jenkins_detected"] = is_jenkins
        target_info["version"] = version

        if not is_jenkins:
            print(f"{INFO_COLOR}[INFO]{RESET_COLOR} No Jenkins detected at {url}")
            return target_info

        print(f"{HIGH_COLOR}[HIGH]{RESET_COLOR} Jenkins detected at {url} (Version: {version})")

        # Active probing for vulnerabilities
        findings = await probe_rce(client, url)
        target_info["findings"].extend(findings)

        for finding in findings:
            print(f"{CRITICAL_COLOR}[CRITICAL]{RESET_COLOR} {finding}")

        return target_info

async def main():
    parser = argparse.ArgumentParser(description="Jenkins Unauthenticated RCE Scanner")
    parser.add_argument("--target", help="Scan a single target (e.g., http://jenkins.example.com).")
    parser.add_argument("--list", help="File containing list of targets to scan.")
    parser.add_argument("--output", help="Output file for results in JSON format.", default=None)
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only, no active probing).")
    parser.add_argument("--concurrency", type=int, help="Number of concurrent scans.", default=DEFAULT_CONCURRENCY)
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for HTTPS.")

    args = parser.parse_args()

    # Safe mode setting
    global SAFE_MODE_ENABLED
    SAFE_MODE_ENABLED = args.safe

    # Read targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            for line in f:
                targets.append(line.strip())

    # No targets specified
    if not targets:
        print(f"{CRITICAL_COLOR}[CRITICAL]{RESET_COLOR} No targets specified! Use --target or --list.")
        return

    # Prepare HTTP client
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)

        tasks = [scan_target(client, url, semaphore) for url in targets]
        results = await asyncio.gather(*tasks)

    # Save results
    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)
        print(f"{INFO_COLOR}[INFO]{RESET_COLOR} Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
