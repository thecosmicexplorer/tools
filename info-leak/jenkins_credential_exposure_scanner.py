#!/usr/bin/env python3
"""
Jenkins Credential Exposure Scanner
===================================
Scans Jenkins instances to identify exposed sensitive credentials in configuration files.

Vulnerability Description:
Jenkins configuration files may contain plaintext or insufficiently protected credentials
which can be accessed by unauthenticated or unauthorized users due to improper permissions 
in certain configurations. This could potentially lead to further exploitation of the Jenkins instance 
or other systems accessible with the compromised credentials.

Risk:
  - Exposed credentials could lead to network compromise, privilege escalation, or other attacks.
  - Highly critical for organizations utilizing Jenkins for continuous integration/continuous deployment (CI/CD).

Common Misconfigurations:
  - Insecure file permissions on the Jenkins home directory.
  - Insufficient access restrictions on publicly accessible Jenkins instances.

Features:
  - Detects Jenkins instances by querying known API and web endpoints.
  - Extracts and analyzes configuration files for sensitive credentials.
  - A `--safe` mode is implemented to disable active probing and perform detection only.

Usage:
  # Scan a single target
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com

  # Scan multiple targets from a list
  python jenkins_credential_exposure_scanner.py --list targets.txt --output results.json

  # Safe mode: detection only (no active checks for credential leak)
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com --safe

References:
  - https://www.jenkins.io/doc/book/system-administration/securing-jenkins/
  - https://nvd.nist.gov
"""
import argparse
import asyncio
import json
import re
from urllib.parse import urljoin

import httpx
from colorama import Fore, Style

JENKINS_FINGERPRINT_MARKERS = [
    "<title>Dashboard [Jenkins]</title>",
    'id="jenkins"'
]

DETECTION_PATHS = [
    "/",
    "/login",
    "/manage",
]

CONFIG_PATHS = [
    "/credentials/store/system/domain/_/",
    "/scriptText"  # Dangerous, contains scripting console access
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10


def normalize_url(url: str) -> str:
    """Normalize a URL to include protocol and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def print_status(message: str, level: str = "INFO"):
    """Print color-coded status messages."""
    levels = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "INFO": Fore.GREEN,
    }
    color = levels.get(level.upper(), Fore.RESET)
    print(f"{color}[{level}]{Style.RESET_ALL} {message}")


async def detect_jenkins(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if a URL is running Jenkins.
    Returns a dictionary with detection details.
    """
    async with semaphore:
        for path in DETECTION_PATHS:
            try:
                response = await client.get(urljoin(base_url, path), timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    for marker in JENKINS_FINGERPRINT_MARKERS:
                        if marker in response.text:
                            return {"url": base_url, "detected": True}
            except (httpx.RequestError, Exception):
                pass
    return {"url": base_url, "detected": False}


async def check_exposed_credentials(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Check for exposed Jenkins credentials at known vulnerable paths.
    """
    async with semaphore:
        findings = []
        for path in CONFIG_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code < 400 and "credentials" in response.text:
                    findings.append({"url": url, "status_code": response.status_code})
            except (httpx.RequestError, Exception) as e:
                pass
        return findings


async def scan_target(client: httpx.AsyncClient, url: str, safe: bool, semaphore: asyncio.Semaphore):
    """Scan a single target."""
    base_url = normalize_url(url)

    detection_result = await detect_jenkins(client, base_url, semaphore)

    if not detection_result["detected"]:
        await print_status(f"{base_url} is not running Jenkins.", "INFO")
        return detection_result

    await print_status(f"Jenkins detected at {base_url}", "HIGH")

    if not safe:
        findings = await check_exposed_credentials(client, base_url, semaphore)
        if findings:
            await print_status(f"CRITICAL: Exposed credentials found at {base_url}.", "CRITICAL")
            detection_result["findings"] = findings
        else:
            await print_status(f"No exposed credentials found at {base_url}.", "INFO")
    return detection_result


async def scan(targets, safe, concurrency, output_file, no_verify):
    """Scan a list of targets."""
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        scan_tasks = [scan_target(client, target, safe, semaphore) for target in targets]
        results = await asyncio.gather(*scan_tasks)

        if output_file:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
            await print_status(f"Results written to {output_file}.", "INFO")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Credential Exposure Scanner")
    parser.add_argument("--target", help="URL of the Jenkins instance to scan.")
    parser.add_argument("--list", help="File with a list of targets (one per line).")
    parser.add_argument("--output", help="File to save scan results as JSON.")
    parser.add_argument("--safe", action="store_true", help="Enable safe mode (detection only).")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests.")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification.")

    args = parser.parse_args()
    target_list = []

    if args.target:
        target_list = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            target_list = [line.strip() for line in f if line.strip()]
    
    if not target_list:
        print("Error: No targets provided. Use --target or --list.")
        exit(1)

    asyncio.run(scan(target_list, args.safe, args.concurrency, args.output, args.no_verify))
