#!/usr/bin/env python3
"""
Jenkins Pipeline Environment Variable Injection Scanner
========================================================
Scans Jenkins instances for environment variable injection vulnerabilities in Pipeline configurations. Exploitable 
injections may lead to unauthorized remote code execution (RCE) or sensitive data exposure.

Vulnerability details:
  - Affects Jenkins environments with misconfigured Pipeline jobs allowing arbitrary environment variables.
  - Attackers can inject malicious variables that are executed in the job’s runtime environment.
  - Exploitation can result in command execution or leakage of sensitive information.

Usage:
  # Scan a single target
  python jenkins_pipeline_env_injection_scanner.py --target https://jenkins.example.com

  # Scan multiple targets from a list
  python jenkins_pipeline_env_injection_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only
  python jenkins_pipeline_env_injection_scanner.py --target https://jenkins.example.com --safe

References:
  - https://www.jenkins.io/security/
  - https://owasp.org/www-project-top-ten/
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urlparse

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

JENKINS_FINGERPRINTS = [
    # Common Jenkins UI elements or HTTP headers
    "<title>Dashboard [Jenkins]</title>",
    "Jenkins-Crumb",
    "X-Jenkins-Session",
    "class=\"jenkins_header\"",
]

DETECTION_PATHS = [
    "/",
    "/login",
    "/view/All/",
]

VERSION_PATTERNS = [
    r"X-Jenkins:(?:\s*)([0-9]+\.[0-9]+\.[0-9]+)",
]

VULN_FIXED_VERSION = (2, 389, 3)

SEMAPHORE_LIMIT = 25
REQUEST_TIMEOUT = 8

# Probing path for the environment variables test
ENV_INJECT_TEST_PATH = "/job/{job_name}/build"

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse the first version string found in HTTP headers."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            try:
                return tuple(map(int, match.group(1).split(".")))
            except ValueError:
                pass
    return None

def is_vulnerable_version(version_tuple):
    """Return True if version is below the fixed version."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION

def normalize_url(url: str) -> str:
    """Ensure URL starts with http:// or https:// and strip trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def print_status(message: str, severity: str = "INFO"):
    """Print a message with ANSI color based on severity."""
    colors = {
        "INFO": "\033[92m",   # Green
        "HIGH": "\033[93m",   # Yellow
        "CRITICAL": "\033[91m",  # Red
        "RESET": "\033[0m",   # Reset
    }
    print(f"{colors[severity]}[{severity}] {message}{colors['RESET']}")

# ── Core scanner ────────────────────────────────────────────────────────────

async def detect_jenkins(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running Jenkins and retrieve version information.
    Returns dict with detection info, or None if not Jenkins.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version_str = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                headers = response.headers

                # Look for Jenkins fingerprints in response body or headers
                if any(marker in response.text for marker in JENKINS_FINGERPRINTS) or "X-Jenkins" in headers:
                    detected = True
                    version = parse_version(headers.get("X-Jenkins", ""))
                    if version:
                        raw_version_str = ".".join(map(str, version))
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version_str,
            "vulnerable": is_vulnerable_version(version),
        }

async def probe_env_inject(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Probe for environment variable injection in a Jenkins instance.
    Returns dict with test results, or None if detection-only mode (--safe).
    """
    if safe_mode:
        return None

    async with semaphore:
        test_url = base_url + ENV_INJECT_TEST_PATH.format(job_name="test")
        payload = {
            "parameter": [{"name": "env_var_name", "value": "`echo injected`"}]
        }

        try:
            response = await client.post(
                test_url,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json"},
            )
            if "injected" in response.text:
                return {"test_url": test_url, "status": "vulnerable"}
        except (httpx.RequestError, Exception):
            pass

        return {"test_url": test_url, "status": "not_vulnerable"}

async def scan_target(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """Scan a single Jenkins target and return detection and probe results."""
    base_url = normalize_url(base_url)
    detection_result = await detect_jenkins(client, base_url, semaphore)

    if detection_result and detection_result["detected"]:
        probe_result = await probe_env_inject(client, base_url, semaphore, safe_mode)
        detection_result["probe_results"] = probe_result

    return detection_result

async def main(args):
    """Entrypoint for Jenkins Pipeline Environment Variable Injection scanner."""
    semaphore = asyncio.Semaphore(args.concurrency)
    client = httpx.AsyncClient(verify=not args.no_verify)

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = f.read().splitlines()
        except FileNotFoundError:
            print_status(f"Target file {args.list} not found.", "CRITICAL")
            return

    results = []
    tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
    
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)

        # Print scan result to terminal
        if result["detected"]:
            severity = "CRITICAL" if result["vulnerable"] else "INFO"
            print_status(
                f"Detected Jenkins: {result['url']} | Version: {result['version']} | Vulnerable: {result['vulnerable']}",
                severity,
            )
        else:
            print_status(f"No Jenkins detected: {result['url']}", "INFO")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    await client.aclose()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Pipeline Environment Variable Injection Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="File containing a list of target URLs")
    parser.add_argument("--output", type=str, help="Write JSON scan results to this file")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (no active probes)")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for HTTPS requests")
    args = parser.parse_args()

    asyncio.run(main(args))
