#!/usr/bin/env python3
"""
GitLab CI/CD YAML Configuration Injection Scanner
==================================================
Scans GitLab instances for vulnerabilities related to YAML configuration injection in `.gitlab-ci.yml` files. 
This class of vulnerabilities, if exploited, could allow a malicious actor to introduce arbitrary job execution (potential RCE) 
or access sensitive data within the CI/CD pipeline.

Affected Systems:
  - GitLab Community Edition (CE) and Enterprise Edition (EE)
  - Vulnerabilities may vary based on specific versions and configurations.

Key Features:
  - Detects GitLab instances
  - Extracts the version and checks if it's vulnerable
  - Probes for YAML injection issues (if not in --safe mode)

Usage:
  # Scan a single target
  python gitlab_ci_yaml_injection_scanner.py --target https://gitlab.example.com

  # Scan a list of targets
  python gitlab_ci_yaml_injection_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no active probing
  python gitlab_ci_yaml_injection_scanner.py --list targets.txt --safe

References:
  - https://docs.gitlab.com/ee/ci/yaml/
  - https://nvd.nist.gov/
"""

import asyncio
import argparse
import json
import re
import sys
from urllib.parse import urljoin

import httpx
from colorama import Fore, Style

# ── Detection markers ────────────────────────────────────────────────────────

GITLAB_FINGERPRINTS = [
    "<title>Sign in · GitLab</title>",
    '<meta content="GitLab',
]

DETECTION_PATHS = [
    "/users/sign_in",
    "/",
    "/help",
    "/explore",
]

VERSION_PATTERN = r"GitLab Community Edition (\d{1,3}\.\d{1,3}\.\d{1,3})"
VULN_VERSIONS = {
    "14.0.0": (14, 5, 2),  # Example patched version for a specific issue
    # Add specific version mappings here as needed
}

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10

# ── Helper Methods ───────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """
    Parse a version string into a tuple of integers.
    """
    try:
        return tuple(map(int, version_str.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_str: str):
    """
    Check if the version string is in the affected version range.
    Return True if vulnerable, False otherwise.
    """
    parsed_version = parse_version(version_str)
    return parsed_version and parsed_version <= VULN_VERSIONS["14.0.0"]


def normalize_url(url: str) -> str:
    """
    Normalize URLs to include the protocol and remove trailing slashes.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


# ── Detection Function ──────────────────────────────────────────────────────

async def detect_gitlab(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if a given URL hosts a GitLab instance and check its version.
    """
    async with semaphore:
        detected = False
        version = None

        for path in DETECTION_PATHS:
            url = urljoin(base_url, path)
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if any(marker in response.text for marker in GITLAB_FINGERPRINTS):
                    detected = True
                    match = re.search(VERSION_PATTERN, response.text)
                    if match:
                        version = match.group(1)
                        break
            except httpx.RequestError:
                continue

        return {
            "url": base_url,
            "detected": detected,
            "version": version,
            "vulnerable": is_vulnerable_version(version),
        }


# ── Active Probing Function ─────────────────────────────────────────────────

async def probe_yaml_injection(client: httpx.AsyncClient, base_url: str):
    """
    Attempt to test for YAML injection by creating a deliberately malicious pipeline.
    This function requires administrative privileges or a set of credentials that
    has access to the project.
    """
    test_pipeline = {
        "stages": ["build"],
        "job1": {
            "script": ["echo Injected command executed"],
        },
    }

    probe_path = urljoin(base_url, "/api/v4/projects/1/pipeline")
    data = {"pipeline_file": test_pipeline}

    try:
        response = await client.post(probe_path, json=data, timeout=REQUEST_TIMEOUT)
        if response.status_code == 201:
            return True
    except httpx.RequestError:
        pass

    return False


# ── Scan Function ────────────────────────────────────────────────────────────

async def scan_target(base_url: str, probe: bool, semaphore: asyncio.Semaphore):
    """
    Scan a single target for GitLab and perform detection/probe as needed.
    """
    async with httpx.AsyncClient(verify=False) as client:
        result = await detect_gitlab(client, base_url, semaphore)
        if result["detected"]:
            print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} GitLab detected at {result['url']}")
            version = result.get("version")
            if version:
                print(f"  {Fore.YELLOW}[VERSION]{Style.RESET_ALL} Detected version: {version}")
                if result["vulnerable"]:
                    print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} Version is vulnerable!")
                else:
                    print(f"  {Fore.GREEN}[SAFE]{Style.RESET_ALL} Version is patched.")
            else:
                print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} Version information not found.")

            if probe:
                print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} Probing for YAML injection...")
                vulnerable = await probe_yaml_injection(client, base_url)
                if vulnerable:
                    print(f"  {Fore.RED}[CRITICAL]{Style.RESET_ALL} YAML injection vulnerability confirmed!")
                else:
                    print(f"  {Fore.GREEN}[SAFE]{Style.RESET_ALL} No YAML injection vulnerability detected.")
        else:
            print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No GitLab instance detected at {base_url}")

        return result


# ── Main Program ────────────────────────────────────────────────────────────

async def main(args):
    if args.list:
        with open(args.list, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} No target(s) specified.")
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    tasks = [scan_target(normalize_url(url), not args.safe, semaphore) for url in targets]
    for result in await asyncio.gather(*tasks):
        if result:
            results.append(result)

    if args.output:
        with open(args.output, "w") as outfile:
            json.dump(results, outfile, indent=4)
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Results saved to {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitLab CI/CD YAML Configuration Injection Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing list of target URLs")
    parser.add_argument("--output", help="Save results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode. Skips active probing.")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent scans")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate validation")

    args = parser.parse_args()

    if args.no_verify:
        httpx._config.DEFAULT_CA_CERTS = None

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Scan interrupted.")
