#!/usr/bin/env python3
"""
GitLab CI/CD YAML Secrets Exposure Scanner
===========================================
Scans GitLab CI/CD YAML configuration files for exposed secrets such as API
keys, credentials, and sensitive environment variables due to misconfigured
or publicly accessible project repositories.

Problem Description:
  The misuse or misconfiguration of GitLab CI/CD YAML files can result in the
  unintentional exposure of secrets, including but not limited to AWS keys,
  API tokens, database passwords, and sensitive internal URLs. These secrets
  may be exposed via:
    - Hardcoded sensitive variables in `variables` sections.
    - Debugging outputs writing variables into logs during pipeline execution.
    - Incorrect use of `script:` blocks.

Vulnerability Impact:
  - Leakage of sensitive data such as sensitive API tokens, private keys,
    and hardcoded credentials to unauthorized entities.
  
Examples:
  - An API token is included in the `variables` section of the `.gitlab-ci.yml`
    file and committed to a repository.
  - Information disclosure due to echo statements exposing secrets in plain text
    during pipeline logs. If the project is configured for public visibility, these
    secrets can be inadvertently disclosed.

This scanner can identify such potential exposures via retrieval and analysis
of the GitLab CI/CD YAML file.

Usage:
  # Scan a single repository
  python gitlab_ci_yaml_secret_exposure_scanner.py --target https://gitlab.example.com/group-name/project-name

  # Scan multiple repositories from a file
  python gitlab_ci_yaml_secret_exposure_scanner.py --list gitlab_urls.txt --output findings.json

  # Detection only – skips active secret checking
  python gitlab_ci_yaml_secret_exposure_scanner.py --target https://gitlab.example.com/group-name/project-name --safe

  # Customize concurrency and disable SSL verification
  python gitlab_ci_yaml_secret_exposure_scanner.py --list gitlab_urls.txt --concurrency 20 --no-verify

References:
  - https://docs.gitlab.com/ee/ci/variables/
  - https://cheatsheetseries.owasp.org/cheatsheets/Source_Code_Analysis_Tools.html
  - https://docs.gitlab.com/ee/ci/pipelines/
  - https://securitylab.github.com/research/gitlab-ci-tokens/

"""
import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME = "gitlab_ci_yaml_secret_exposure_scanner"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 10

# Patterns to detect potential secrets in YAML files
DEFAULT_SECRET_PATTERNS = [
    r'(?i)(aws_access_key_id|aws_secret_access_key|api_key|private_key):\s*["\']?([a-zA-Z0-9+/=]{20,})["\']?',
    r'(?i)(password|passwd|pwd):\s*["\']?([^\'"\s]+)["\']?',
    r'(https?:\/\/[^:]+\:[^@]+@[^\/]+)',
]

# Common GitLab CI/CD configuration file names
DEFAULT_CI_CONFIGS = [
    "/.gitlab-ci.yml",
    "/.gitlab-ci.yaml",
]


# ── Functions ─────────────────────────────────────────────────────────────────

def parse_args():
    """Parse and validate CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Scans GitLab CI/CD YAML files for sensitive information exposure."
    )
    parser.add_argument("--target", help="Target GitLab project URL to scan.")
    parser.add_argument("--list", help="File containing a list of GitLab project URLs to scan.")
    parser.add_argument("--output", help="Write JSON results to the specified file.", default=None)
    parser.add_argument("--safe", action="store_true", help="Detection only mode (does not fetch YAML).")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrency (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification.")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("Either --target or --list must be provided.")
    return args


async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch content from a URL."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except httpx.RequestError as exc:
        print(c(RED, f"ERROR: Failed to fetch {url}: {exc}"))
        return None
    except httpx.HTTPStatusError:
        print(c(YELLOW, f"WARNING: Got HTTP {exc.response.status_code} for {url}"))
        return None


async def scan_gitlab_project(
    client: httpx.AsyncClient, 
    url: str, 
    safe_mode: bool
) -> dict:
    """Scan a single GitLab project for potential secrets in CI/CD configuration."""
    print(c(CYAN, f"[*] Scanning: {url}"))
    result = {
        "target": url, "status": "unchecked", "secrets": [], "error": None
    }

    try:
        for config_path in DEFAULT_CI_CONFIGS:
            config_url = f"{url}{config_path}"
            response = await fetch_url(client, config_url)
            if response and response.status_code == 200:
                result["status"] = "detected"
                data = response.text
                print(c(GREEN, f"[INFO] Found configuration: {config_url}"))

                # Scan for potential secrets only in non-safe mode
                if not safe_mode:
                    for pattern in DEFAULT_SECRET_PATTERNS:
                        for match in re.findall(pattern, data):
                            result["secrets"].append(match)
                break
    except Exception as e:
        result["error"] = str(e)
        print(c(RED, f"ERROR: {e}"))
    
    return result


async def main():
    """Main asynchronous entry point."""
    args = parse_args()
    tasks = []
    semaphore = asyncio.Semaphore(args.concurrency)

    connector_args = {"verify": not args.no_verify, "timeout": REQUEST_TIMEOUT}
    async with httpx.AsyncClient(**connector_args) as client:
        if args.target:
            tasks.append(scan_gitlab_project(client, args.target, args.safe))
        elif args.list:
            with open(args.list, "r") as f:
                for line in f:
                    target = line.strip()
                    if target:
                        tasks.append(scan_gitlab_project(client, target, args.safe))

        results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
            print(c(GREEN, f"[+] Results written to {args.output}"))

# Entry point
if __name__ == "__main__":
    asyncio.run(main())
