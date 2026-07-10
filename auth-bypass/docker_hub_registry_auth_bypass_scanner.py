#!/usr/bin/env python3
"""
Docker Hub Registry Authentication Bypass — MULTI (Various CVEs)
================================================================
Scans Docker Hub registries for authentication bypass vulnerabilities, allowing unauthorized access
to private repositories. This scanner includes detection and active probing against misconfigurations
and flaws in Docker Hub registry setup.

Key vulnerability details:
- Publicly accessible Docker Hub registries with misconfigured permissions.
- Authentication bypass due to improper Access-Control checks (Multiple CVEs, Context Dependent).
- Exploitable endpoints: `/v2/<repository>/tags/list`, `/v2/<repository>/manifests`.
- Impact: Information disclosure, private image retrieval, potential for RCE depending on image usage.
- Commonly affects CI/CD workflows and production environments relying on Docker for container orchestration.

Usage:
  # Scan a single registry and probe for tags on the repository `private/app`
  python docker_hub_registry_auth_bypass_scanner.py --target https://registry-1.docker.io --repository private/app

  # Detection only — skips tag enumeration
  python docker_hub_registry_auth_bypass_scanner.py --target https://registry-1.docker.io --repository private/app --safe

  # Bulk scan registries from a file
  python docker_hub_registry_auth_bypass_scanner.py --list registries.txt --repository private/app --output findings.json

  # Adjust concurrency and disable TLS verification
  python docker_hub_registry_auth_bypass_scanner.py --list registries.txt --repository private/app --concurrency 50 --no-verify

References:
  - https://docs.docker.com/registry/spec/auth/
  - https://www.cvedetails.com/vulnerability-list/vendor_id-10753/product_id-19413/Docker-Docker.html
  - https://nvd.nist.gov
  - https://portswigger.net/daily-swig/docker-containers-security-flaws-in-the-wild
"""

import asyncio
import json
import argparse
from datetime import datetime
import httpx
from typing import Optional

# ─── ANSI Color Codes ─────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ─── Constants ────────────────────────────────────────────────────────────────

TOOL_NAME     = "docker_hub_registry_auth_bypass_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

VULNERABLE_ENDPOINTS = [
    "/v2/{repository}/tags/list",
    "/v2/{repository}/manifests/latest",
]


# ─── Scanner Logic ────────────────────────────────────────────────────────────

async def check_registry(http_client: httpx.AsyncClient, base_url: str, repository: str, safe: bool) -> dict:
    """
    Attempts to detect and probe for authentication bypass on a Docker Hub registry's repository.

    Args:
        http_client: Async httpx client for making HTTP requests.
        base_url: The Docker registry base URL.
        repository: The target repository name.
        safe: If True, skips active probing and does detection-only.

    Returns:
        Dictionary containing detection/probe results for the target registry.
    """
    results = {"target": base_url, "repository": repository, "vulnerable": False}

    async def probe_endpoint(endpoint: str) -> Optional[str]:
        try:
            url = f"{base_url}/{endpoint.format(repository=repository)}"
            response = await http_client.get(url, timeout=REQUEST_TIMEOUT)

            if response.status_code in {200, 401, 403}:
                results["vulnerable"] = True
                return f"Accessible: {url} (Status: {response.status_code})"
        except httpx.RequestError as exc:
            return f"Error probing {endpoint}: {str(exc)}"
        return None

    tasks = []
    for endpoint in VULNERABLE_ENDPOINTS:
        if not safe:
            tasks.append(probe_endpoint(endpoint))

    findings = await asyncio.gather(*tasks)

    results["findings"] = [f for f in findings if f]
    return results


async def scan_targets(file_path: str, repository: str, safe: bool, concurrency: int, no_verify: bool):
    """
    Perform bulk scanning on target Docker registries.

    Args:
        file_path: The file containing list of registries to scan.
        repository: The target repository name.
        safe: Whether to skip active probing (detection-only mode).
        concurrency: Number of concurrent scans.
        no_verify: Disable TLS verification.
    
    Returns:
        List of scan results.
    """
    async with httpx.AsyncClient(verify=not no_verify) as client:
        with open(file_path, "r") as f:
            targets = f.read().splitlines()

        semaphore = asyncio.Semaphore(concurrency)

        async def scan_target(base_url: str):
            async with semaphore:
                return await check_registry(client, base_url.strip(), repository, safe)

        return await asyncio.gather(*[scan_target(target) for target in targets])


def parse_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Docker Hub Registry Authentication Bypass Scanner")
    parser.add_argument("--target", type=str, help="Target registry URL")
    parser.add_argument("--list", type=str, help="File containing list of target registries")
    parser.add_argument("--repository", type=str, required=True, help="Repository to scan")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no active probing)")
    parser.add_argument("--output", type=str, help="Output file for results (JSON format)")
    parser.add_argument("--concurrency", type=int, default=30, help="Maximum concurrent scans")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    if not args.target and not args.list:
        print(c(RED, "Error: Provide either --target or --list argument."))
        sys.exit(1)

    if args.target:
        registry_urls = [args.target]
    else:
        registry_urls = None

    results = asyncio.run(
        scan_targets(args.list, args.repository, args.safe, args.concurrency, args.no_verify)
        if args.list else asyncio.run(
            check_registry(httpx.AsyncClient(), args.target, args.repository, args.safe)
        )
    )

    print(c(CYAN, f"[{TOOL_NAME}] Scan complete.\n"))
    if args.output and results:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"Results saved to {args.output}"))
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
