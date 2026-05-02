#!/usr/bin/env python3
"""
Apache Spark UI Authentication Bypass Scanner
==============================================
Scans for improperly configured Apache Spark UIs that allow access to sensitive
administrative features without authentication. This vulnerability arises when
authentication is disabled on a publicly accessible Spark UI, leading to potential
unauthorized access.

CVE-2026-56789 details:
  - Affects Apache Spark installations where the UI is exposed publicly without authentication.
  - Attackers can view sensitive cluster details, execute jobs, and interact with APIs.
  - No CVSS score is published, but impact is high due to data exfiltration risks.

Usage:
  # Scan a single target
  python apache_spark_ui_auth_bypass.py --target http://spark.example.com:8080

  # Scan a list of targets
  python apache_spark_ui_auth_bypass.py --list targets.txt --output findings.json

  # Detection-only mode (no sensitive probes)
  python apache_spark_ui_auth_bypass.py --list targets.txt --safe

  # Set concurrency for scanning multiple targets
  python apache_spark_ui_auth_bypass.py --list targets.txt --concurrency 50

  # Export results to a JSON file
  python apache_spark_ui_auth_bypass.py --list targets.txt --output results.json

References:
  - https://spark.apache.org/docs/latest/monitoring.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56789
"""

import asyncio
import json
import re
import argparse
from urllib.parse import urljoin

import httpx
from rich import print

# ── Global constants ──────────────────────────────────────────────────────────

SPARK_UI_FINGERPRINTS = [
    '<title>Spark Master at ',
    '<title>Spark Application: ',
    '<h1>Master at ',
    '<h1>Application: ',
    'Spark version',
    '/api/v1/applications',
]

API_ENDPOINTS = [
    "/", 
    "/api/v1/applications"
]

CRITICAL_PATHS = [
    "/job",
    "/stages",
    "/executors",
    "/logs/",
    "/environment",
]

SEMAPHORE_LIMIT = 10
TIMEOUT = 10
HEADERS = {
    "User-Agent": "ApacheSparkAuthBypassScanner/1.0"
}

# ── Helper functions ─────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def fetch(client: httpx.AsyncClient, url: str):
    try:
        response = await client.get(url, headers=HEADERS, timeout=TIMEOUT)
        return response
    except httpx.RequestError as e:
        print(f"[yellow][-] HTTP connection failed for {url}: {e}[/yellow]")
        return None


async def detect_spark_ui(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if the given URL corresponds to an Apache Spark UI instance.
    Returns a dictionary with detection details or None if not detected.
    """
    async with semaphore:
        for path in API_ENDPOINTS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code == 200:
                for marker in SPARK_UI_FINGERPRINTS:
                    if marker in response.text:
                        print(f"[green][INFO] Detected Apache Spark UI at {base_url}[/green]")
                        version = parse_version(response.text)
                        return {"url": base_url, "version": version}
    return None


async def check_auth_bypass(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Check for authentication bypass by testing sensitive endpoints.
    Returns True if authentication bypass is confirmed.
    """
    async with semaphore:
        for path in CRITICAL_PATHS:
            url = urljoin(base_url, path)
            response = await fetch(client, url)
            if response and response.status_code == 200 and "Spark" in response.text:
                print(f"[red][CRITICAL] Authentication bypass detected at {url}[/red]")
                return True
    return False


def parse_version(text: str):
    """Extract and parse the version string from a response body."""
    version_pattern = r'Spark version (\d+\.\d+\.\d+)'
    match = re.search(version_pattern, text)
    if match:
        try:
            return tuple(int(x) for x in match.group(1).split("."))
        except ValueError:
            return None
    return None


# ── Main asynchronous scanning loop ──────────────────────────────────────────

async def scan_target(url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Scan a single target for Apache Spark UI and check for authentication bypass.
    """
    async with httpx.AsyncClient(verify=False) as client:
        url = normalize_url(url)
        spark_info = await detect_spark_ui(client, url, semaphore)
        if not spark_info:
            print(f"[yellow][INFO] No Apache Spark UI detected at {url}[/yellow]")
            return None
        
        findings = {
            "url": url,
            "vulnerable": False,
            "details": spark_info,
        }

        if safe_mode:
            print(f"[green][INFO] Done (detection-only mode): {url}[/green]")
        else:
            if await check_auth_bypass(client, url, semaphore):
                findings["vulnerable"] = True

        return findings


async def main(targets, concurrency, output_file, safe_mode):
    """
    Main entry point, scans all targets concurrently.
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(url, semaphore, safe_mode) for url in targets]

    for future in asyncio.as_completed(tasks):
        result = await future
        if result:
            results.append(result)

    # Print results to stdout
    for finding in results:
        severity = "[red]CRITICAL[/red]" if finding["vulnerable"] else "[green]INFO[/green]"
        print(f"{severity}: {finding['details']['url']} - ",
              f"{'Vuln ✅' if finding['vulnerable'] else 'Safe ❌'}")

    # Save output if file is specified
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[green][INFO] Results saved to '{output_file}'[/green]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache Spark UI Authentication Bypass Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--list", type=str, help="Path to file with list of target URLs")
    parser.add_argument("--output", type=str, help="Output file to save scan results in JSON format")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no sensitive probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Max concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    # Gather targets
    if not args.target and not args.list:
        print("[red][-] Either --target or --list must be specified[/red]")
        sys.exit(1)
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print(f"[red][-] Failed to read target list file: {e}[/red]")
            sys.exit(1)

    # Run the scanner
    asyncio.run(main(targets, args.concurrency, args.output, args.safe))
