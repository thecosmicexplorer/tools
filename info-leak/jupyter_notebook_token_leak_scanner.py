#!/usr/bin/env python3
"""
Jupyter Notebook Token Leak Detection Scanner
==============================================
This scanner identifies misconfigured Jupyter Notebook or JupyterLab instances
that expose a token in the URL or allow unauthenticated access to the interface.

Jupyter Notebook and JupyterLab require an access token for authentication by default.
However, users often misconfigure deployments, either disabling the token or exposing
the token through referer leaks, browser history, or direct URL links. If an attacker
obtains the token, they can gain control of the Jupyter instance and access critical data.

Vulnerability details:
  - Impact: Full compromise of Jupyter instances, arbitrary command/code execution
  - Scope: Potential exposure of sensitive data, cloud credentials, arbitrary commands
  - Cause: Misconfiguration allowing unauthenticated access, URL-exposed tokens
  - Difficulty: Easy to exploit

Features:
  - Actively attempts to enumerate exposed tokens.
  - Detects misconfigured Jupyter instances that disable authentication.
  - Provides version extraction to identify outdated or vulnerable instances.

Usage:
  # Scan a single target for Jupyter token leaks
  python jupyter_notebook_token_leak_scanner.py --target http://jupyter.example.com

  # Detection mode only (does not include sensitive token enumeration)
  python jupyter_notebook_token_leak_scanner.py --target http://jupyter.example.com --safe

  # Bulk scan targets from a file
  python jupyter_notebook_token_leak_scanner.py --list targets.txt --output results.json

  # Customize concurrency and disable TLS verification
  python jupyter_notebook_token_leak_scanner.py --list targets.txt --concurrency 20 --no-verify

References:
  - https://jupyter-notebook.readthedocs.io/en/stable/security.html
  - https://nvd.nist.gov/vuln/detail/CVE-2020-26215
  - https://blog.nelhage.com/2018/04/detecting-token-leaks-in-juypter/
"""

import asyncio
import re
import json
import httpx
import argparse
from datetime import datetime, timezone
from typing import List, Optional

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

TOOL_NAME      = "jupyter_notebook_token_leak_scanner"
CVE_ID         = "N/A"
CVSS           = "9.0"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 20

JUPYTER_FINGERPRINTS = [
    "<title>Jupyter Notebook</title>",
    "<title>JupyterLab</title>",
    "data-jupyter-api-token",
]

TOKEN_PATTERNS = [
    r"token=([a-z0-9\-]+)",
]

DETECTION_PATHS = [
    "/tree",
    "/lab",
    "/notebooks",
    "/login",
    "/api/status",
]

# ── Functions ────────────────────────────────────────────────────────────────

async def check_url(client: httpx.AsyncClient, url: str, safe: bool = False) -> dict:
    result = {
        "url": url,
        "status": "UNKNOWN",
        "info": [],
        "token": None,
        "error": None,
    }

    try:
        for path in DETECTION_PATHS:
            response = await client.get(f"{url.rstrip('/')}{path}")
            if response.status_code in [200, 401]:
                content = response.text

                if any(fingerprint in content for fingerprint in JUPYTER_FINGERPRINTS):
                    result["status"] = "JUPYTER DETECTED"
                    result["info"].append(f"Detected Jupyter interface at: {response.url}")

                    for pattern in TOKEN_PATTERNS:
                        match = re.search(pattern, response.text)
                        if match:
                            token = match.group(1)
                            if not safe:
                                result["status"] = f"{c(RED, 'CRITICAL')} TOKEN LEAK"
                                result["token"] = token
                            else:
                                result["status"] = f"{c(YELLOW, 'DETECTION ONLY')}"

                    # Version detection
                    match_version = re.search(r'JupyterLab\s*v([0-9]+\.[0-9]+\.[0-9]+)', content, re.IGNORECASE)
                    if match_version:
                        version = match_version.group(1)
                        result["info"].append(f"JupyterLab version: {version}")
                    break

        if result["status"] == "UNKNOWN":
            result["status"] = f"{c(GREEN, 'SAFE')}"

    except Exception as ex:
        result["error"] = str(ex)
        result["status"] = f"{c(RED, 'ERROR')}"
    
    return result


async def scan_targets(targets: List[str], safe: bool, concurrency: int, no_verify: bool) -> List[dict]:
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify, timeout=REQUEST_TIMEOUT) as client:
        async def scan(target: str):
            async with semaphore:
                results.append(await check_url(client, target, safe))

        await asyncio.gather(*(scan(target) for target in targets))

    return results


def parse_arguments():
    parser = argparse.ArgumentParser(description="Jupyter Notebook Token Leak Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", type=str, help="URL of the target to scan (e.g., http://example.com:8888)")
    group.add_argument("--list", type=str, help="File containing a list of targets to scan, one per line")
    parser.add_argument("--output", type=str, help="File to write JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only, skips active probing for access tokens")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args()


def main():
    args = parse_arguments()
    targets = []

    if args.target:
        targets = [args.target]
    elif args.list:
        try:
            with open(args.list, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(c(RED, f"Error reading file: {e}"))
            sys.exit(1)

    print(c(CYAN, f"\n[{TOOL_NAME}] Starting scan...\n{'=' * 60}"))
    
    results = asyncio.run(scan_targets(targets, args.safe, args.concurrency, args.no_verify))

    for result in results:
        status_color = RED if "CRITICAL" in result["status"] else YELLOW if "DETECTION" in result["status"] else GREEN
        print(f" - {c(status_color, result['status'])} {result['url']}")
        for info in result['info']:
            print(f"     {c(CYAN, '[INFO]')} {info}")
        if result['token']:
            print(f"     {c(RED, '[TOKEN]')} {result['token']}")
        if result['error']:
            print(f"     {c(RED, '[ERROR]')} {result['error']}")

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            print(c(GREEN, f"\n[+] Results saved to {args.output}"))
        except Exception as e:
            print(c(RED, f"\n[ERROR] Failed to write output file: {e}"))

    print(c(CYAN, f"\n[{TOOL_NAME}] Scan complete.\n"))


if __name__ == "__main__":
    main()
