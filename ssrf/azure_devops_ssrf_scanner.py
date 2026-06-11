#!/usr/bin/env python3
"""
Azure DevOps Server SSRF Vulnerability Scanner
==============================================
This scanner detects Server-Side Request Forgery (SSRF) vulnerabilities in Azure DevOps Server installations.

The SSRF vulnerabilities exploit certain routes or API endpoints in Azure DevOps Server that may allow
an attacker to manipulate outbound HTTP requests, potentially exposing sensitive internal resources or misusing
server capabilities for further attacks.

Usage:
  # Scan a single instance
  python azure_devops_ssrf_scanner.py --target https://devops.example.com

  # Scan multiple instances from a file
  python azure_devops_ssrf_scanner.py --list targets.txt --output findings.json

  # Enable safe mode for detection only without active SSRF probes
  python azure_devops_ssrf_scanner.py --list targets.txt --safe

References:
  - https://learn.microsoft.com/en-us/security/sensitivity-resources/azure-devops-secure
  - Multiple SSRF reports under Azure DevOps Server bug bounty programs
"""

import asyncio
import argparse
import json
import httpx
import re

# ── Detection markers ─────────────────────────────────────────────────────────

AZURE_DEVOPS_FINGERPRINTS = [
    "<title>Azure DevOps</title>",
    'name="Description" content="Azure DevOps web platform"',
    '"applicationName":"Microsoft Team Foundation Server"',
]

DETECTION_PATHS = [
    "/_static/tfs",
    "/Tfs/VersionControl",
    "/_apis/connectionData",
    "/_api/_version",
]

VERSION_PATTERNS = [
    r"\"version\":\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\"",
    r"\"buildVersion\":\"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\"",
]

VULN_FIXED_VERSION = (8, 0, 0, 0)  # Azure DevOps Server 2020 Fixed Versions

SSRF_PROBE_PATHS = [
    "/_apis/distributedtask/pools/test/connections?url=http://example.com",
    "/_tasks/httpRequest?api-version=5.0",
]

SEMAPHORE_LIMIT = 25
REQUEST_TIMEOUT = 10

# ── Utilities and helpers ────────────────────────────────────────────────────

def is_vulnerable_version(version_tuple):
    """Check if the version is below the fixed vulnerability patch version."""
    if not version_tuple:
        return None
    return version_tuple < VULN_FIXED_VERSION


def parse_version(response_text):
    """Extract Azure DevOps Server version from response content."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, response_text)
        if match:
            try:
                return tuple(map(int, match.group(1).split(".")))
            except ValueError:
                pass
    return None


def normalize_url(url: str) -> str:
    """Normalize URLs to start with https:// and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


async def print_terminal(message: str, severity: str = "INFO"):
    """Print a message to the terminal with appropriate color based on severity."""
    colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "INFO": "\033[92m",
        "RESET": "\033[0m",
    }
    color = colors.get(severity.upper(), colors["RESET"])
    reset = colors["RESET"]
    print(f"{color}{message}{reset}")


async def save_json(data, output_file):
    """Save results as JSON to a specified file."""
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

# ── Scanner core logic ──────────────────────────────────────────────────────

async def detect_azure_devops(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect Azure DevOps Server instance and version.
    Returns detection information, including vulnerable status.
    """
    async with semaphore:
        detected = False
        version = None
        raw_version = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                for marker in AZURE_DEVOPS_FINGERPRINTS:
                    if marker in response.text:
                        detected = True
                        version = parse_version(response.text)
                        if version:
                            raw_version = ".".join(map(str, version))
                        break
                if detected:
                    break
            except (httpx.RequestError, Exception):
                pass

        return {
            "url": base_url,
            "detected": detected,
            "version": raw_version,
            "vulnerable": is_vulnerable_version(version),
        }


async def probe_ssrf(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe=False):
    """
    Actively test SSRF weakness if safe mode is disabled.
    Returns active probe results.
    """
    if safe:
        return {"probes": None, "ssrf_detected": None}

    async with semaphore:
        for path in SSRF_PROBE_PATHS:
            url = base_url + path
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code in {200, 301, 302} and "example.com" in response.text:
                    return {
                        "probes": path,
                        "ssrf_detected": True,
                    }
            except (httpx.RequestError, Exception):
                pass
        return {
            "probes": SSRF_PROBE_PATHS,
            "ssrf_detected": False,
        }

# ── Main scanner runner ─────────────────────────────────────────────────────

async def scan_target(client, base_url, semaphore, safe):
    """Scan a single Azure DevOps Server target."""
    base_url = normalize_url(base_url)
    detection = await detect_azure_devops(client, base_url, semaphore)
    if detection["detected"]:
        await print_terminal(f"[INFO] Detected Azure DevOps Server at {base_url}", severity="INFO")
        if detection["vulnerable"]:
            await print_terminal(f"[CRITICAL] Vulnerable version: {detection['version']}", severity="CRITICAL")
            ssrf_probe = await probe_ssrf(client, base_url, semaphore, safe)
            if ssrf_probe["ssrf_detected"]:
                await print_terminal(f"[CRITICAL] SSRF vulnerability detected at {base_url}.", severity="CRITICAL")
                detection.update(ssrf_probe)
        else:
            await print_terminal(f"[INFO] Patched instance at {base_url} (Version: {detection['version']}).", severity="INFO")
    else:
        await print_terminal(f"[INFO] No Azure DevOps Server detected at {base_url}.", severity="INFO")
        detection["vulnerable"] = False
    return detection


async def main():
    parser = argparse.ArgumentParser(description="Azure DevOps Server SSRF Vulnerability Scanner")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--list", help="Path to a file containing a list of URLs to scan")
    parser.add_argument("--output", help="Save scan results to JSON file")
    parser.add_argument("--safe", action="store_true", help="Run in safe mode (detection-only)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrent scans (default: 5)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: Either --target or --list must be specified.")
        return

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as file:
            targets.extend(line.strip() for line in file.readlines() if line.strip())

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_target(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    if args.output:
        await save_json(results, args.output)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
