#!/usr/bin/env python3
"""
kubectl Proxy SSRF Scanner
===========================
Scans publicly exposed Kubernetes `kubectl proxy` endpoints for Server-Side
Request Forgery (SSRF) vulnerabilities due to improper access control.

Background:
  - `kubectl proxy` can inadvertently expose the Kubernetes API if the hosting
    system is misconfigured or lacks network segmentation.
  - Attackers can use exposed endpoints to execute SSRF attacks, access sensitive
    metadata, or perform unauthorized operations on the Kubernetes API.

Risk:
  - Unauthenticated access to the Kubernetes API through exposed `kubectl proxy`
  - Potential escalation to compromise the underlying Kubernetes cluster

Usage:
  # Scan a single target
  python kubectl_proxy_ssrf_scanner.py --target https://example.com:8001

  # Scan a list of targets
  python kubectl_proxy_ssrf_scanner.py --list targets.txt --output findings.json

  # Detection-only mode (no SSRF probes)
  python kubectl_proxy_ssrf_scanner.py --list targets.txt --safe

  # Custom concurrency limit
  python kubectl_proxy_ssrf_scanner.py --list targets.txt --concurrency 50

References:
  - https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster-api/
  - https://security.stackexchange.com/questions/222967/security-risks-of-running-kubectl-proxy
"""

import asyncio
import httpx
import json
import argparse
import re
from urllib.parse import urljoin

# ── Detection markers ─────────────────────────────────────────────────────────

KUBECTL_PROXY_FINGERPRINTS = [
    "Kubernetes API",
    "kubectl proxy",
    "/api/v1/",
    "/api/",
]

PROBE_PATHS = [
    "/api/v1/",
    "/apis/",
    "/healthz",
    "/metrics",
]

SSRF_TEST_PATHS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://localhost/",
]

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def print_colored(color, message):
    print(f"{color}{message}{ANSI_RESET}")


def json_dump(data, output_file):
    """Dump JSON data to a file"""
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)


# ── Core Detection ────────────────────────────────────────────────────────────

async def detect_kubectl_proxy(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is hosting a kubectl proxy endpoint.
    Returns detection information or None if not detected.
    """
    async with semaphore:
        detected = False

        for path in PROBE_PATHS:
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=REQUEST_TIMEOUT)

                if any(fingerprint in response.text for fingerprint in KUBECTL_PROXY_FINGERPRINTS):
                    detected = True
                    break

            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

        return {"url": base_url, "detected": detected}


async def test_ssrf(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Test for SSRF vulnerability, if `safe_mode` is False.
    Returns SSRF test results or None if safe mode.
    """
    async with semaphore:
        results = []

        if not safe_mode:
            for ssrf_path in SSRF_TEST_PATHS:
                try:
                    url = urljoin(base_url, ssrf_path)
                    response = await client.get(url, timeout=REQUEST_TIMEOUT)

                    if response.status_code == 200 and response.text:
                        results.append({
                            "ssrf_path": ssrf_path,
                            "response": response.text[:200],
                        })

                except httpx.RequestError:
                    continue

        return {"url": base_url, "ssrf_results": results if results else None}


async def scan_target(target, safe_mode, semaphore):
    """
    Full scan routine combining detection and SSRF testing.
    """
    async with httpx.AsyncClient(verify=True) as client:
        detection_result = await detect_kubectl_proxy(client, target, semaphore)
        if detection_result["detected"]:
            ssrf_result = await test_ssrf(client, target, semaphore, safe_mode)
            return {**detection_result, **ssrf_result}
        return detection_result


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)

    if args.list:
        with open(args.list, "r") as f:
            targets = [normalize_url(line.strip()) for line in f if line.strip()]
    elif args.target:
        targets = [normalize_url(args.target)]
    else:
        print("Error: Either --target or --list must be specified.")
        return

    tasks = [scan_target(target, args.safe, semaphore) for target in targets]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result.get("detected"):
            print_colored(ANSI_GREEN, f"[INFO] Detected kubectl proxy at {result['url']}")
        else:
            print_colored(ANSI_YELLOW, f"[INFO] No kubectl proxy detected at {result['url']}")

        if result.get("ssrf_results"):
            print_colored(ANSI_RED, f"[CRITICAL] SSRF vulnerability detected at {result['url']}")
            for ssrf_entry in result["ssrf_results"]:
                print_colored(ANSI_RED, f"  - SSRF Path: {ssrf_entry['ssrf_path']}")
                print_colored(ANSI_RED, f"  - Response: {ssrf_entry['response']}")
        elif result.get("detected"):
            print_colored(ANSI_YELLOW, f"[HIGH] No SSRF vulnerabilities detected, but endpoint is exposed: {result['url']}")

    if args.output:
        json_dump(results, args.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan for misconfigured kubectl proxy endpoints and test for SSRF.")
    parser.add_argument("--target", help="Single target URL to scan (e.g., https://example.com:8001)")
    parser.add_argument("--list", help="File containing a list of URLs to scan")
    parser.add_argument("--output", help="File to save JSON results")
    parser.add_argument("--safe", action="store_true", help="Detection only, no SSRF probes")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level (default: 30)")
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Scan aborted.")
