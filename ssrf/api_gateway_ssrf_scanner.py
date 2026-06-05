#!/usr/bin/env python3
"""
API Gateway SSRF Vulnerability Scanner
======================================
This tool scans API gateway instances for potential Server-Side Request Forgery (SSRF) vulnerabilities. SSRF 
vulnerabilities can allow attackers to send requests to internal systems or exfiltrate sensitive data by exploiting 
servers that process maliciously crafted HTTP requests.

Commonly impacted systems:
  - API Gateway services (e.g., AWS API Gateway, Kong Gateway, NGINX-based gateways)
  - Reverse proxies that expose misconfigured open routes
  - HTTP to HTTPS proxies

Key Features:
  - Detects SSRF vulnerabilities using known SSRF exploitation patterns
  - Tests common misconfigurations, such as open redirects and unprotected AWS metadata APIs
  - Supports a safe mode for detection-only scanning
  - Provides JSON and color-coded terminal output

Usage:
  # Scan a single target
  python api_gateway_ssrf_scanner.py --target http://gateway.example.com

  # Scan a list of targets
  python api_gateway_ssrf_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no active SSRF probes
  python api_gateway_ssrf_scanner.py --target http://gateway.example.com --safe

References:
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  - https://portswigger.net/web-security/ssrf
"""

import asyncio
import argparse
import httpx
import json
import re
from urllib.parse import urljoin, urlparse

# ── Detection markers ─────────────────────────────────────────────────────────

COMMON_GATEWAY_FINGERPRINTS = [
    "API Gateway", "nginx", "Kong", "Traefik", "Envoy",
    "Server: awselb", "Server: envoy", "Server: ApiGw"
]

SSRF_TEST_PATHS = [
    "/api/v1/internal", "/services/internal", "/metadata", 
    "/.env", "/admin/config", "/debug/info", "/internal/info"
]

AWS_METADATA_URL = "http://169.254.169.254/latest/meta-data/"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ANSI colors for CLI output
COLOR_CRITICAL = "\033[91m"
COLOR_HIGH = "\033[93m"
COLOR_INFO = "\033[92m"
COLOR_RESET = "\033[0m"

# ── Helper functions ─────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure a target URL has the proper scheme and format."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def is_vulnerable_status_code(status_code: int) -> bool:
    """Checks whether a given HTTP status code indicates an SSRF vulnerability."""
    return status_code in [200, 201, 202, 203, 204, 302, 307]

async def fetch_url(client: httpx.AsyncClient, url: str, method: str = "GET", data: dict = None):
    """
    Perform an HTTP request using the given client.
    Handles network-related exceptions.
    """
    try:
        if method == "GET":
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
        elif method == "POST":
            response = await client.post(url, data=data, timeout=REQUEST_TIMEOUT)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        return response
    except (httpx.RequestError, httpx.TimeoutException):
        return None

# ── Core scanner ─────────────────────────────────────────────────────────

async def detect_api_gateway(client: httpx.AsyncClient, target_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether the target URL is potentially an API gateway or reverse proxy.
    Returns a dictionary with detection info.
    """
    async with semaphore:
        url = normalize_url(target_url)
        try:
            response = await client.get(url, timeout=REQUEST_TIMEOUT)
        except httpx.RequestError:
            return {"url": url, "detected": False, "details": None}

        detected = any(marker in response.headers.get("Server", "") for marker in COMMON_GATEWAY_FINGERPRINTS)
        details = response.headers if detected else None

        return {"url": url, "detected": detected, "details": details}

async def probe_ssrf(client: httpx.AsyncClient, target_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Actively probe the target for SSRF vulnerabilities by testing known paths and patterns.
    Returns a list of potential SSRF findings.
    """
    async with semaphore:
        findings = []
        for path in SSRF_TEST_PATHS:
            try:
                response = await client.get(urljoin(target_url, path), timeout=REQUEST_TIMEOUT)
                if is_vulnerable_status_code(response.status_code):
                    findings.append({
                        "path": path,
                        "status_code": response.status_code,
                        "reason": response.reason_phrase
                    })

                    if not safe_mode:
                        # Active SSRF exploitation check: try accessing AWS Metadata API
                        aws_metadata_response = await client.get(urljoin(target_url, path) + "?url=" + AWS_METADATA_URL, timeout=REQUEST_TIMEOUT)
                        if aws_metadata_response and "ami-id" in aws_metadata_response.text:
                            findings.append({
                                "path": path,
                                "ssrf_potential": True,
                                "aws_metadata": True
                            })
                        else:
                            findings.append({
                                "path": path,
                                "ssrf_potential": True,
                                "aws_metadata": False
                            })

            except (httpx.RequestError, Exception):
                continue

        return findings

async def main(targets, output_file, concurrency, safe_mode, no_verify):
    """
    Main asynchronous function to execute the scanner.
    """
    semaphore = asyncio.Semaphore(concurrency)
    client_kwargs = {"verify": not no_verify}
    async with httpx.AsyncClient(**client_kwargs) as client:
        tasks = []
        for target in targets:
            tasks.append(detect_api_gateway(client, target, semaphore))
        results = await asyncio.gather(*tasks)

        for result in results:
            if result.get("detected"):
                target = result.get("url")
                print(f"{COLOR_INFO}INFO: {COLOR_RESET}API Gateway detected at {target}")
                probes = await probe_ssrf(client, target, semaphore, safe_mode)
                for probe in probes:
                    severity_color = COLOR_CRITICAL if "ssrf_potential" in probe and probe["ssrf_potential"] else COLOR_HIGH
                    print(f"{severity_color}POTENTIAL SSRF: {target + probe['path']} - {probe['status_code']} {probe['reason']}{COLOR_RESET}")

                if output_file:
                    result["probes"] = probes

        if output_file:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
                print(f"{COLOR_INFO}INFO: Results saved to {output_file}{COLOR_RESET}")

# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Gateway SSRF Vulnerability Scanner")
    parser.add_argument("--target", type=str, help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--list", type=str, help="Path to a file containing a list of target URLs")
    parser.add_argument("--output", type=str, help="File to save JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only, no SSRF probes")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent scan requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    args = parser.parse_args()

    # Load targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend([line.strip() for line in f if line.strip()])

    # Validate inputs
    if not targets:
        print(f"{COLOR_CRITICAL}ERROR: No targets specified. Use --target or --list to provide targets.{COLOR_RESET}")
        exit(1)

    # Run scanner
    asyncio.run(main(targets, args.output, args.concurrency, args.safe, args.no_verify))
