#!/usr/bin/env python3
"""
Spring Boot Actuator RCE Scanner
================================
Scans Spring Boot applications for exposed Actuator endpoints that could lead to Remote Code Execution (RCE)
or unauthorized sensitive information disclosure. Spring Boot Actuator provides management endpoints but
misconfigurations can lead to serious vulnerabilities.

Vulnerability Details:
  - Exposed Actuator endpoints such as `/env`, `/restart`, or `/heapdump` can lead to sensitive information
    disclosure or remote code execution.
  - Common misconfigurations involve enabling publicly accessible endpoints without proper access restrictions.
  - Attackers can potentially manipulate application state or invoke dangerous operations through these endpoints.

Usage:
  # Scan a single target
  python spring_boot_actuator_rce_scanner.py --target http://example.com

  # Scan a list of targets
  python spring_boot_actuator_rce_scanner.py --list targets.txt --output findings.json

  # Safe mode — detection only, no RCE probes
  python spring_boot_actuator_rce_scanner.py --list targets.txt --safe

References:
  - https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
  - https://snyk.io/vuln/SNYK-JAVA-ORGSPRINGFRAMEWORKBOOT-31626
"""

import asyncio
import argparse
import json
from typing import List, Optional
import colorama
from colorama import Fore, Style
import httpx

colorama.init(autoreset=True)

# ── Constants ────────────────────────────────────────────────────────────────

ACTUATOR_ENDPOINTS = [
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/loggers",
    "/actuator/shutdown",
]

DANGEROUS_ENDPOINTS = [
    "/actuator/env",
    "/actuator/restart",
    "/actuator/shutdown",
]

DETECTION_MARKERS = [
    "applicationConfig",  # Found in `/actuator/env`
    "heapMemoryUsage",    # Found in `/actuator/heapdump`
]

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8

# ── CLI Colors ──────────────────────────────────────────────────────────────

def color(text: str, level: str) -> str:
    if level == "CRITICAL":
        return f"{Fore.RED}{text}{Style.RESET_ALL}"
    elif level == "HIGH":
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    else:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

# ── Helper Functions ────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Normalize the target URL by ensuring it has an HTTP scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

# ── Detection Functions ─────────────────────────────────────────────────────

async def detect_actuator(client: httpx.AsyncClient, base_url: str) -> Optional[dict]:
    """
    Detect whether the target has exposed Spring Boot Actuator endpoints.
    Returns detection information, or None if no Actuator service was detected.
    """
    detected_endpoints = []
    async with asyncio.Semaphore(SEMAPHORE_LIMIT):
        for endpoint in ACTUATOR_ENDPOINTS:
            url = f"{base_url}{endpoint}"
            try:
                response = await client.get(url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200:
                    for marker in DETECTION_MARKERS:
                        if marker in response.text:
                            detected_endpoints.append(endpoint)
                            break
            except (httpx.RequestError, Exception):
                continue

    return {
        "url": base_url,
        "has_actuator": bool(detected_endpoints),
        "detected_endpoints": detected_endpoints,
    }

async def probe_rce(client: httpx.AsyncClient, base_url: str, endpoints: List[str]) -> List[dict]:
    """
    Actively probe identified Actuator endpoints for potential exploitation.
    Returns exploitation results per endpoint.
    """
    results = []
    async with asyncio.Semaphore(SEMAPHORE_LIMIT):
        for endpoint in endpoints:
            if endpoint in DANGEROUS_ENDPOINTS:
                try:
                    url = f"{base_url}{endpoint}"
                    response = await client.post(url, timeout=REQUEST_TIMEOUT)
                    if response.status_code in {200, 202, 204}:
                        results.append({"endpoint": endpoint, "exploitable": True})
                    else:
                        results.append({"endpoint": endpoint, "exploitable": False})
                except (httpx.RequestError, Exception):
                    results.append({"endpoint": endpoint, "exploitable": False})
    return results

# ── Main Scanner Logic ──────────────────────────────────────────────────────

async def scan_target(base_url: str, safe_mode: bool) -> dict:
    """
    Scan a single target for exposed Spring Boot Actuator vulnerabilities.

    :param base_url: Target base URL.
    :param safe_mode: If True, skip active probing.
    :return: A dictionary containing scan results.
    """
    result = {}
    async with httpx.AsyncClient(verify=False) as client:
        detection_result = await detect_actuator(client, base_url)
        if not detection_result['has_actuator']:
            result["status"] = "INFO"
            result["details"] = f"No Spring Boot Actuator endpoints detected on {base_url}."
            return result

        result["status"] = "HIGH"
        result["details"] = f"Detected Actuator endpoints: {', '.join(detection_result['detected_endpoints'])}"
        result["vulnerable_endpoints"] = []
        if not safe_mode:
            rce_results = await probe_rce(client, base_url, detection_result['detected_endpoints'])
            for res in rce_results:
                if res["exploitable"]:
                    result["status"] = "CRITICAL"
                    result["vulnerable_endpoints"].append(res["endpoint"])
    return result

# ── Async Entry Point ───────────────────────────────────────────────────────

async def main(args):
    semaphore = asyncio.Semaphore(args.concurrency)
    async def scan(url):
        url = normalize_url(url)
        result = await scan_target(url, args.safe)
        level = color(result["status"], result["status"])
        endpoints = ", ".join(result.get("vulnerable_endpoints", [])) or "None"
        print(f"[{level}] {url}: {result['details']}")
        return {
            "url": url,
            "status": result["status"],
            "details": result["details"],
            "vulnerable_endpoints": result.get("vulnerable_endpoints", []),
        }

    # Input Handling
    if args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.target:
        targets = [args.target]
    else:
        print("Error: Either --target or --list must be specified.")
        return

    results = await asyncio.gather(*[scan(url) for url in targets])
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    print(f"\nScan complete. Results saved to {args.output}." if args.output else "\nScan complete.")

# ── Argument Parsing ────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Spring Boot Actuator RCE Scanner")
    parser.add_argument("--target", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--list", help="File containing a list of target URLs")
    parser.add_argument("--output", help="File to save JSON output")
    parser.add_argument("--safe", action="store_true", help="Safe mode (detection only, no RCE probes)")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent scan tasks (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if args.no_verify:
        httpx._config.DEFAULT_CA_BUNDLE_PATH = None
    asyncio.run(main(args))
