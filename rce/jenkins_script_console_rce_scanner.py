#!/usr/bin/env python3
"""
Jenkins Script Console - Unauthenticated Remote Code Execution Scanner
========================================================================
This tool scans for Jenkins instances with unauthenticated access to the
"Script Console" feature, potentially allowing remote code execution (RCE).

Various misconfigurations and outdated Jenkins installations may leave the
Script Console exposed, enabling attackers to execute arbitrary Groovy scripts.
This tool identifies such instances, detects their versions, and optionally
performs safe probing to verify exploitability.

Vulnerability details:
  - Script Console provides administrators the ability to execute Groovy code.
  - If unauthenticated users can access it, full compromise of the Jenkins
    server is possible.
  - A significant risk to CI/CD pipelines and sensitive credentials stored
    within Jenkins.
  - Affected versions vary depending on the specific misconfiguration or
    vulnerability.

Usage:
  # Scan a single target
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080

  # Detection only – no active probes
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com:8080 --safe

  # Bulk scan from file
  python jenkins_script_console_rce_scanner.py --list targets.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 20 --no-verify

References:
  - https://www.jenkins.io/doc/book/security
  - https://github.com/jenkinsci-cert
  - https://cwe.mitre.org/data/definitions/94.html
  - https://owasp.org/www-community/attacks/Remote_Code_Execution
"""

import asyncio
import argparse
import json
import re
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI color helpers ────────────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap text in an ANSI color code."""
    return f"{color}{text}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────
TOOL_NAME = "jenkins_script_console_rce_scanner"
CVE_ID = "MULTI"
REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 10

JENKINS_FINGERPRINTS = [
    "Jenkins ver.",
    "Jenkins-Crumb",
    "X-Jenkins",
    "X-Jenkins-Session",
    "/jnlpJars/jenkins-cli.jar",
]

DETECTION_PATHS = [
    "/",
    "/login",
    "/manage",
    "/script",
]

PATTERN_JENKINS_VERSION = re.compile(r"Jenkins ver\. (\d+\.\d+)")

# ── Functions ────────────────────────────────────────────────────────────────
async def fetch(session: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Send an HTTP GET request to the specified URL."""
    try:
        response = await session.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response
    except (httpx.HTTPError, httpx.RequestError):
        return None

async def probe_target(session: httpx.AsyncClient, target: str, safe_mode: bool) -> Optional[dict]:
    """Probe a target URL to determine if it's vulnerable to Jenkins RCE."""
    findings = {"target": target, "vulnerable": False, "version": None, "details": []}

    for path in DETECTION_PATHS:
        url = target.rstrip("/") + path
        response = await fetch(session, url)
        if response and any(fingerprint in response.text for fingerprint in JENKINS_FINGERPRINTS):
            findings["details"].append(f"Jenkins fingerprint detected at {url}")
            version_match = PATTERN_JENKINS_VERSION.search(response.text)
            if version_match:
                findings["version"] = version_match.group(1)

            # Script Console URL detected
            if "/script" in url:
                findings["vulnerable"] = True
                if not safe_mode:
                    # Active probe to test code execution (example: 'println("hello world")')
                    script_exec_url = f"{target.rstrip('/')}/scriptText"
                    probe_response = await session.post(
                        script_exec_url,
                        data={"script": "println('RCE detected')"},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if probe_response and "RCE detected" in probe_response.text:
                        findings["details"].append(f"RCE SUCCESSFUL: {script_exec_url}")
                    else:
                        findings["details"].append(f"Script Console accessible but RCE not verified (safe mode enabled or blocked).")
            break
    return findings if findings["details"] else None

async def process_targets(targets: list[str], safe_mode: bool, concurrency: int, no_verify: bool) -> list[dict]:
    """Process and scan a list of targets asynchronously."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=not no_verify) as session:
        async def bound_probe(target):
            async with semaphore:
                print(f"{c(CYAN, '[*]')} Scanning {target}...")
                result = await probe_target(session, target, safe_mode)
                if result:
                    results.append(result)
                    level = c(RED, "CRITICAL") if result["vulnerable"] else c(YELLOW, "HIGH")
                    print(f"{c(GREEN if result['vulnerable'] else YELLOW, '[+]')} {target} - {level}")
                else:
                    print(f"{c(RED, '[-]')} {target} - {BOLD}Not Vulnerable{RESET}")
        tasks = [bound_probe(target) for target in targets]
        await asyncio.gather(*tasks)
    return results

def parse_args() -> argparse.Namespace:
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(description="Unauthenticated Jenkins Script Console RCE Scanner")
    parser.add_argument("--target", type=str, help="Single target URL (e.g., http://example.com:8080)")
    parser.add_argument("--list", type=str, help="File containing list of target URLs (one per line)")
    parser.add_argument("--output", type=str, help="File to save scan results in JSON")
    parser.add_argument("--safe", action="store_true", help="Detection only without active probing")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL/TLS certificate verification")
    return parser.parse_args()

def save_results(results: list[dict], output_file: str):
    """Save scan results to a JSON file."""
    with open(output_file, "w") as f:
        json.dump({
            "tool": TOOL_NAME,
            "cve": CVE_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": results
        }, f, indent=2)
    print(f"{c(GREEN, '[+]')} Results saved to {output_file}")

async def main():
    args = parse_args()
    if not args.target and not args.list:
        print(f"{c(RED, '[!]')} Error: either --target or --list is required.")
        sys.exit(1)
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            print(f"{c(RED, '[!]')} Error: Could not read file {args.list}")
            sys.exit(1)

    results = await process_targets(
        targets,
        safe_mode=args.safe,
        concurrency=args.concurrency,
        no_verify=args.no_verify,
    )
    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{c(RED, '[!]')} Scan interrupted.")
        sys.exit(1)
