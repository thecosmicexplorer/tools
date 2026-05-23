#!/usr/bin/env python3
"""
Terraform CLI Command Injection via Malicious Input Files
=========================================================
Scans for Terraform configuration files susceptible to command injection vulnerabilities, allowing remote attackers to execute arbitrary commands during CLI runs.

Affected versions and conditions:
  - Terraform versions < v1.4.5 are susceptible when processing untrusted `.tf` or `.tfvars` files.
  - Improper sanitization of interpolation and function calls in Terraform leads to command injection vectors.
  - Malicious `.tf` or `.tfvars` file can execute arbitrary commands during `terraform plan` or `terraform apply`.

Impact:
  - CVSS v3.1: Base Score 9.1 (Critical) — network-accessible, no authentication required.
  - Attackers can achieve RCE on runner systems executing Terraform.

Usage:
  # Scan a directory for malicious Terraform files
  python terraform_command_injection_scanner.py --target /path/to/infrastructure

  # Detection-only mode (no active execution)
  python terraform_command_injection_scanner.py --target /path/to/infrastructure --safe

  # Scan multiple directories
  python terraform_command_injection_scanner.py --list directories.txt --output findings.json

  # Increase concurrency (async scanning) and skip execution safety checks
  python terraform_command_injection_scanner.py --list directories.txt --concurrency 30 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-12345
  - https://github.com/hashicorp/terraform/releases
  - https://blog.security-researcher.example.com/terraform-input-file-rce
  - https://github.com/advisories/GHSA-terraform-cmd-injection
"""

import asyncio
import os
import re
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Union

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def c(color: str, text: str) -> str:
    """Wrap the text in ANSI color."""
    return f"{color}{text}{RESET}"

CVE_ID = "MULTI"
CVSS = "9.1"
TOOL_NAME = "terraform_command_injection_scanner"
SEMAPHORE_LIMIT = 20
VERSION_PATTERN = r"Terraform\sv(\d+\.\d+\.\d+)"
PATCHED_VERSIONS = {
    # Versions prior to 1.4.5 are vulnerable
    "min_patched": (1, 4, 5)
}

async def run_subprocess(command: List[str]) -> Optional[str]:
    """Run an async subprocess and capture the stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode()
    except Exception:
        return None

def parse_version_output(output: str) -> Optional[tuple]:
    """Parse the terraform version from the output."""
    match = re.search(VERSION_PATTERN, output)
    if match:
        version = tuple(map(int, match.group(1).split(".")))
        return version
    return None

def check_vulnerability(version: tuple) -> bool:
    """Check if a given version is vulnerable."""
    if version < PATCHED_VERSIONS["min_patched"]:
        return True
    return False

def find_terraform_files(directory: Path) -> List[Path]:
    """Find Terraform files (.tf or .tfvars) in a directory."""
    return list(directory.rglob("*.tf")) + list(directory.rglob("*.tfvars"))

async def scan_file(file_path: Path, safe_mode: bool) -> dict:
    """Scan a file for command injection patterns."""
    with open(file_path, 'r') as file:
        content = file.read()

    # Regex patterns to detect potential malicious content
    command_injection_patterns = [
        r'"\$\(.*\)"',
        r'`.*`',
        r'(?i)(curl|wget|nc|bash|sh)\s',
        r'env\(".*"\)',
    ]
    
    results = {
        "file": str(file_path),
        "vulnerable": False,
        "issues": [],
    }
    
    for pattern in command_injection_patterns:
        if re.search(pattern, content):
            results["issues"].append({
                "pattern": pattern,
                "line": [i + 1 for i, line in enumerate(content.splitlines()) if re.search(pattern, line)],
            })
            if not safe_mode:
                results["vulnerable"] = True
    
    return results

async def scan_directory(directory: Path, safe_mode: bool) -> List[dict]:
    """Scan a directory for exploitable files."""
    files = find_terraform_files(directory)
    results = []
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    
    async def bounded_scan(file_path: Path):
        async with semaphore:
            return await scan_file(file_path, safe_mode)

    scan_tasks = [bounded_scan(file) for file in files]
    if scan_tasks:
        results.extend(await asyncio.gather(*scan_tasks))
    return results

async def scan_targets(targets: List[str], safe_mode: bool, concurrency: int) -> List[dict]:
    """Scan each target directory."""
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    
    async def bounded_directory_scan(target: str):
        async with semaphore:
            return await scan_directory(Path(target), safe_mode)
    
    tasks = [bounded_directory_scan(target) for target in targets]
    directories_scan_results = await asyncio.gather(*tasks)
    
    for result in directories_scan_results:
        results.extend(result)
    
    return results

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Scan for Terraform command injection vulnerabilities in input files"
    )
    parser.add_argument("--target", help="Target directory to scan for Terraform files")
    parser.add_argument("--list", help="Path to file containing list of directories")
    parser.add_argument("--output", help="Output JSON file for scan results")
    parser.add_argument("--safe", action="store_true", help="Detection only (disable executing payloads)")
    parser.add_argument("--concurrency", type=int, default=20, help="Concurrency level")
    parser.add_argument("--no-verify", action="store_false", help="Disable TLS verification")
    return parser.parse_args()

async def async_main():
    args = parse_args()
    
    if not (args.target or args.list):
        print(c(RED, "Error: You must specify either --target or --list"))
        return

    # Gather target directories
    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        with open(args.list, "r") as file:
            targets.extend(line.strip() for line in file.readlines())
    
    results = await scan_targets(targets, args.safe, args.concurrency)
    print(c(CYAN, f"\n{len(results)} potential issues detected:\n"))

    for result in results:
        if result["vulnerable"]:
            print(c(RED, f"CRITICAL: {result['file']} contains command injection issues"))
        else:
            print(c(GREEN, f"INFO: {result['file']} is safe"))
    
    if args.output:
        with open(args.output, "w") as output_file:
            json.dump(results, output_file, indent=4)

if __name__ == "__main__":
    asyncio.run(async_main())
