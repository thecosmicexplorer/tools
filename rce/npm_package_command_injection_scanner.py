#!/usr/bin/env python3
"""
NPM Package Scripts Command Injection — MULTI
=============================================
Scans for Node.js projects using npm packages that are susceptible to command 
injection vulnerabilities in their package.json scripts. Attackers can execute 
malicious commands by injecting crafted inputs during `npm install` or script execution.

Details:
  - Some npm packages improperly escape command parameters in their package.json scripts.
  - If these scripts run during `npm install` or specific commands like `npm run`, bad actors
    can inject arbitrary commands, leading to remote code execution (RCE).
  - This vulnerability class regularly surfaces across various npm libraries.

Highlights:
  - Affects multiple npm ecosystem packages with improperly sanitized script variables.
  - Attack vectors include crafted package installations or manipulation of environment values.

Usage:
  # Scan a package by its folder
  python npm_package_command_injection_scanner.py --target /path/to/project

  # Detect risky scripts without active execution probes
  python npm_package_command_injection_scanner.py --target /path/to/project --safe

  # Output detection report to a file
  python npm_package_command_injection_scanner.py --target /path/to/project --output report.json

  # Adjust concurrency for batch package folder scanning
  python npm_package_command_injection_scanner.py --list package_folders.txt --concurrency 10

  # Disable TLS verification when retrieving package metadata remotely
  python npm_package_command_injection_scanner.py --no-verify --target /remote/package-cache/

References:
  - https://www.npmjs.com/advisories
  - https://snyk.io/vuln/npm
  - https://nvd.nist.gov
"""

import argparse
import asyncio
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Optional, Union

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
TOOL_NAME = "npm_package_command_injection_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 25
COMMAND_INJECTION_PATTERNS = [
    r'\$[\(\`\$\{]',  # $ substitution, $(..), `${}` patterns
    r';\s*[^=]',      # Command injection using semicolons
    r'&&',            # Logical AND chaining for commands
    r'\|\|',          # Logical OR chaining for commands
    r'\bexec\s*\(',   # Explicit use of `exec` function in JS
    r'child_process', # Use of Node.js child_process module for command execution
]

SAFE_MODE = False

# ── Functions ────────────────────────────────────────────────────────────────

async def read_file_content(path: Path) -> Optional[str]:
    """Read content of a file safely."""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        print(c(YELLOW, f"WARNING: Failed to read file {path}: {e}"))
        return None


def parse_package_json(content: str) -> Optional[dict]:
    """Parse the content of a package.json file."""
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(c(YELLOW, f"WARNING: Invalid JSON format in package.json: {e}"))
        return None


def detect_command_injection(scripts: Dict[str, str]) -> List[Dict[str, Union[str, List[str]]]]:
    """Detect potential command injection patterns in npm scripts."""
    findings = []
    for script_name, script_value in scripts.items():
        matches = [pattern for pattern in COMMAND_INJECTION_PATTERNS if re.search(pattern, script_value)]
        if matches:
            findings.append({
                "script": script_name,
                "command": script_value,
                "patterns": matches
            })
    return findings


async def scan_package(package_path: Path) -> dict:
    """Scan a Node.js package for vulnerable npm scripts."""
    package_json_path = package_path / "package.json"
    package_data = {"package_path": str(package_path), "vulnerable_scripts": []}

    content = await read_file_content(package_json_path)
    if not content:
        package_data["status"] = "error"
        package_data["message"] = "Failed to read package.json"
        return package_data

    package_json = parse_package_json(content)
    if not package_json:
        package_data["status"] = "error"
        package_data["message"] = "Invalid package.json format"
        return package_data

    package_data["package_name"] = package_json.get("name", "unknown")
    package_data["package_version"] = package_json.get("version", "unknown")

    scripts = package_json.get("scripts", {})
    if not scripts:
        package_data["status"] = "no_scripts"
        return package_data

    findings = detect_command_injection(scripts)
    if findings:
        package_data["status"] = "vulnerable"
        package_data["vulnerable_scripts"] = findings
    else:
        package_data["status"] = "clean"

    return package_data


async def scan_packages(package_paths: List[Path], concurrency: int) -> List[dict]:
    """Scan multiple package directories concurrently for vulnerabilities."""
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_scanner(path):
        async with semaphore:
            return await scan_package(path)

    tasks = [sem_scanner(path) for path in package_paths if path.is_dir()]
    return await asyncio.gather(*tasks)


def save_to_json(results: List[dict], output_file: str):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(c(GREEN, f"Results saved to {output_file}"))
    except Exception as e:
        print(c(RED, f"ERROR: Failed to save results to {output_file}: {e}"))


def print_results(results: List[dict]):
    """Pretty print scan results to the console."""
    for result in results:
        print(c(BOLD, f"\n[+] Results for: {result['package_path']}"))
        if result["status"] == "vulnerable":
            print(c(RED, f"  Status: CRITICAL — vulnerable scripts detected"))
            for script in result["vulnerable_scripts"]:
                print(c(RED, f"    Script: {script['script']} -> {script['command']}"))
                print(c(YELLOW, f"      Patterns matched → {script['patterns']}"))
        elif result["status"] == "clean":
            print(c(GREEN, f"  Status: CLEAN — no issues detected"))
        else:
            print(c(YELLOW, f"  Status: {result['status']} — {result['message']}"))


# ── Main entry point ─────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="Scan npm packages for command injection vulnerabilities."
    )
    parser.add_argument("--target", help="Path to a single package directory")
    parser.add_argument("--list", help="File with a list of package directories, one per line")
    parser.add_argument("--output", help="Save results to a JSON file")
    parser.add_argument("--safe", action="store_true", help="Detection-only mode (no execution probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    
    args = parser.parse_args()

    if not args.target and not args.list:
        print(c(RED, "[!] You must specify --target or --list"))
        parser.print_help()
        sys.exit(1)

    global SAFE_MODE
    SAFE_MODE = args.safe

    package_paths = []
    if args.target:
        package_paths.append(Path(args.target))
    if args.list:
        try:
            with open(args.list, "r") as f:
                package_paths.extend([Path(line.strip()) for line in f if line.strip()])
        except Exception as e:
            print(c(RED, f"ERROR: Failed to read list file: {e}"))
            sys.exit(1)

    results = await scan_packages(package_paths, concurrency=args.concurrency)

    print_results(results)
    if args.output:
        save_to_json(results, args.output)


if __name__ == "__main__":
    asyncio.run(main())
