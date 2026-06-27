#!/usr/bin/env python3
"""
Ansible Vault Password Leak Scanner
====================================
Scans for potential Ansible Vault password leaks due to misconfigurations or common pattern mistakes in Ansible playbooks.

Description:
  Ansible Vault is a feature used to encrypt and store sensitive data such as passwords or API credentials. However, due to
  misconfigurations or oversight, Vault passwords are sometimes exposed in playbooks or related files. This tool scans
  for common patterns and misconfigurations that might result in the disclosure of Vault passwords.

Potential risks:
  - Storing plaintext passwords within Ansible playbooks or inventory files.
  - Exposing Vault passwords in shell execution logs with unsafe CLI options.
  - Using insecure practices to pass Vault passwords, e.g., hardcoding them into scripts.

Features:
  - Detects files containing easily identifiable plaintext Vault passwords.
  - Identifies unsafe usage of `--vault-password-file` or similar CLI arguments in shell execution logs.
  - Scans large codebases asynchronously for misconfigurations and password leaks.

Usage:
  # Analyze a single file
  python ansible_vault_password_leak_scanner.py --target playbook.yml

  # Bulk scan from a list of files
  python ansible_vault_password_leak_scanner.py --list ansible_files.txt --output findings.json

  # Run in safe mode to avoid reading sensitive file contents
  python ansible_vault_password_leak_scanner.py --list ansible_files.txt --safe

  # Adjust concurrency for faster scanning of multiple files
  python ansible_vault_password_leak_scanner.py --list ansible_files.txt --concurrency 50

References:
  - https://docs.ansible.com/ansible/latest/user_guide/vault.html
  - https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html

"""

import asyncio
import re
import sys
import json
import argparse
from pathlib import Path
from typing import List

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

TOOL_NAME = "ansible_vault_password_leak_scanner"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

VAULT_PASSWORD_PATTERNS = [
    r'vault_password\s*=\s*["\'](.+?)["\']',  # e.g., vault_password = "password123"
    r'VAULT_PASS\s+=\s+["\'](.*)["\']',       # e.g., VAULT_PASS = "hardcodedkey"
    r'--vault-password-file\s+(\S+)',        # Unsafe practice with `--vault-password-file`
]

# ── Async Helper Functions ────────────────────────────────────────────────────

async def scan_file(filepath: Path, patterns: List[str], semaphore: asyncio.Semaphore, safe_mode: bool = False) -> Optional[dict]:
    """Scan a file for potential Ansible Vault password leaks."""
    async with semaphore:
        try:
            content = filepath.read_text(errors='ignore') if not safe_mode else ""
            results = []

            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    match_text = match.groups()[0].strip() if not safe_mode else "REDACTED"
                    results.append({
                        "file": str(filepath),
                        "pattern": pattern,
                        "match": match_text
                    })

            if results:
                print(f"{c(RED, '[CRITICAL]')} Potential leak found in: {filepath}")
                return {"file": str(filepath), "leaks": results}
        except Exception as e:
            print(f"{c(YELLOW, '[WARN]')} Could not scan file {filepath}: {e}")
        return None


async def scan_files(file_list: List[Path], patterns: List[str], safe_mode: bool, concurrency: int):
    """Scan multiple files asynchronously for potential Vault password leaks."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(scan_file(file_path, patterns, semaphore, safe_mode))
        for file_path in file_list
    ]
    return await asyncio.gather(*tasks)

# ── Main Scanner Logic ───────────────────────────────────────────────────────

def run_scanner(target: str, file_list: Optional[str], output_file: Optional[str], safe_mode: bool, concurrency: int):
    """Main function to run the scanner."""
    target_files = []
    
    if target:
        target_path = Path(target)
        if target_path.is_file():
            target_files.append(target_path)
        else:
            print(c(RED, f"[ERROR] File not found: {target}"))
            sys.exit(1)
    
    if file_list:
        list_path = Path(file_list)
        if list_path.is_file():
            with open(list_path, 'r') as f:
                target_files.extend([Path(line.strip()) for line in f if line.strip()])
        else:
            print(c(RED, f"[ERROR] File list not found: {file_list}"))
            sys.exit(1)

    if not target_files:
        print(c(RED, "[ERROR] No valid targets specified."))
        sys.exit(1)

    print(c(CYAN, f"[INFO] Scanning {len(target_files)} files for Ansible Vault password leaks..."))

    # Run the scans
    all_results = asyncio.run(scan_files(target_files, VAULT_PASSWORD_PATTERNS, safe_mode, concurrency))

    # Filter out None results and save valid findings
    findings = [result for result in all_results if result is not None]

    if findings:
        print(c(RED, f"[CRITICAL] {len(findings)} potential leaks found."))
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(findings, f, indent=4)
            print(c(GREEN, f"[INFO] Results saved to: {output_file}"))
    else:
        print(c(GREEN, "[INFO] No leaks found."))


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ansible Vault Password Leak Scanner"
    )
    parser.add_argument("-t", "--target", help="Target file path to scan (e.g., playbook.yml).")
    parser.add_argument("-l", "--list", help="File containing list of target file paths to scan.")
    parser.add_argument("-o", "--output", help="File path to save JSON results.")
    parser.add_argument("--safe", action="store_true", help="Run in safe mode (detection-only, no contents will be shown).")
    parser.add_argument("--concurrency", type=int, default=30, help="Maximum number of concurrent file scans.")
    
    args = parser.parse_args()

    try:
        run_scanner(
            target=args.target,
            file_list=args.list,
            output_file=args.output,
            safe_mode=args.safe,
            concurrency=args.concurrency,
        )
    except KeyboardInterrupt:
        print(c(RED, "\n[ERROR] Scan interrupted by user."))
        sys.exit(1)
