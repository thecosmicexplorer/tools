#!/usr/bin/env python3
"""
Git Large Object (LFS) Exposure Scanner
========================================
Scans for publicly exposed Git repositories that use Large File Storage (LFS)
to identify potential sensitive file leaks due to misconfigured access controls.

Git Large File Storage (LFS) allows storing large binary files outside of the repository
but relies on additional endpoints to access these files. If the LFS server is improperly
secured, attackers can fetch sensitive files without appropriate authentication.

Vulnerability Details:
  - Affects Git repositories configured with LFS
  - Misconfigured LFS endpoints may allow public or unauthorized access
  - Common file types exposed: environment files, build artifacts, private keys, etc.

Usage:
  # Scan a single Git repository
  python git_large_object_exposure_scanner.py --target https://github.com/user/repo.git

  # Scan a list of repositories
  python git_large_object_exposure_scanner.py --list repos.txt --output findings.json

  # Detection-only mode (no active probing for LFS objects)
  python git_large_object_exposure_scanner.py --list repos.txt --safe

Features:
  - Detects if a repository uses Git LFS
  - Attempts to fetch LFS metadata and files for validation
  - Matches exposed files against common sensitive file patterns

References:
  - https://github.com/git-lfs/git-lfs
  - https://docs.github.com/en/repositories/working-with-files/managing-large-files
"""

import asyncio
import argparse
import httpx
import os
import json
import re
from urllib.parse import urlparse

# ── Configuration ──────────────────────────────────────────────────────────────

LFS_MARKERS = [".gitattributes", ".lfsconfig"]

# Common LFS file patterns indicating possible sensitive data
SENSITIVE_FILE_PATTERNS = [
    r".*\.env",
    r".*\.pem",
    r".*\.key",
    r".*\.p12",
    r".*\.crt",
    r".*\.cfg",
    r".*/id_[rd]sa",
    r".*\.backup",
    r".*\.bak",
]

SEMAPHORE_LIMIT = 20
REQUEST_TIMEOUT = 8


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str):
    """
    Normalize a Git repository URL to a base Git HTTP/HTTPS endpoint, removing
    '.git' suffix and any trailing slashes.
    """
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if not url.startswith(("http://", "https://")):
        raise ValueError("Invalid URL format: must start with http:// or https://")
    return url


def check_sensitive_file(filename: str) -> bool:
    """Check if a filename matches known sensitive file patterns."""
    return any(re.match(pattern, filename) for pattern in SENSITIVE_FILE_PATTERNS)


# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_lfs(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore):
    """
    Detect if a Git repository is using Git LFS by checking for LFS-specific markers.
    Returns (True, [detected_files]) if LFS files are identified, else (False, []).
    """
    async with semaphore:
        for marker in LFS_MARKERS:
            try:
                lfs_url = f"{url}/.git/info/attributes"
                response = await client.get(lfs_url, timeout=REQUEST_TIMEOUT)
                if response.status_code == 200 and marker in response.text:
                    return True, response.text.split("\n")
            except Exception:
                pass
        return False, []


async def check_file_exposure(client: httpx.AsyncClient, lfs_file_url: str, semaphore: asyncio.Semaphore):
    """
    Attempt to access a given LFS object URL. Returns True if successful.
    """
    async with semaphore:
        try:
            response = await client.get(lfs_file_url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                # File successfully accessed
                return True, response.content
        except Exception:
            pass
        return False, None


async def scan_repository(client: httpx.AsyncClient, repo_url: str, semaphore: asyncio.Semaphore, safe_mode: bool):
    """
    Scan a single Git repository to detect exposed LFS objects.
    If safe_mode is enabled, this function does not attempt to fetch LFS files.
    """
    results = {
        "repository": repo_url,
        "lfs_detected": False,
        "exposed_files": [],
    }

    try:
        repo_url = normalize_url(repo_url)
        lfs_detected, attributes = await detect_lfs(client, repo_url, semaphore)

        if lfs_detected:
            results["lfs_detected"] = True
            for line in attributes:
                if not line.strip() or line.strip().startswith("#"):
                    continue

                parts = line.split(" ")
                if len(parts) >= 2 and check_sensitive_file(parts[0]):
                    exposed_file_url = f"{repo_url}.git/info/lfs/objects/{parts[1]}"
                    file_data = None

                    # Attempt to fetch the file if not in safe mode
                    if not safe_mode:
                        success, file_data = await check_file_exposure(client, exposed_file_url, semaphore)
                        if success:
                            results["exposed_files"].append({"file": parts[0], "url": exposed_file_url, "content": file_data.decode()[:100]})
                    else:
                        results["exposed_files"].append({"file": parts[0], "url": exposed_file_url})
        return results
    except Exception as e:
        results["error"] = str(e)
        return results


async def scan_targets(targets, safe, concurrency, verify):
    """
    Orchestrate the scanning process for a list of Git repository URLs.
    """
    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(verify=verify) as client:
        tasks = [scan_repository(client, target, semaphore, safe) for target in targets]
        return await asyncio.gather(*tasks)


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scan for exposed git LFS objects.")
    parser.add_argument("--target", help="Target Git repository URL")
    parser.add_argument("--list", help="Path to a file containing a list of repository URLs")
    parser.add_argument("--output", help="Path to save scan results as JSON")
    parser.add_argument("--safe", action="store_true", help="Detection only (no active probes)")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Number of concurrent requests")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    args = parser.parse_args()

    if not args.target and not args.list:
        print("Error: You must provide either --target or --list")
        parser.print_help()
        exit(1)

    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    print("\033[1;33m[INFO] Starting Git LFS exposure scan...\033[0m")
    results = asyncio.run(scan_targets(targets, args.safe, args.concurrency, not args.no_verify))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\033[1;32m[INFO] Results saved to {args.output}\033[0m")
    else:
        print("\033[1;32m[INFO] Scan results:\033[0m")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
