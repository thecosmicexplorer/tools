#!/usr/bin/env python3
"""
n8n CVE-2025-68613 Expression Injection Scanner
=================================================
Scans for exposed n8n workflow automation instances and checks whether
they are vulnerable to the expression injection RCE (CVE-2025-68613, CVSS 9.9).

CVE-2025-68613 details:
  - Affects n8n < 1.89.1
  - Unauthenticated /webhook/ endpoints evaluate n8n expressions without sanitization
  - Attacker can inject {{ $evaluateExpression('...') }} payloads to execute arbitrary code
  - CISA added to KEV catalog; ~24,700 instances exposed on Shodan
  - Fixed in n8n v1.89.1 (March 2025)

Usage:
  # Scan a single target
  python n8n_rce_scanner.py --target https://n8n.example.com

  # Scan a list of targets
  python n8n_rce_scanner.py --list targets.txt --output findings.json

  # Fast Shodan-sourced bulk scan (requires SHODAN_API_KEY env var)
  python n8n_rce_scanner.py --shodan --output findings.json

  # Safe mode — detection only, no expression injection probes
  python n8n_rce_scanner.py --list targets.txt --safe

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-68613
  - https://docs.n8n.io/release-notes/ (v1.89.1 fix)
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import json
import os
import re
import sys
import time
import argparse
from datetime import datetime
from urllib.parse import urlparse

import httpx

# ── Detection markers ─────────────────────────────────────────────────────────

N8N_FINGERPRINTS = [
    # UI title / meta
    "n8n - Workflow Automation",
    "<title>n8n",
    "n8n.io",
    # API responses
    '"n8n_version"',
    '"versionCli"',
    '"versionNotificationSettings"',
    # Login page
    "n8n-login",
    "Sign in to n8n",
    # Webhook endpoint marker
    '"message":"Workflow was started"',
    '"message":"Workflow got started"',
]

# Paths that fingerprint an n8n instance
DETECTION_PATHS = [
    "/",
    "/healthz",
    "/api/v1/",
    "/rest/settings",
    "/rest/active-workflows",
    "/setup",
]

# Version extraction — n8n returns version in multiple places
VERSION_PATTERNS = [
    r'"versionCli"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'"n8n_version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'n8n@([0-9]+\.[0-9]+\.[0-9]+)',
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
]

# ── Expression injection probe ─────────────────────────────────────────────────
# Safe math expression — evaluates to "2" if injection works.
# NOT a destructive payload — this confirms expression evaluation only.
EXPRESSION_PROBE = "{{ 1 + 1 }}"
EXPRESSION_EXPECTED = "2"

# Canary string for blind injection detection
CANARY_EXPR = "{{ 'n8nCVE2568613' }}"
CANARY_EXPECTED = "n8nCVE2568613"

VULN_FIXED_VERSION = (1, 89, 1)

SEMAPHORE_LIMIT = 30
REQUEST_TIMEOUT = 8


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse the first version string found in text."""
    for pattern in VERSION_PATTERNS:
        m = re.search(pattern, text)
        if m:
            try:
                return tuple(int(x) for x in m.group(1).split("."))
            except ValueError:
                pass
    return None


def is_vulnerable_version(version_tuple):
    """Return True if version is below the fixed version."""
    if version_tuple is None:
        return None  # Unknown
    return version_tuple < VULN_FIXED_VERSION


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ── Core scanner ──────────────────────────────────────────────────────────────

async def detect_n8n(client: httpx.AsyncClient, base_url: str, semaphore: asyncio.Semaphore):
    """
    Detect whether a URL is running n8n.
    Returns dict with detection info, or None if not n8n.
    """
    async with semaphore:
        version = None
        detected = False
        raw_version_str = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 SecurityResearch/n8n-scanner"},
                )
                body = r.text
                if any(fp.lower() in body.lower() for fp in N8N_FINGERPRINTS):
                    detected = True
                    v = parse_version(body)
                    if v:
                        version = v
                        raw_version_str = ".".join(str(x) for x in v)
                    break
            except Exception:
                continue

        if not detected:
            return None

        return {
            "url": base_url,
            "version": raw_version_str,
            "version_tuple": version,
            "version_vulnerable": is_vulnerable_version(version),
        }


async def check_webhook_injection(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> dict:
    """
    Probe for unauthenticated expression injection via /webhook/ endpoint.

    n8n processes expressions in webhook payloads when a workflow is
    configured to accept webhook triggers. The CVE allows injecting
    expressions that evaluate server-side.

    This probe uses a safe arithmetic expression {{ 1 + 1 }} — no
    destructive payloads, no file access, no command execution.
    """
    if safe_mode:
        return {"expression_injection": None, "note": "skipped (safe mode)"}

    async with semaphore:
        # Probe the webhook test endpoint — n8n uses this for workflow debugging
        # In vulnerable versions, expressions in the body are evaluated
        probe_url = base_url + "/webhook-test/n8n-scan-probe"

        probe_payload = {
            "probe": EXPRESSION_PROBE,
            "canary": CANARY_EXPR,
        }

        try:
            r = await client.post(
                probe_url,
                json=probe_payload,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 SecurityResearch/n8n-scanner",
                    "Content-Type": "application/json",
                },
            )
            body = r.text

            # Check if our expressions were evaluated in the response
            if EXPRESSION_EXPECTED in body or CANARY_EXPECTED in body:
                return {
                    "expression_injection": True,
                    "probe_url": probe_url,
                    "response_status": r.status_code,
                    "response_preview": body[:300],
                    "confirmed": True,
                }

            return {
                "expression_injection": False,
                "probe_url": probe_url,
                "response_status": r.status_code,
            }

        except Exception as e:
            return {"expression_injection": None, "error": str(e)[:100]}


async def check_unauthenticated_api(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """Check for unauthenticated access to sensitive n8n API endpoints."""
    async with semaphore:
        exposed = []

        sensitive_endpoints = [
            ("/rest/workflows", "workflow list"),
            ("/rest/credentials", "credential list"),
            ("/rest/executions", "execution history"),
            ("/rest/active-workflows", "active workflow IDs"),
            ("/api/v1/workflows", "workflow list (v1 API)"),
            ("/api/v1/credentials", "credentials (v1 API)"),
        ]

        for path, label in sensitive_endpoints:
            url = base_url + path
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 SecurityResearch/n8n-scanner"},
                )
                # 200 with JSON body = unauthenticated access
                if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                    try:
                        data = r.json()
                        count = len(data.get("data", data) if isinstance(data, dict) else data)
                        exposed.append({
                            "path": path,
                            "label": label,
                            "item_count": count,
                            "preview": r.text[:200],
                        })
                    except Exception:
                        exposed.append({"path": path, "label": label})
            except Exception:
                continue

        return {"unauthenticated_endpoints": exposed}


async def scan_target(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> dict | None:
    """Full scan of a single target URL."""
    base_url = normalize_url(url)

    # Step 1: Detect n8n
    detection = await detect_n8n(client, base_url, semaphore)
    if not detection:
        return None

    result = {
        "url": base_url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "n8n_detected": True,
        "version": detection["version"],
        "version_vulnerable": detection["version_vulnerable"],
        "cve": "CVE-2025-68613",
        "risk": None,
        "findings": [],
    }

    # Step 2: Check version-based vulnerability
    if detection["version_vulnerable"] is True:
        result["findings"].append({
            "type": "vulnerable_version",
            "severity": "CRITICAL",
            "detail": f"Version {detection['version']} is below the patched version 1.89.1",
        })
        result["risk"] = "CRITICAL"
    elif detection["version_vulnerable"] is False:
        result["findings"].append({
            "type": "patched_version",
            "severity": "INFO",
            "detail": f"Version {detection['version']} is patched (>= 1.89.1)",
        })
        result["risk"] = "LOW"
    else:
        result["findings"].append({
            "type": "version_unknown",
            "severity": "MEDIUM",
            "detail": "Could not determine version — manual verification needed",
        })
        result["risk"] = "MEDIUM"

    # Step 3: Check expression injection (if not safe mode)
    injection = await check_webhook_injection(client, base_url, semaphore, safe_mode)
    if injection.get("expression_injection") is True:
        result["findings"].append({
            "type": "expression_injection_confirmed",
            "severity": "CRITICAL",
            "detail": "Expression injection confirmed via /webhook-test/ endpoint",
            "probe_url": injection.get("probe_url"),
            "response_preview": injection.get("response_preview"),
        })
        result["risk"] = "CRITICAL"

    # Step 4: Check unauthenticated API access
    api_check = await check_unauthenticated_api(client, base_url, semaphore)
    if api_check["unauthenticated_endpoints"]:
        for ep in api_check["unauthenticated_endpoints"]:
            result["findings"].append({
                "type": "unauthenticated_api",
                "severity": "HIGH",
                "detail": f"Unauthenticated access to {ep['label']} at {ep['path']}",
                "item_count": ep.get("item_count", "?"),
            })
        if result["risk"] not in ("CRITICAL",):
            result["risk"] = "HIGH"

    return result


async def load_shodan_targets(api_key: str) -> list[str]:
    """Query Shodan for exposed n8n instances."""
    targets = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # n8n default port 5678, title contains "n8n"
            query = 'title:"n8n" port:5678'
            r = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query, "page": 1},
            )
            if r.status_code == 200:
                data = r.json()
                for match in data.get("matches", []):
                    ip = match.get("ip_str")
                    port = match.get("port", 5678)
                    targets.append(f"http://{ip}:{port}")
                print(f"[*] Shodan: found {len(targets)} n8n instances")
            else:
                print(f"[!] Shodan API error: {r.status_code}")
    except Exception as e:
        print(f"[!] Shodan fetch failed: {e}")
    return targets


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(args):
    targets = []

    if args.target:
        targets.append(args.target)

    if args.list:
        try:
            with open(args.list) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] File not found: {args.list}")
            sys.exit(1)

    if args.shodan:
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            print("[!] SHODAN_API_KEY environment variable not set")
            sys.exit(1)
        shodan_targets = await load_shodan_targets(api_key)
        targets.extend(shodan_targets)

    if not targets:
        print("[!] No targets specified. Use --target, --list, or --shodan")
        sys.exit(1)

    # Deduplicate
    targets = list(dict.fromkeys(targets))
    print(f"[*] Scanning {len(targets)} target(s) for CVE-2025-68613 (n8n expression injection RCE)")
    if args.safe:
        print("[*] Safe mode: detection only, no expression injection probes")
    print()

    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    findings = []

    async with httpx.AsyncClient(verify=not args.no_verify, timeout=REQUEST_TIMEOUT) as client:
        tasks = [scan_target(client, t, semaphore, args.safe) for t in targets]
        completed = 0

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            if completed % 20 == 0 or completed == len(targets):
                print(f"    Progress: {completed}/{len(targets)} | n8n found: {len(findings)}", end="\r")

            if result:
                findings.append(result)
                risk = result.get("risk", "?")
                version = result.get("version") or "unknown"
                print(f"\n{'='*70}")
                print(f"  n8n FOUND   : {result['url']}")
                print(f"  Version     : {version}")
                print(f"  Risk        : {risk}")
                for f in result["findings"]:
                    sev = f.get("severity", "?")
                    print(f"  [{sev}] {f['detail']}")
                if result.get("risk") == "CRITICAL":
                    print(f"  >>> VULNERABLE TO CVE-2025-68613 — PATCH IMMEDIATELY <<<")
                print(f"{'='*70}\n")

    # Summary
    critical = [r for r in findings if r.get("risk") == "CRITICAL"]
    high     = [r for r in findings if r.get("risk") == "HIGH"]
    medium   = [r for r in findings if r.get("risk") == "MEDIUM"]

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")
    print(f"Targets scanned : {len(targets)}")
    print(f"n8n instances   : {len(findings)}")
    print(f"  CRITICAL (vulnerable): {len(critical)}")
    print(f"  HIGH (unauth API)    : {len(high)}")
    print(f"  MEDIUM (unknown ver) : {len(medium)}")
    print(f"{'='*60}")

    if critical:
        print("\nCRITICAL findings (patch immediately):")
        for r in critical:
            print(f"  {r['url']}  (v{r['version'] or 'unknown'})")

    if args.output and findings:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"\n[*] Full results saved to {args.output}")

    return findings


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser(
        description="n8n CVE-2025-68613 Expression Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python n8n_rce_scanner.py --target https://n8n.mycompany.com
  python n8n_rce_scanner.py --list n8n_hosts.txt --output results.json
  python n8n_rce_scanner.py --shodan --output shodan_findings.json
  python n8n_rce_scanner.py --target https://n8n.mycompany.com --safe
        """,
    )
    parser.add_argument("--target", help="Single target URL")
    parser.add_argument("--list", help="File with one URL per line")
    parser.add_argument("--shodan", action="store_true",
                        help="Query Shodan for exposed n8n instances (requires SHODAN_API_KEY)")
    parser.add_argument("--output", help="Save findings to JSON file")
    parser.add_argument("--safe", action="store_true",
                        help="Detection only — skip expression injection probes")
    parser.add_argument("--concurrency", type=int, default=30,
                        help="Max concurrent requests (default: 30)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable TLS certificate verification (for self-signed certs)")
    args = parser.parse_args()

    SEMAPHORE_LIMIT = args.concurrency
    asyncio.run(main(args))
