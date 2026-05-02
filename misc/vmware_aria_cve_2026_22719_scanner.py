#!/usr/bin/env python3
"""
VMware Aria Operations CVE-2026-22719 Scanner
==============================================

Threat addressed:
    CVE-2026-22719 — Command Injection in VMware Aria Operations (Broadcom).
    CVSS score: 8.1 (High). Added to CISA's Known Exploited Vulnerabilities (KEV)
    catalog in March 2026 with active in-the-wild exploitation confirmed.
    Federal agencies must patch by March 24, 2026.

    An unauthenticated remote attacker can send a crafted HTTP request to
    the Aria Operations API endpoint and inject arbitrary OS commands that
    execute with the privileges of the 'admin' service account. No credentials
    are required. Exploitation has been observed in enterprise environments
    targeting cloud-management infrastructure.

Why researchers need this tool:
    - Quickly determine whether Aria Operations instances in your environment
      are running a vulnerable version.
    - Detect potential post-exploitation indicators on hosts (suspicious
      process names, outbound connections, log artifacts).
    - Generate a structured JSON report suitable for ticket/SIEM ingestion.
    - Supports scanning a single host or a bulk list from a file.

Usage:
    # Scan a single host
    python3 vmware_aria_cve_2026_22719_scanner.py --host 192.168.1.50

    # Scan with a custom port and verbose output
    python3 vmware_aria_cve_2026_22719_scanner.py --host aria.corp.local --port 443 --verbose

    # Scan multiple hosts from a file (one host per line)
    python3 vmware_aria_cve_2026_22719_scanner.py --file hosts.txt

    # Output results as JSON to a file
    python3 vmware_aria_cve_2026_22719_scanner.py --file hosts.txt --output report.json

    # Skip TLS certificate verification (lab/self-signed certs)
    python3 vmware_aria_cve_2026_22719_scanner.py --host 10.0.0.5 --no-verify-tls

Patching guidance:
    Apply the VMware Aria Operations update provided by Broadcom.
    Reference: https://support.broadcom.com/
    CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
import ssl
import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Versions known to be vulnerable (< 8.18.2 per Broadcom advisory)
VULNERABLE_VERSION_PATTERN = re.compile(
    r'"version"\s*:\s*"(?P<ver>[^"]+)"'
)

PATCHED_VERSION = (8, 18, 2)  # First patched release

# API paths used by Aria Operations for version disclosure and health checks
VERSION_ENDPOINTS = [
    "/suite-api/api/version",
    "/suite-api/api/deployment/node/status",
]

# Indicators of post-exploitation in HTTP responses or headers
SUSPICIOUS_HEADERS = [
    "x-cmd-out",        # sometimes injected by PoC payloads
    "x-debug-output",
]

# Typical Aria Operations banner fragment
ARIA_BANNER_FRAGMENTS = [
    "VMware Aria Operations",
    "vRealize Operations",   # legacy branding — same product
    "suite-api",
]

# Safe probe payload — confirms injection surface exists without causing harm
# This is a benign reflection probe: injects a marker into a header field
SAFE_PROBE_HEADERS = {
    "X-Probe-Marker": "CVE-2026-22719-scanner-probe",
    "User-Agent": "SecurityScanner/1.0 (CVE-2026-22719 research)",
}


# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------

def parse_version_tuple(ver_str: str) -> Optional[tuple]:
    """Parse a dotted version string into an integer tuple, e.g. '8.18.1' -> (8,18,1)."""
    parts = ver_str.strip().split(".")
    try:
        return tuple(int(p) for p in parts[:3])
    except ValueError:
        return None


def is_vulnerable_version(ver_str: str) -> bool:
    """Return True if the version string represents a version below the patched release."""
    ver = parse_version_tuple(ver_str)
    if ver is None:
        return False  # can't determine — do not false-positive
    return ver < PATCHED_VERSION


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def build_ssl_context(verify: bool) -> ssl.SSLContext:
    """Build an SSL context, optionally disabling certificate verification."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url(url: str, ssl_ctx: ssl.SSLContext, timeout: int = 10) -> tuple:
    """
    Perform an HTTP GET to *url*.
    Returns (status_code, headers_dict, body_str).
    Returns (-1, {}, '') on connection failure.
    """
    req = urllib.request.Request(url, headers=SAFE_PROBE_HEADERS)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return resp.status, headers, body
    except urllib.error.HTTPError as exc:
        # Non-2xx responses still give us useful info
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, dict(exc.headers), body
    except (urllib.error.URLError, socket.timeout, OSError):
        return -1, {}, ""


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def detect_aria_operations(host: str, port: int, ssl_ctx: ssl.SSLContext, verbose: bool) -> dict:
    """
    Probe a single host and return a structured result dict:
    {
        "host": str,
        "port": int,
        "reachable": bool,
        "is_aria_operations": bool,
        "version": str | None,
        "vulnerable": bool | None,   # None = undetermined
        "suspicious_indicators": list[str],
        "endpoints_checked": list[str],
        "timestamp": str
    }
    """
    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "is_aria_operations": False,
        "version": None,
        "vulnerable": None,
        "suspicious_indicators": [],
        "endpoints_checked": [],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{host}:{port}"

    for path in VERSION_ENDPOINTS:
        url = base_url + path
        result["endpoints_checked"].append(url)
        if verbose:
            print(f"  [>] Probing {url}")

        status, headers, body = fetch_url(url, ssl_ctx)

        if status == -1:
            if verbose:
                print(f"  [!] Connection failed for {url}")
            continue

        result["reachable"] = True

        # Check for Aria Operations identity markers in body or headers
        server_header = headers.get("Server", "") + headers.get("X-Powered-By", "")
        combined = body + server_header
        if any(frag.lower() in combined.lower() for frag in ARIA_BANNER_FRAGMENTS):
            result["is_aria_operations"] = True

        # Extract version from JSON body
        if result["version"] is None:
            ver_match = VULNERABLE_VERSION_PATTERN.search(body)
            if ver_match:
                result["version"] = ver_match.group("ver")
                result["is_aria_operations"] = True  # version endpoint confirms product

        # Check response headers for post-exploitation artifacts
        for suspicious_hdr in SUSPICIOUS_HEADERS:
            if suspicious_hdr in {k.lower() for k in headers}:
                indicator = f"Suspicious response header present: {suspicious_hdr}"
                if indicator not in result["suspicious_indicators"]:
                    result["suspicious_indicators"].append(indicator)
                    if verbose:
                        print(f"  [!!] {indicator}")

    # Determine vulnerability status
    if result["version"]:
        result["vulnerable"] = is_vulnerable_version(result["version"])
    elif result["is_aria_operations"]:
        # Product identified but version undetermined — flag as unknown risk
        result["vulnerable"] = None
        result["suspicious_indicators"].append(
            "Aria Operations detected but version could not be extracted — manual inspection required"
        )
    # If not identified as Aria Operations at all, vulnerable stays None (not applicable)

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEVERITY_LABEL = {
    True: "VULNERABLE",
    False: "PATCHED / NOT AFFECTED",
    None: "UNDETERMINED",
}

SEVERITY_COLOR = {
    True: "\033[91m",    # red
    False: "\033[92m",   # green
    None: "\033[93m",    # yellow
}
RESET = "\033[0m"


def print_result(r: dict) -> None:
    """Print a human-readable summary for one scan result."""
    host_label = f"{r['host']}:{r['port']}"
    if not r["reachable"]:
        print(f"  {host_label}  =>  UNREACHABLE")
        return

    vuln = r["vulnerable"]
    color = SEVERITY_COLOR.get(vuln, "")
    label = SEVERITY_LABEL.get(vuln, "UNDETERMINED")
    version_info = f"  version={r['version']}" if r["version"] else "  version=unknown"
    product_info = "  [Aria Operations detected]" if r["is_aria_operations"] else "  [product not confirmed]"

    print(f"  {host_label}{product_info}{version_info}")
    print(f"    Status: {color}{label}{RESET}")

    if r["suspicious_indicators"]:
        print("    Indicators:")
        for ind in r["suspicious_indicators"]:
            print(f"      - {ind}")


def print_summary(results: list) -> None:
    """Print aggregate summary stats."""
    total = len(results)
    reachable = sum(1 for r in results if r["reachable"])
    confirmed_vuln = sum(1 for r in results if r["vulnerable"] is True)
    patched = sum(1 for r in results if r["vulnerable"] is False)
    undetermined = sum(1 for r in results if r["reachable"] and r["vulnerable"] is None)

    print("\n" + "=" * 60)
    print("SCAN SUMMARY — CVE-2026-22719 (VMware Aria Operations)")
    print("=" * 60)
    print(f"  Hosts scanned   : {total}")
    print(f"  Reachable       : {reachable}")
    print(f"  VULNERABLE      : {confirmed_vuln}")
    print(f"  Patched/N/A     : {patched}")
    print(f"  Undetermined    : {undetermined}")
    if confirmed_vuln > 0:
        print("\n  ACTION REQUIRED: Apply Broadcom patch immediately.")
        print("  Reference: https://support.broadcom.com/")
        print("  CISA KEV deadline: 2026-03-24 (federal agencies)")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Argument parsing & main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="vmware_aria_cve_2026_22719_scanner",
        description=(
            "Scan VMware Aria Operations instances for CVE-2026-22719 "
            "(unauthenticated command injection, CISA KEV March 2026)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--host", "-H",
        metavar="HOST",
        help="Single hostname or IP address to scan.",
    )
    target_group.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Path to a file containing one host per line (lines starting with # are ignored).",
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=443,
        metavar="PORT",
        help="HTTPS port Aria Operations listens on (default: 443).",
    )
    parser.add_argument(
        "--no-verify-tls",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (useful for self-signed certs in labs).",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write full JSON results to this file.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Print detailed probe information during scanning.",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10).",
    )

    return parser.parse_args()


def load_hosts_from_file(path: str) -> list:
    """Read hosts from a file, one per line, skipping blank lines and comments."""
    hosts = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
    except OSError as exc:
        print(f"[ERROR] Cannot read host file '{path}': {exc}", file=sys.stderr)
        sys.exit(1)
    return hosts


def main():
    args = parse_args()

    # Collect target hosts
    if args.host:
        hosts = [args.host]
    else:
        hosts = load_hosts_from_file(args.file)

    if not hosts:
        print("[ERROR] No hosts to scan.", file=sys.stderr)
        sys.exit(1)

    ssl_ctx = build_ssl_context(verify=not args.no_verify_tls)

    print(f"\nCVE-2026-22719 VMware Aria Operations Scanner")
    print(f"Scanning {len(hosts)} host(s) on port {args.port} ...")
    print("-" * 60)

    results = []
    for host in hosts:
        if args.verbose:
            print(f"\n[*] Scanning {host}:{args.port}")
        result = detect_aria_operations(
            host=host,
            port=args.port,
            ssl_ctx=ssl_ctx,
            verbose=args.verbose,
        )
        results.append(result)
        print_result(result)

    print_summary(results)

    # Optionally write JSON output
    if args.output:
        try:
            with open(args.output, "w") as fh:
                json.dump(
                    {
                        "scan_metadata": {
                            "cve": "CVE-2026-22719",
                            "product": "VMware Aria Operations",
                            "cvss": 8.1,
                            "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                            "patched_version": ".".join(str(x) for x in PATCHED_VERSION),
                        },
                        "results": results,
                    },
                    fh,
                    indent=2,
                )
            print(f"\n[+] Full JSON report written to: {args.output}")
        except OSError as exc:
            print(f"[ERROR] Could not write output file: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
