#!/usr/bin/env python3
"""
Apache Tomcat CVE-2025-24813 Partial PUT RCE Scanner
=====================================================
Scans for Apache Tomcat instances vulnerable to the partial PUT
deserialization remote code execution vulnerability (CVE-2025-24813,
CVSS 9.8).

CVE-2025-24813 details:
  - Affects Apache Tomcat 11.0.0-M1 through 11.0.2
                          10.1.0-M1 through 10.1.34
                          9.0.0.M1  through 9.0.98
  - Partial PUT requests with a Content-Range header cause Tomcat to
    store the body as a temporary file under the upload work directory.
  - If the default servlet has write access enabled (readonly=false),
    a two-step attack allows:
      1. Upload a serialized Java payload via a partial PUT to a
         predictable temp file path.
      2. Trigger deserialization by issuing a GET request that maps
         to the temp file, causing Tomcat to deserialize the content
         and execute arbitrary code.
  - No authentication required in typical misconfigured deployments.
  - Fixed in Tomcat 11.0.3, 10.1.35, 9.0.99 (released 2025-03-10).
  - CISA added to KEV catalog; exploitation observed in the wild.
  - Approximately 145,000 internet-exposed Tomcat instances on Shodan
    at time of discovery.

Usage:
  # Scan a single target
  python tomcat_partial_put_scanner.py --target https://tomcat.example.com

  # Scan a list of targets
  python tomcat_partial_put_scanner.py --list targets.txt --output findings.json

  # Detection only — no partial PUT probes
  python tomcat_partial_put_scanner.py --list targets.txt --safe

  # Adjust concurrency and disable TLS verification
  python tomcat_partial_put_scanner.py --list targets.txt --concurrency 50 --no-verify

References:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-24813
  - https://lists.apache.org/thread/y6lzhnwy6nxcq174o1by4p0hxnfk4dr
  - https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.35
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://github.com/SleepingBag945/CVE-2025-24813
"""

import asyncio
import json
import os
import re
import sys
import argparse
import hashlib
import uuid
from datetime import datetime
from urllib.parse import urlparse, urljoin

import httpx

# ── ANSI color codes ──────────────────────────────────────────────────────────

RESET   = "\033[0m"
RED     = "\033[91m"    # CRITICAL
YELLOW  = "\033[93m"    # HIGH
GREEN   = "\033[92m"    # INFO / patched
CYAN    = "\033[96m"    # status/progress
BOLD    = "\033[1m"
DIM     = "\033[2m"

def critical(msg: str) -> str:
    return f"{BOLD}{RED}{msg}{RESET}"

def high(msg: str) -> str:
    return f"{BOLD}{YELLOW}{msg}{RESET}"

def info(msg: str) -> str:
    return f"{GREEN}{msg}{RESET}"

def status(msg: str) -> str:
    return f"{CYAN}{msg}{RESET}"

def dim(msg: str) -> str:
    return f"{DIM}{msg}{RESET}"


# ── Fingerprints & detection patterns ─────────────────────────────────────────

TOMCAT_FINGERPRINTS = [
    # Default Tomcat error pages and landing page
    "Apache Tomcat",
    "Apache Software Foundation",
    "Tomcat/",
    "/tomcat.css",
    "tomcat.png",
    "Apache Tomcat/",
    # Error page markers
    "HTTP Status",
    "org.apache.catalina",
    "org.apache.tomcat",
    # Manager app
    "Tomcat Web Application Manager",
    "Tomcat Manager",
    # Server header
    "Apache-Coyote",
]

# Paths probed during fingerprinting
DETECTION_PATHS = [
    "/",
    "/index.jsp",
    "/index.html",
    "/docs/",
    "/manager/html",
    "/host-manager/html",
    "/examples/",
    "/nonexistent-path-probe-12345",  # 404 page often reveals Tomcat
]

# Version extraction patterns
VERSION_PATTERNS = [
    # From landing page title: "Apache Tomcat/10.1.34"
    r"Apache Tomcat/([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:\.[A-Z0-9-]+)?)",
    # From Server header: "Apache-Coyote/1.1" (older) or "Apache Tomcat/..."
    r"Apache-Coyote/([0-9]+\.[0-9]+)",
    # From error pages
    r"<title>Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)",
    r"<h3>Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)",
    # From version string in docs or /RELEASE-NOTES
    r"Apache Tomcat Version ([0-9]+\.[0-9]+\.[0-9]+)",
    # From header
    r"Tomcat/([0-9]+\.[0-9]+\.[0-9]+)",
]

# Fixed versions per branch
FIXED_VERSIONS = {
    11: (11, 0, 3),
    10: (10, 1, 35),
    9:  (9, 0, 99),
    8:  None,  # EOL, no fix — flag as unsupported
}

# Affected version ranges per branch
AFFECTED_RANGES = {
    11: {"min": (11, 0, 0), "max": (11, 0, 2)},
    10: {"min": (10, 1, 0), "max": (10, 1, 34)},
    9:  {"min": (9, 0, 0),  "max": (9, 0, 98)},
}

REQUEST_TIMEOUT = 10
SEMAPHORE_LIMIT = 30


# ── Version helpers ───────────────────────────────────────────────────────────

def parse_version(text: str):
    """Extract and parse the first Tomcat version string found in text."""
    for pattern in VERSION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            raw = m.group(1)
            # Strip milestone/alpha suffixes like "9.0.0.M1" → (9, 0, 0)
            cleaned = re.sub(r"[^0-9.].*$", "", raw)
            parts = cleaned.rstrip(".").split(".")
            try:
                return tuple(int(x) for x in parts[:3])
            except ValueError:
                continue
    return None


def version_str(v: tuple) -> str:
    if v is None:
        return "unknown"
    return ".".join(str(x) for x in v)


def assess_version(version_tuple) -> dict:
    """
    Assess vulnerability status based on version.
    Returns dict with 'status', 'severity', 'detail'.
    """
    if version_tuple is None:
        return {
            "status": "unknown",
            "severity": "MEDIUM",
            "detail": "Could not extract version — manual verification required",
        }

    major = version_tuple[0]
    range_info = AFFECTED_RANGES.get(major)

    if range_info is None:
        if major <= 8:
            return {
                "status": "eol",
                "severity": "HIGH",
                "detail": (
                    f"Tomcat {version_str(version_tuple)} is end-of-life and receives no security fixes. "
                    "Treat as potentially vulnerable."
                ),
            }
        # Tomcat 12+ not known to be affected
        return {
            "status": "unaffected",
            "severity": "INFO",
            "detail": f"Tomcat {version_str(version_tuple)} is not in a known-affected branch.",
        }

    vmin = range_info["min"]
    vmax = range_info["max"]
    fixed = FIXED_VERSIONS.get(major)

    if vmin <= version_tuple <= vmax:
        return {
            "status": "vulnerable",
            "severity": "CRITICAL",
            "detail": (
                f"Version {version_str(version_tuple)} is in vulnerable range "
                f"{version_str(vmin)}–{version_str(vmax)}. "
                f"Patched version: {version_str(fixed)}."
            ),
        }

    if fixed and version_tuple >= fixed:
        return {
            "status": "patched",
            "severity": "INFO",
            "detail": f"Version {version_str(version_tuple)} is patched (>= {version_str(fixed)}).",
        }

    # Below vmin means older than the affected range start (unusual)
    return {
        "status": "unknown",
        "severity": "MEDIUM",
        "detail": (
            f"Version {version_str(version_tuple)} is older than the known vulnerable range start. "
            "CVE applicability unclear — verify manually."
        ),
    }


# ── URL helpers ───────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ── Fingerprinting ────────────────────────────────────────────────────────────

async def fingerprint_tomcat(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict | None:
    """
    Probe a set of well-known paths to detect Apache Tomcat.
    Returns detection info dict, or None if Tomcat not detected.
    """
    async with semaphore:
        version = None
        detected = False
        server_header = None
        detection_path = None

        for path in DETECTION_PATHS:
            url = base_url + path
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 SecurityResearch/tomcat-scanner"},
                )
                body = r.text
                headers_str = str(r.headers)

                # Check fingerprints in body AND headers
                combined = body + headers_str
                if any(fp.lower() in combined.lower() for fp in TOMCAT_FINGERPRINTS):
                    detected = True
                    detection_path = path

                    # Try to extract version from body
                    v = parse_version(body)
                    if v:
                        version = v

                    # Try from Server header
                    srv = r.headers.get("server", "")
                    if srv:
                        server_header = srv
                        if version is None:
                            v = parse_version(srv)
                            if v:
                                version = v
                    break

            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout):
                continue
            except Exception:
                continue

        if not detected:
            return None

        return {
            "url": base_url,
            "version": version,
            "version_str": version_str(version),
            "server_header": server_header,
            "detection_path": detection_path,
        }


# ── Additional version probes ─────────────────────────────────────────────────

async def probe_version_endpoints(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> tuple | None:
    """
    Try additional paths that may expose the exact Tomcat version.
    Returns version tuple if found, else None.
    """
    async with semaphore:
        version_paths = [
            "/RELEASE-NOTES",
            "/RUNNING.txt",
            "/docs/changelog.html",
            "/docs/",
            "/manager/text/serverinfo",
        ]
        for path in version_paths:
            try:
                r = await client.get(
                    base_url + path,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 SecurityResearch/tomcat-scanner"},
                )
                if r.status_code == 200:
                    v = parse_version(r.text)
                    if v:
                        return v
            except Exception:
                continue
    return None


# ── Partial PUT probe ─────────────────────────────────────────────────────────

async def probe_partial_put(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> dict:
    """
    Probe for the CVE-2025-24813 partial PUT vulnerability.

    The attack works by sending a PUT request with a Content-Range header.
    In vulnerable Tomcat with the DefaultServlet writable (readonly=false),
    Tomcat stores the body as a temp file. This probe uses a harmless
    plaintext payload — no shellcode, no serialized objects, no exec().

    A 201 Created or 204 No Content response to a partial PUT request
    indicates that:
      (a) The DefaultServlet has write access enabled (misconfigured), AND
      (b) Tomcat accepted the partial PUT, meaning the temp file storage
          mechanism is active — the prerequisite for exploitation.

    This is a safe indicator-of-exposure probe, not a full exploit.
    """
    if safe_mode:
        return {"partial_put_writable": None, "note": "skipped (safe mode)"}

    async with semaphore:
        # Use a unique probe filename to avoid collisions across scans
        probe_id = uuid.uuid4().hex[:12]
        probe_path = f"/cve-2025-24813-probe-{probe_id}.txt"
        probe_url = base_url + probe_path

        # Partial PUT body — harmless plaintext canary
        canary_body = f"CVE-2025-24813-probe-{probe_id}".encode()
        total_size = len(canary_body) + 1024  # Indicate larger intended upload

        try:
            r = await client.put(
                probe_url,
                content=canary_body,
                timeout=REQUEST_TIMEOUT,
                follow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 SecurityResearch/tomcat-scanner",
                    "Content-Type": "application/octet-stream",
                    "Content-Range": f"bytes 0-{len(canary_body)-1}/{total_size}",
                    "Content-Length": str(len(canary_body)),
                },
            )

            # 201 = file created (writable DefaultServlet, partial PUT accepted)
            # 204 = updated
            # 409 = conflict (partial PUT accepted, file exists)
            if r.status_code in (201, 204, 409):
                return {
                    "partial_put_writable": True,
                    "probe_url": probe_url,
                    "response_status": r.status_code,
                    "note": (
                        f"Tomcat accepted partial PUT (HTTP {r.status_code}). "
                        "DefaultServlet has write access — prerequisite for CVE-2025-24813 confirmed."
                    ),
                }

            # 405 = PUT method not allowed (DefaultServlet readonly — not writable)
            # 403 = forbidden
            # 404 = path not found but server responded (interesting)
            return {
                "partial_put_writable": False,
                "probe_url": probe_url,
                "response_status": r.status_code,
                "note": (
                    f"Tomcat rejected partial PUT (HTTP {r.status_code}). "
                    "DefaultServlet appears to be in read-only mode."
                ),
            }

        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            return {"partial_put_writable": None, "error": f"Connection error: {str(e)[:80]}"}
        except Exception as e:
            return {"partial_put_writable": None, "error": str(e)[:100]}


# ── Check for open Manager app ────────────────────────────────────────────────

async def probe_manager_access(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> dict:
    """
    Check whether the Tomcat Manager or Host Manager app is accessible
    without authentication (or with default credentials).
    An accessible manager amplifies exploit impact significantly.
    """
    async with semaphore:
        exposed = []
        manager_paths = [
            ("/manager/html", "Manager Web UI"),
            ("/manager/text", "Manager Text API"),
            ("/host-manager/html", "Host Manager Web UI"),
            ("/manager/status", "Manager Status"),
        ]

        default_creds = [
            ("tomcat", "tomcat"),
            ("admin", "admin"),
            ("tomcat", "s3cret"),
            ("admin", "password"),
            ("manager", "manager"),
        ]

        for path, label in manager_paths:
            url = base_url + path
            try:
                # First try unauthenticated
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 SecurityResearch/tomcat-scanner"},
                )

                if r.status_code == 200:
                    exposed.append({
                        "path": path,
                        "label": label,
                        "access": "unauthenticated",
                        "severity": "CRITICAL",
                    })
                    continue

                if r.status_code == 401:
                    # Try default credentials
                    for user, passwd in default_creds:
                        try:
                            r2 = await client.get(
                                url,
                                timeout=REQUEST_TIMEOUT,
                                follow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0 SecurityResearch/tomcat-scanner"},
                                auth=(user, passwd),
                            )
                            if r2.status_code == 200:
                                exposed.append({
                                    "path": path,
                                    "label": label,
                                    "access": f"default credentials ({user}:{passwd})",
                                    "severity": "CRITICAL",
                                })
                                break
                        except Exception:
                            continue

            except Exception:
                continue

        return {"manager_exposed": exposed}


# ── Full target scan ──────────────────────────────────────────────────────────

async def scan_target(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
) -> dict | None:
    """
    Full vulnerability scan of a single Tomcat target.
    Returns a findings dict, or None if Tomcat is not detected.
    """
    base_url = normalize_url(url)

    # Step 1: Fingerprint
    detection = await fingerprint_tomcat(client, base_url, semaphore)
    if not detection:
        return None

    result = {
        "url": base_url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tomcat_detected": True,
        "version": detection["version_str"],
        "server_header": detection.get("server_header"),
        "cve": "CVE-2025-24813",
        "risk": None,
        "findings": [],
    }

    # Step 2: Try to get a more precise version if not found
    version = detection["version"]
    if version is None:
        v2 = await probe_version_endpoints(client, base_url, semaphore)
        if v2:
            version = v2
            result["version"] = version_str(version)

    # Step 3: Version assessment
    v_assessment = assess_version(version)
    result["findings"].append({
        "type": "version_check",
        "severity": v_assessment["severity"],
        "detail": v_assessment["detail"],
    })

    if v_assessment["status"] == "vulnerable":
        result["risk"] = "CRITICAL"
    elif v_assessment["status"] in ("eol",):
        result["risk"] = "HIGH"
    elif v_assessment["status"] == "unknown":
        result["risk"] = "MEDIUM"
    else:
        result["risk"] = "LOW"

    # Step 4: Partial PUT probe (unless safe mode)
    put_result = await probe_partial_put(client, base_url, semaphore, safe_mode)
    if put_result.get("partial_put_writable") is True:
        result["findings"].append({
            "type": "partial_put_writable",
            "severity": "CRITICAL",
            "detail": put_result.get("note", "DefaultServlet accepts partial PUT — write access confirmed."),
            "probe_url": put_result.get("probe_url"),
            "response_status": put_result.get("response_status"),
        })
        result["risk"] = "CRITICAL"
        result["exploitation_prerequisite_met"] = True
    elif put_result.get("partial_put_writable") is False:
        result["findings"].append({
            "type": "partial_put_readonly",
            "severity": "INFO",
            "detail": put_result.get("note", "DefaultServlet is read-only; partial PUT not accepted."),
            "response_status": put_result.get("response_status"),
        })
        result["exploitation_prerequisite_met"] = False
    elif put_result.get("note") == "skipped (safe mode)":
        result["findings"].append({
            "type": "partial_put_skipped",
            "severity": "INFO",
            "detail": "Partial PUT probe skipped (--safe mode).",
        })

    # Step 5: Manager access check
    manager_result = await probe_manager_access(client, base_url, semaphore)
    for exposed in manager_result.get("manager_exposed", []):
        result["findings"].append({
            "type": "manager_accessible",
            "severity": exposed["severity"],
            "detail": (
                f"Tomcat {exposed['label']} accessible via {exposed['access']} at {exposed['path']}. "
                "An accessible manager enables direct WAR deployment — amplifies RCE impact."
            ),
        })
        if result["risk"] not in ("CRITICAL",):
            result["risk"] = "CRITICAL"

    return result


# ── Output / display ──────────────────────────────────────────────────────────

def print_result(result: dict) -> None:
    risk = result.get("risk", "?")
    url = result["url"]
    version = result.get("version", "unknown")

    risk_fmt = {
        "CRITICAL": critical,
        "HIGH":     high,
        "MEDIUM":   lambda s: f"\033[95m{s}{RESET}",  # magenta
        "LOW":      info,
        "INFO":     info,
    }.get(risk, lambda s: s)

    sep = "=" * 72
    print(f"\n{sep}")
    print(f"  {status('TOMCAT FOUND')}  : {BOLD}{url}{RESET}")
    print(f"  Version       : {version}")
    print(f"  Risk          : {risk_fmt(risk)}")

    for finding in result.get("findings", []):
        sev = finding.get("severity", "?")
        detail = finding.get("detail", "")
        sev_fmt = {
            "CRITICAL": critical,
            "HIGH":     high,
            "MEDIUM":   lambda s: f"\033[95m{s}{RESET}",
            "INFO":     info,
        }.get(sev, lambda s: s)
        print(f"  [{sev_fmt(sev)}] {detail}")
        if "probe_url" in finding:
            print(f"    {dim('Probe URL')}: {finding['probe_url']}")

    if result.get("exploitation_prerequisite_met"):
        print(f"\n  {critical('>>> WRITE ACCESS CONFIRMED — CVE-2025-24813 EXPLOITATION PREREQUISITE MET <<<')}")
    elif result.get("risk") == "CRITICAL" and "version" in result:
        print(f"\n  {critical('>>> VULNERABLE VERSION DETECTED — PATCH TO LATEST TOMCAT IMMEDIATELY <<<')}")

    print(sep)


# ── Main ──────────────────────────────────────────────────────────────────────

async def main(args):
    targets = []

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
            print(critical(f"[!] File not found: {args.list}"))
            sys.exit(1)

    if not targets:
        print(critical("[!] No targets specified. Use --target or --list."))
        sys.exit(1)

    # Deduplicate while preserving order
    targets = list(dict.fromkeys(targets))

    print(status(f"[*] CVE-2025-24813 — Apache Tomcat Partial PUT RCE Scanner"))
    print(status(f"[*] Scanning {len(targets)} target(s)"))
    if args.safe:
        print(info("[*] Safe mode active: partial PUT probes will be skipped"))
    print()

    semaphore = asyncio.Semaphore(args.concurrency)
    findings = []

    ssl_verify = not args.no_verify
    async with httpx.AsyncClient(
        verify=ssl_verify,
        timeout=REQUEST_TIMEOUT,
        limits=httpx.Limits(max_connections=args.concurrency + 10),
    ) as client:
        tasks = [scan_target(client, t, semaphore, args.safe) for t in targets]
        completed = 0

        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1

            # Progress indicator (overwrites line)
            found_so_far = len(findings)
            sys.stdout.write(
                f"\r{dim(f'  Progress: {completed}/{len(targets)} | Tomcat found: {found_so_far}  ')}"
            )
            sys.stdout.flush()

            if result:
                findings.append(result)
                sys.stdout.write("\r" + " " * 60 + "\r")  # clear progress line
                print_result(result)

    # Clear progress line
    sys.stdout.write("\r" + " " * 60 + "\r")

    # Summary
    critical_findings = [r for r in findings if r.get("risk") == "CRITICAL"]
    high_findings     = [r for r in findings if r.get("risk") == "HIGH"]
    medium_findings   = [r for r in findings if r.get("risk") == "MEDIUM"]
    low_findings      = [r for r in findings if r.get("risk") in ("LOW", "INFO")]

    print(f"\n{'=' * 60}")
    print(f"{BOLD}SCAN COMPLETE — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC{RESET}")
    print(f"  Targets scanned      : {len(targets)}")
    print(f"  Tomcat instances     : {len(findings)}")
    print(f"  {critical('CRITICAL')}              : {len(critical_findings)}")
    print(f"  {high('HIGH')}                 : {len(high_findings)}")
    print(f"  {info('MEDIUM')}               : {len(medium_findings)}")
    print(f"  {info('LOW/patched')}          : {len(low_findings)}")
    print(f"{'=' * 60}")

    # Highlight write-access confirmed instances
    write_confirmed = [r for r in findings if r.get("exploitation_prerequisite_met")]
    if write_confirmed:
        print(f"\n{critical('Write-access confirmed (full exploit prerequisite met):')}")
        for r in write_confirmed:
            print(f"  {r['url']}  (v{r['version']})")

    elif critical_findings:
        print(f"\n{critical('CRITICAL — Vulnerable versions detected:')}")
        for r in critical_findings:
            print(f"  {r['url']}  (v{r['version']})")

    if args.output:
        if findings:
            with open(args.output, "w") as fh:
                json.dump(findings, fh, indent=2)
            print(f"\n{info(f'[*] Results saved to {args.output}')}")
        else:
            print(f"\n{dim('[*] No Tomcat instances found — nothing written to output file.')}")

    return findings


if __name__ == "__main__":
    # Suppress urllib3 InsecureRequestWarning when --no-verify is used
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        description="Apache Tomcat CVE-2025-24813 Partial PUT RCE Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tomcat_partial_put_scanner.py --target https://tomcat.example.com
  python tomcat_partial_put_scanner.py --list hosts.txt --output results.json
  python tomcat_partial_put_scanner.py --list hosts.txt --safe --concurrency 50
  python tomcat_partial_put_scanner.py --target http://10.0.0.5:8080 --no-verify

Notes:
  Default servlet write access (readonly=false in web.xml) is required for
  the exploit to succeed. The --safe flag skips the partial PUT probe entirely,
  performing version-based detection only.
        """,
    )
    parser.add_argument("--target",      help="Single target URL (e.g. https://tomcat.example.com)")
    parser.add_argument("--list",        help="File containing one target URL per line")
    parser.add_argument("--output",      help="Write findings to this JSON file")
    parser.add_argument("--safe",        action="store_true",
                                         help="Skip active partial PUT probes (detection only)")
    parser.add_argument("--concurrency", type=int, default=30,
                                         help="Maximum concurrent requests (default: 30)")
    parser.add_argument("--no-verify",   action="store_true",
                                         help="Disable TLS certificate verification")

    args = parser.parse_args()
    asyncio.run(main(args))
