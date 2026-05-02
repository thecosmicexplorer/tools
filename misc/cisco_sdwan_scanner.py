#!/usr/bin/env python3
"""
Cisco Catalyst SD-WAN Manager (vManage) CVE-2026-20122 / CVE-2026-20128 Scanner
=================================================================================
Detects and assesses Cisco Catalyst SD-WAN Manager (vManage) instances for
two actively exploited vulnerabilities confirmed by Cisco PSIRT on March 5, 2026.
Nation-state group UAT-8616 has been observed exploiting these issues to deploy
webshells and move laterally across SD-WAN infrastructure.

CVE-2026-20122 — Arbitrary File Overwrite (CVSS 5.4)
  - Affects: Cisco Catalyst SD-WAN Manager (vManage), all versions prior to patch
  - Authentication: read-only API credentials sufficient to exploit
  - Impact: authenticated attacker can overwrite arbitrary files via the vManage
    REST API due to improper path sanitisation in the file-upload handling code,
    enabling privilege escalation to the vmanage OS user
  - In-the-wild: UAT-8616 exploited this to write JSP webshells under the Tomcat
    webapp root, achieving persistent remote code execution on SD-WAN controllers

CVE-2026-20128 — Credential Exposure via DCA Config File (CVSS 7.5)
  - Affects: Cisco Catalyst SD-WAN Manager versions < 20.18
  - Authentication: any local OS user (gained via CVE-2026-20122 or another path)
  - Impact: the Data Collection Agent (DCA) stores its credentials in a world-
    readable configuration file; any unprivileged user can read the DCA password
    and use it to authenticate against other SD-WAN Manager nodes, enabling lateral
    movement across the SD-WAN management plane
  - Not affected: vManage 20.18 and later

Active exploitation confirmed by Cisco PSIRT on March 5, 2026.
Reference advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-mgr-2026-Q1
Talos blog: https://blog.talosintelligence.com/uat-8616-sdwan-exploitation-2026/

Usage:
  # Scan a single target
  python cisco_sdwan_scanner.py --target https://vmanage.example.com

  # Scan a list of targets
  python cisco_sdwan_scanner.py --list vmanage_hosts.txt --output findings.json

  # Safe mode — no credential attempts, no webshell probes
  python cisco_sdwan_scanner.py --target https://vmanage.example.com --safe

  # Authenticated scan (enables CVE-2026-20128 DCA check)
  python cisco_sdwan_scanner.py --target https://vmanage.example.com \\
      --username admin --password Admin1234!

  # Disable TLS verification (common with self-signed vManage certs)
  python cisco_sdwan_scanner.py --list hosts.txt --no-verify --output out.json

  # Tune concurrency for large scans
  python cisco_sdwan_scanner.py --list hosts.txt --concurrency 20 --output out.json

References:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-mgr-2026-Q1
  - https://blog.talosintelligence.com/uat-8616-sdwan-exploitation-2026/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20122
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20128
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import json
import re
import sys
import argparse
from datetime import datetime, timezone
from typing import Optional

import httpx

# ── ANSI colour helpers ───────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"       # CRITICAL
YELLOW = "\033[93m"       # HIGH
DIM_Y  = "\033[33m"       # MEDIUM  (dim yellow)
GREEN  = "\033[92m"       # INFO / patched
BOLD   = "\033[1m"
CYAN   = "\033[96m"


def col(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


def severity_colour(sev: str) -> str:
    mapping = {
        "CRITICAL": RED,
        "HIGH":     YELLOW,
        "MEDIUM":   DIM_Y,
        "LOW":      GREEN,
        "INFO":     GREEN,
    }
    return mapping.get(sev.upper(), "")


# ── Constants ─────────────────────────────────────────────────────────────────

REQUEST_TIMEOUT    = 10
SEMAPHORE_LIMIT    = 20

# vManage fingerprint markers
VMANAGE_FINGERPRINTS = [
    "Cisco SD-WAN",
    "vManage",
    "cisco-sdwan",
    "x-csrf-token",
    "sdwan",
    '"configDBVersion"',
    '"tenantId"',
    "Cisco Systems, Inc.",
    "data-ng-app=\"vmanage\"",
    "SD-WAN Manager",
]

DETECTION_PATHS = [
    "/dataservice/client/server",   # JSON API — most reliable
    "/login",                       # HTML login page
    "/index.html",                  # SPA entry point
    "/",                            # root redirect
]

VERSION_PATTERNS = [
    # /dataservice/client/server response:  {"server":"20.12.1","configDBVersion":"..."}
    r'"server"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
    # /about or other endpoints
    r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
    r'vManage\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    r'SD-WAN\s+Manager\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    r'"configDBVersion"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
]

# Default credentials to probe (skipped in --safe mode)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "cisco"),
    ("admin", "Admin1234!"),
    ("admin", "Cisco1234!"),
    ("admin", "vmanage"),
]

# Auth endpoints — try both; vManage versions differ
AUTH_ENDPOINTS = [
    "/j_security_check",
    "/dataservice/client/token",
]

# Unauthenticated API endpoints that should require a session cookie
UNAUTH_API_PATHS = [
    ("/dataservice/device",                    "connected device list"),
    ("/dataservice/template/feature",          "feature template list"),
    ("/dataservice/statistics/interface",      "interface statistics"),
    ("/dataservice/system/information",        "system information"),
    ("/dataservice/clusterManagement/list",    "cluster nodes"),
]

# Webshell paths observed in UAT-8616 campaign and generic Tomcat webshell names
WEBSHELL_PATHS = [
    "/dataservice/index.jsp",
    "/dataservice/cmd.jsp",
    "/dataservice/shell.jsp",
    "/dataservice/upload.jsp",
    "/dataservice/test.jsp",
    "/dataservice/manager.jsp",
    "/dataservice/webshell.jsp",
    "/dataservice/reverse.jsp",
    # Tomcat-standard webapp paths sometimes used when webapps/ is writable
    "/cmd.jsp",
    "/shell.jsp",
    "/upload.jsp",
    "/webshell.jsp",
    "/tomcatwar.jsp",
    "/antSword.jsp",
    "/Godzilla.jsp",
    "/behinder.jsp",
]

# Webshell content markers — presence of these in a 200 response is suspicious
WEBSHELL_MARKERS = [
    "cmd",
    "exec",
    "Runtime",
    "ProcessBuilder",
    "getRuntime",
    "shell",
    "whoami",
    "passphrase",
]

# Versions affected by CVE-2026-20128; >= 20.18 are NOT affected
CVE_20128_UNAFFECTED_MAJOR_MINOR = (20, 18)

# DCA config endpoints; exposure of credential fields is the indicator
DCA_INDICATOR_PATHS = [
    "/dataservice/settings/configuration/dca",
    "/dataservice/dca/settings",
]

DCA_CREDENTIAL_PATTERNS = [
    r'"password"\s*:\s*"[^"]+"',
    r'"dca_password"\s*:\s*"[^"]+"',
    r'"dcaPassword"\s*:\s*"[^"]+"',
    r'"credential"\s*:\s*\{',
]


# ── Utility ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def parse_version(text: str) -> Optional[tuple]:
    """Return the first version tuple found in text, or None."""
    for pattern in VERSION_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            parts = m.group(1).split(".")
            try:
                return tuple(int(x) for x in parts)
            except ValueError:
                pass
    return None


def version_str(tup: Optional[tuple]) -> str:
    if tup is None:
        return "unknown"
    return ".".join(str(x) for x in tup)


def is_20128_affected(version_tuple: Optional[tuple]) -> Optional[bool]:
    """
    CVE-2026-20128: affected if version < 20.18.
    Returns True (affected), False (not affected), or None (unknown).
    """
    if version_tuple is None:
        return None
    major_minor = version_tuple[:2]
    return major_minor < CVE_20128_UNAFFECTED_MAJOR_MINOR


def _risk_level(findings: list) -> str:
    """Derive overall risk from list of finding severities."""
    severities = [f.get("severity", "INFO") for f in findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if "LOW" in severities:
        return "LOW"
    return "INFO"


# ── Fingerprinting ────────────────────────────────────────────────────────────

async def fingerprint_vmanage(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> Optional[dict]:
    """
    Detect whether base_url is a Cisco SD-WAN Manager (vManage) instance.

    Probes multiple paths and checks for vManage-specific response markers,
    HTTP headers, and page content.  Returns a detection dict or None.
    """
    async with semaphore:
        version      = None
        detected     = False
        csrf_present = False
        server_info  = {}

        for path in DETECTION_PATHS:
            url = f"{base_url}{path}"
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityResearch/sdwan-scanner)"},
                )
            except Exception:
                continue

            body    = r.text
            headers = {k.lower(): v for k, v in r.headers.items()}

            # CSRF token header is a strong vManage indicator
            if "x-csrf-token" in headers:
                csrf_present = True
                detected     = True

            # Check fingerprint strings
            if any(fp.lower() in body.lower() for fp in VMANAGE_FINGERPRINTS):
                detected = True

            # Extract version
            if version is None:
                version = parse_version(body)

            # Parse /dataservice/client/server JSON for extra metadata
            if path == "/dataservice/client/server" and r.status_code == 200:
                try:
                    data = r.json()
                    server_info = {
                        "server_version": data.get("server"),
                        "tenant_id":      data.get("tenantId"),
                        "config_db_ver":  data.get("configDBVersion"),
                    }
                    if data.get("server") and version is None:
                        version = parse_version(data.get("server", ""))
                except Exception:
                    pass

            if detected:
                break   # enough evidence — no need to probe further paths

        if not detected:
            return None

        return {
            "url":          base_url,
            "version":      version,
            "csrf_present": csrf_present,
            "server_info":  server_info,
        }


# ── Credential check ──────────────────────────────────────────────────────────

async def check_default_credentials(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
    extra_creds: Optional[tuple] = None,
) -> dict:
    """
    Try default/common credentials against vManage login endpoints.
    Stops at first successful authentication.

    Tested endpoints:
      - POST /j_security_check  (form-encoded, older vManage)
      - GET  /dataservice/client/token  (token fetch after session cookie)

    Returns a dict with `auth_success`, `credential`, and optional `session_token`.
    """
    creds_to_try = list(DEFAULT_CREDS)
    if extra_creds:
        creds_to_try.insert(0, extra_creds)

    async with semaphore:
        for username, password in creds_to_try:
            # ── Attempt 1: POST /j_security_check (form login) ──────────────
            try:
                login_url = f"{base_url}/j_security_check"
                form_data = {
                    "j_username": username,
                    "j_password": password,
                }
                r = await client.post(
                    login_url,
                    data=form_data,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={
                        "User-Agent":   "Mozilla/5.0 (SecurityResearch/sdwan-scanner)",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                # Successful login redirects away from /j_security_check
                # or sets a JSESSIONID cookie
                cookies = dict(r.cookies)
                if (
                    r.status_code in (302, 303)
                    and "JSESSIONID" in cookies
                    and "error" not in r.headers.get("location", "").lower()
                ) or (
                    r.status_code == 200
                    and "JSESSIONID" in cookies
                    and "invalid" not in r.text.lower()
                    and "incorrect" not in r.text.lower()
                ):
                    # Fetch CSRF token to confirm the session is valid
                    token = None
                    try:
                        tr = await client.get(
                            f"{base_url}/dataservice/client/token",
                            timeout=REQUEST_TIMEOUT,
                            cookies=cookies,
                        )
                        if tr.status_code == 200:
                            token = tr.text.strip().strip('"')
                    except Exception:
                        pass

                    return {
                        "auth_success":  True,
                        "method":        "j_security_check",
                        "credential":    (username, password),
                        "session_token": token,
                        "cookies":       cookies,
                    }
            except Exception:
                pass

            # ── Attempt 2: token endpoint with Basic-style header ────────────
            try:
                token_url = f"{base_url}/dataservice/client/token"
                r = await client.get(
                    token_url,
                    auth=(username, password),
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityResearch/sdwan-scanner)"},
                )
                if r.status_code == 200 and len(r.text.strip()) > 10:
                    return {
                        "auth_success":  True,
                        "method":        "basic_token",
                        "credential":    (username, password),
                        "session_token": r.text.strip().strip('"'),
                        "cookies":       dict(r.cookies),
                    }
            except Exception:
                pass

        return {"auth_success": False}


# ── Unauthenticated API check ─────────────────────────────────────────────────

async def check_unauthenticated_api(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> list:
    """
    Probe API endpoints that should require authentication.
    Returns a list of exposed endpoint dicts.
    """
    exposed = []
    async with semaphore:
        for path, label in UNAUTH_API_PATHS:
            url = f"{base_url}{path}"
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityResearch/sdwan-scanner)"},
                )
                ct = r.headers.get("content-type", "")
                if r.status_code == 200 and "json" in ct:
                    try:
                        data  = r.json()
                        items = data.get("data", data)
                        count = len(items) if isinstance(items, list) else "?"
                        exposed.append({
                            "path":    path,
                            "label":   label,
                            "count":   count,
                            "preview": r.text[:250],
                        })
                    except Exception:
                        exposed.append({"path": path, "label": label, "count": "?"})
            except Exception:
                continue
    return exposed


# ── Webshell detection ────────────────────────────────────────────────────────

async def check_webshells(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
) -> list:
    """
    Probe paths associated with webshells observed in UAT-8616 campaigns.
    A hit is flagged when the path returns HTTP 200 with content markers
    suggesting a JSP shell (e.g. references to exec/Runtime/cmd).
    404 and 403 responses are silently skipped.
    """
    hits = []
    async with semaphore:
        for path in WEBSHELL_PATHS:
            url = f"{base_url}{path}"
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityResearch/sdwan-scanner)"},
                )
                if r.status_code == 200:
                    body_lower = r.text.lower()
                    marker_hits = [
                        m for m in WEBSHELL_MARKERS
                        if m.lower() in body_lower
                    ]
                    hits.append({
                        "path":         path,
                        "status_code":  r.status_code,
                        "content_len":  len(r.text),
                        "marker_hits":  marker_hits,
                        "suspicious":   len(marker_hits) >= 2,
                        "preview":      r.text[:200],
                    })
            except Exception:
                continue
    return hits


# ── CVE-2026-20128 DCA credential exposure ────────────────────────────────────

async def check_dca_exposure(
    client: httpx.AsyncClient,
    base_url: str,
    semaphore: asyncio.Semaphore,
    auth_cookies: Optional[dict] = None,
    session_token: Optional[str] = None,
) -> dict:
    """
    Check whether the DCA configuration endpoint exposes credential fields.
    This is the API-layer indicator for CVE-2026-20128; the actual file-read
    vector requires a local OS foothold, but credential references exposed via
    the API are a strong indicator of vulnerable configuration.

    Requires an authenticated session; pass auth_cookies and session_token
    from a prior check_default_credentials() call when available.
    """
    headers = {"User-Agent": "Mozilla/5.0 (SecurityResearch/sdwan-scanner)"}
    if session_token:
        headers["X-XSRF-TOKEN"] = session_token

    async with semaphore:
        for path in DCA_INDICATOR_PATHS:
            url = f"{base_url}{path}"
            try:
                r = await client.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=False,
                    headers=headers,
                    cookies=auth_cookies or {},
                )
                if r.status_code == 200:
                    body = r.text
                    cred_fields = []
                    for pattern in DCA_CREDENTIAL_PATTERNS:
                        matches = re.findall(pattern, body)
                        cred_fields.extend(matches)
                    return {
                        "endpoint_reachable": True,
                        "path":               path,
                        "credential_fields":  cred_fields,
                        "exposed":            len(cred_fields) > 0,
                        "preview":            body[:300],
                    }
            except Exception:
                continue

    return {"endpoint_reachable": False}


# ── Per-target orchestration ──────────────────────────────────────────────────

async def scan_target(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    safe_mode: bool = False,
    extra_creds: Optional[tuple] = None,
) -> Optional[dict]:
    """
    Full scan pipeline for a single target URL.

    1. Fingerprint — confirm vManage and extract version
    2. Unauthenticated API check — misconfiguration indicator
    3. Default credential check — unless --safe
    4. Webshell probe — unless --safe
    5. CVE-2026-20128 DCA check — if authenticated session available
    """
    base_url = normalize_url(url)

    # ── Step 1: Fingerprint ────────────────────────────────────────────────
    detection = await fingerprint_vmanage(client, base_url, semaphore)
    if not detection:
        return None

    ver_tup  = detection["version"]
    ver_text = version_str(ver_tup)
    findings = []

    result: dict = {
        "url":           base_url,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "vmanage":       True,
        "version":       ver_text,
        "server_info":   detection["server_info"],
        "csrf_present":  detection["csrf_present"],
        "cves":          ["CVE-2026-20122", "CVE-2026-20128"],
        "risk":          "INFO",
        "findings":      findings,
    }

    # ── Version notes ──────────────────────────────────────────────────────
    if ver_tup:
        findings.append({
            "type":     "version_detected",
            "severity": "INFO",
            "detail":   f"vManage version {ver_text} detected",
        })
        affected_20128 = is_20128_affected(ver_tup)
        if affected_20128 is True:
            findings.append({
                "type":     "cve_2026_20128_version",
                "severity": "HIGH",
                "cve":      "CVE-2026-20128",
                "detail":   (
                    f"Version {ver_text} is below 20.18 — affected by "
                    f"CVE-2026-20128 DCA credential exposure"
                ),
            })
        elif affected_20128 is False:
            findings.append({
                "type":     "cve_2026_20128_patched",
                "severity": "INFO",
                "cve":      "CVE-2026-20128",
                "detail":   f"Version {ver_text} >= 20.18 — not affected by CVE-2026-20128",
            })
    else:
        findings.append({
            "type":     "version_unknown",
            "severity": "MEDIUM",
            "detail":   "Could not determine vManage version — manual verification required",
        })

    # ── Step 2: Unauthenticated API check ─────────────────────────────────
    unauth_exposed = await check_unauthenticated_api(client, base_url, semaphore)
    for ep in unauth_exposed:
        findings.append({
            "type":      "unauthenticated_api",
            "severity":  "HIGH",
            "detail":    f"Unauthenticated access to {ep['label']} at {ep['path']} ({ep['count']} items)",
            "path":      ep["path"],
            "preview":   ep.get("preview", ""),
        })

    # ── Step 3: Default credentials (skip in safe mode) ───────────────────
    auth_result: dict = {"auth_success": False}
    if not safe_mode:
        auth_result = await check_default_credentials(
            client, base_url, semaphore, extra_creds=extra_creds
        )
        if auth_result.get("auth_success"):
            u, p = auth_result["credential"]
            findings.append({
                "type":       "default_credentials",
                "severity":   "CRITICAL",
                "cve":        "CVE-2026-20122",
                "detail":     (
                    f"Default credentials accepted: {u}:{p} via "
                    f"{auth_result.get('method', '?')} — "
                    f"CVE-2026-20122 file-overwrite exploit chain is reachable"
                ),
                "credential": f"{u}:{p}",
                "method":     auth_result.get("method"),
            })

    # ── Step 4: Webshell detection (skip in safe mode) ────────────────────
    if not safe_mode:
        webshell_hits = await check_webshells(client, base_url, semaphore)
        for hit in webshell_hits:
            sev = "CRITICAL" if hit.get("suspicious") else "HIGH"
            findings.append({
                "type":       "webshell_path",
                "severity":   sev,
                "cve":        "CVE-2026-20122",
                "detail":     (
                    f"Webshell candidate at {hit['path']} "
                    f"(HTTP 200, {hit['content_len']} bytes"
                    + (f", markers: {hit['marker_hits']}" if hit.get("marker_hits") else "")
                    + ")"
                ),
                "path":       hit["path"],
                "suspicious": hit.get("suspicious", False),
                "preview":    hit.get("preview", ""),
            })

    # ── Step 5: CVE-2026-20128 DCA check ──────────────────────────────────
    if auth_result.get("auth_success") or extra_creds:
        dca = await check_dca_exposure(
            client,
            base_url,
            semaphore,
            auth_cookies=auth_result.get("cookies"),
            session_token=auth_result.get("session_token"),
        )
        if dca.get("endpoint_reachable"):
            if dca.get("exposed"):
                findings.append({
                    "type":     "dca_credential_exposure",
                    "severity": "HIGH",
                    "cve":      "CVE-2026-20128",
                    "detail":   (
                        f"DCA config endpoint {dca['path']} exposes credential fields — "
                        f"CVE-2026-20128 lateral movement risk; "
                        f"found: {dca['credential_fields']}"
                    ),
                    "path":     dca["path"],
                })
            else:
                findings.append({
                    "type":     "dca_endpoint_accessible",
                    "severity": "MEDIUM",
                    "cve":      "CVE-2026-20128",
                    "detail":   f"DCA config endpoint {dca['path']} is accessible (no credential fields returned)",
                    "path":     dca["path"],
                })

    result["risk"] = _risk_level(findings)
    return result


# ── Output / display ──────────────────────────────────────────────────────────

def print_result(result: dict) -> None:
    """Pretty-print a single scan result to stdout with ANSI colours."""
    risk   = result.get("risk", "INFO")
    colour = severity_colour(risk)
    url    = result["url"]
    ver    = result.get("version", "unknown")

    print(col(BOLD + CYAN, f"\n{'='*72}"))
    print(col(BOLD, f"  vManage : {url}"))
    print(f"  Version : {ver}")
    print(col(colour, f"  Risk    : {risk}"))
    print(f"  CVEs    : CVE-2026-20122  CVE-2026-20128")

    for finding in result.get("findings", []):
        sev     = finding.get("severity", "INFO")
        fc      = severity_colour(sev)
        detail  = finding.get("detail", "")
        cve_tag = f"[{finding['cve']}] " if "cve" in finding else ""
        print(f"  {col(fc, f'[{sev}]')} {cve_tag}{detail}")

    if risk == "CRITICAL":
        print(col(RED + BOLD, "  >>> ACTIVELY EXPLOITED — PATCH OR ISOLATE IMMEDIATELY <<<"))

    print(col(BOLD + CYAN, f"{'='*72}"))


def print_summary(targets: list, findings: list) -> None:
    """Print scan summary statistics."""
    by_risk = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for r in findings:
        risk = r.get("risk", "INFO")
        by_risk.setdefault(risk, []).append(r)

    print(f"\n{col(BOLD, '='*60)}")
    print(col(BOLD, f"SCAN COMPLETE — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC"))
    print(f"Targets scanned  : {len(targets)}")
    print(f"vManage detected : {len(findings)}")
    print(col(RED,    f"  CRITICAL : {len(by_risk['CRITICAL'])}"))
    print(col(YELLOW, f"  HIGH     : {len(by_risk['HIGH'])}"))
    print(col(DIM_Y,  f"  MEDIUM   : {len(by_risk['MEDIUM'])}"))
    print(col(GREEN,  f"  INFO     : {len(by_risk.get('LOW', [])) + len(by_risk['INFO'])}"))
    print(col(BOLD,   '='*60))

    if by_risk["CRITICAL"]:
        print(col(RED + BOLD, "\nCRITICAL hosts (patch / isolate immediately):"))
        for r in by_risk["CRITICAL"]:
            print(f"  {r['url']}  (v{r['version']})")

    if by_risk["HIGH"]:
        print(col(YELLOW, "\nHIGH risk hosts:"))
        for r in by_risk["HIGH"]:
            print(f"  {r['url']}  (v{r['version']})")


# ── Async main ────────────────────────────────────────────────────────────────

async def main(args: argparse.Namespace) -> list:
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
            print(f"[!] Target list not found: {args.list}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        print("[!] No targets specified. Use --target <url> or --list <file>", file=sys.stderr)
        sys.exit(1)

    # Deduplicate while preserving order
    seen: set = set()
    unique: list = []
    for t in targets:
        nt = normalize_url(t)
        if nt not in seen:
            seen.add(nt)
            unique.append(t)
    targets = unique

    extra_creds = None
    if args.username and args.password:
        extra_creds = (args.username, args.password)

    print(col(BOLD + CYAN, f"[*] Cisco SD-WAN Manager Scanner — CVE-2026-20122 / CVE-2026-20128"))
    print(f"[*] Scanning {len(targets)} target(s)")
    if args.safe:
        print(col(YELLOW, "[*] Safe mode: no credential attempts, no webshell probes"))
    if extra_creds:
        print(f"[*] Using provided credentials: {extra_creds[0]}:{'*' * len(extra_creds[1])}")
    print()

    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)
    findings:  list = []

    ssl_ctx: bool = not args.no_verify

    async with httpx.AsyncClient(verify=ssl_ctx, timeout=REQUEST_TIMEOUT) as client:
        tasks = [
            scan_target(client, t, semaphore, safe_mode=args.safe, extra_creds=extra_creds)
            for t in targets
        ]
        completed = 0

        for coro in asyncio.as_completed(tasks):
            result   = await coro
            completed += 1

            if completed % 10 == 0 or completed == len(targets):
                print(
                    f"    Progress: {completed}/{len(targets)} | "
                    f"vManage found: {len(findings)}",
                    end="\r",
                )

            if result:
                findings.append(result)
                print_result(result)

    print_summary(targets, findings)

    if args.output and findings:
        with open(args.output, "w") as fh:
            json.dump(findings, fh, indent=2, default=str)
        print(f"\n[*] Full results saved to: {args.output}")

    return findings


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Suppress InsecureRequestWarning when --no-verify is used
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        description="Cisco SD-WAN Manager CVE-2026-20122 / CVE-2026-20128 Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan of a single instance
  python cisco_sdwan_scanner.py --target https://vmanage.corp.example

  # Bulk scan from a list, save JSON report
  python cisco_sdwan_scanner.py --list vmanage_hosts.txt --output sdwan_findings.json

  # Safe mode — no credential probes, no webshell checks
  python cisco_sdwan_scanner.py --list hosts.txt --safe

  # Authenticated scan with supplied credentials
  python cisco_sdwan_scanner.py --target https://vmanage.corp.example \\
      --username admin --password Admin1234!

  # Ignore TLS errors (self-signed certs are common in SD-WAN deployments)
  python cisco_sdwan_scanner.py --list hosts.txt --no-verify --output out.json

  # Tune concurrency for large subnets
  python cisco_sdwan_scanner.py --list big_list.txt --concurrency 40 --output out.json
        """,
    )
    parser.add_argument("--target",      metavar="URL",   help="Single target URL or IP")
    parser.add_argument("--list",        metavar="FILE",  help="File containing one URL/IP per line")
    parser.add_argument("--output",      metavar="FILE",  help="Write JSON findings to this file")
    parser.add_argument("--safe",        action="store_true",
                        help="Safe mode — skip credential probes and webshell checks")
    parser.add_argument("--username",    metavar="USER",  help="Username for authenticated checks")
    parser.add_argument("--password",    metavar="PASS",  help="Password for authenticated checks")
    parser.add_argument("--concurrency", type=int, default=SEMAPHORE_LIMIT,
                        help=f"Max concurrent requests (default: {SEMAPHORE_LIMIT})")
    parser.add_argument("--no-verify",   action="store_true",
                        help="Disable TLS certificate verification")
    cli_args = parser.parse_args()

    SEMAPHORE_LIMIT = cli_args.concurrency
    asyncio.run(main(cli_args))
