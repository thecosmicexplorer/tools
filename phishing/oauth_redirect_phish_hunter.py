#!/usr/bin/env python3
"""
oauth_redirect_phish_hunter.py
--------------------------------
Detect and analyze OAuth redirection abuse phishing URLs — the active 2026 campaign
technique where attackers craft malicious OAuth authorization requests through trusted
identity providers (Microsoft Entra ID / Azure AD) to silently redirect victims to
attacker-controlled infrastructure for malware delivery or AitM credential theft.

Reference: Microsoft Security Blog, March 2, 2026
https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/

Usage:
    python3 oauth_redirect_phish_hunter.py url  <url>
    python3 oauth_redirect_phish_hunter.py scan <file_of_urls.txt>
    python3 oauth_redirect_phish_hunter.py email <email_file.eml>
    python3 oauth_redirect_phish_hunter.py decode-state <base64_or_encoded_state>
    python3 oauth_redirect_phish_hunter.py report --input urls.txt --output report.json
"""

import argparse
import base64
import binascii
import json
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------------------------
# Constants — patterns derived from Microsoft's March 2026 research
# ---------------------------------------------------------------------------

# Identity provider OAuth authorization endpoints known to be abused
ABUSED_OAUTH_ENDPOINTS = [
    r"login\.microsoftonline\.com/[^/]+/oauth2/v2\.0/authorize",
    r"login\.microsoftonline\.com/[^/]+/oauth2/authorize",
    r"login\.live\.com/oauth20_authorize\.srf",
    r"accounts\.google\.com/o/oauth2/v2/auth",
    r"accounts\.google\.com/o/oauth2/auth",
    r"github\.com/login/oauth/authorize",
    r"login\.okta\.com/oauth2/v1/authorize",
]

# Parameters the March 2026 campaign used to force silent-error redirects
SILENT_FLOW_ABUSE_PARAMS = {
    "prompt": ["none", "no_session"],          # Forces silent auth, triggers error+redirect
}

# Parameters that should NOT contain PII / email addresses (abused in state param)
PII_BEARING_PARAMS = ["state", "login_hint", "nonce"]

# Suspicious redirect_uri patterns — attacker-registered URIs
SUSPICIOUS_REDIRECT_URI_PATTERNS = [
    r"https?://[^/]*\.ngrok\.io",
    r"https?://[^/]*\.ngrok-free\.app",
    r"https?://[^/]*\.trycloudflare\.com",
    r"https?://[^/]*\.workers\.dev",
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # raw IP address
    r"https?://[^/]*\.onion",
    r"/download/[A-Za-z0-9]+",                            # /download/XXXX pattern from campaign
    r"https?://[^/]*evilproxy",
    r"https?://[^/]*phish",
]

# Known EvilProxy / AitM framework path patterns
AITM_PATH_PATTERNS = [
    r"/download/[A-Za-z0-9_-]{4,}",
    r"/[a-z0-9]{8,}/auth",
    r"/proxy/[a-z0-9]+",
    r"/r/[A-Za-z0-9]{6,}",
]

# Lure themes seen in the 2026 campaign (for email analysis)
LURE_KEYWORDS = [
    "e-signature", "esignature", "docusign", "sign document",
    "social security", "ssa.gov",
    "teams meeting", "microsoft teams",
    "payment required", "invoice attached",
    "verify your identity", "unusual sign-in",
    "your account has been",
    "action required",
]

# Encoding patterns used to obfuscate email address in state parameter
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    description: str
    evidence: str = ""


@dataclass
class AnalysisResult:
    url: str
    is_oauth_url: bool
    risk_score: int             # 0–100
    risk_label: str             # CLEAN / LOW / MEDIUM / HIGH / CRITICAL
    findings: List[Finding] = field(default_factory=list)
    decoded_state: Optional[str] = None
    email_in_state: Optional[str] = None
    parsed_params: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Core analysis logic
# ---------------------------------------------------------------------------

def is_oauth_url(url: str) -> bool:
    for pattern in ABUSED_OAUTH_ENDPOINTS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    # Also catch generic oauth/authorize paths
    parsed = urllib.parse.urlparse(url)
    if re.search(r"/oauth2?/", parsed.path, re.IGNORECASE) and (
        "authorize" in parsed.path.lower() or "auth" in parsed.path.lower()
    ):
        return True
    return False


def try_decode(value: str) -> str:
    """Attempt multiple decoding strategies on a parameter value."""
    # 1. URL decode
    decoded = urllib.parse.unquote_plus(value)
    # 2. Base64 decode (standard and URL-safe)
    for b64_variant in [decoded, decoded.replace("-", "+").replace("_", "/")]:
        try:
            padded = b64_variant + "=" * (-len(b64_variant) % 4)
            b64_decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            if len(b64_decoded) > 3 and b64_decoded.isprintable():
                decoded = b64_decoded
                break
        except (binascii.Error, ValueError):
            pass
    # 3. Hex decode
    stripped = re.sub(r"[^0-9a-fA-F]", "", decoded)
    if len(stripped) >= 8 and len(stripped) % 2 == 0:
        try:
            hex_decoded = bytes.fromhex(stripped).decode("utf-8", errors="replace")
            if EMAIL_RE.search(hex_decoded):
                decoded = hex_decoded
        except ValueError:
            pass
    return decoded


def extract_email_from_value(value: str) -> Optional[str]:
    """Attempt to find an email address within an encoded/decoded value."""
    # Try raw first
    m = EMAIL_RE.search(value)
    if m:
        return m.group(0)
    # Try decoded
    decoded = try_decode(value)
    m = EMAIL_RE.search(decoded)
    if m:
        return m.group(0)
    return None


def analyze_url(url: str) -> AnalysisResult:
    url = url.strip()
    result = AnalysisResult(url=url, is_oauth_url=False, risk_score=0, risk_label="CLEAN")

    if not url:
        return result

    # Parse URL
    try:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    except Exception as e:
        result.findings.append(Finding("LOW", "PARSE_ERROR", f"Could not parse URL: {e}"))
        return result

    result.parsed_params = params
    result.is_oauth_url = is_oauth_url(url)

    score = 0

    # ---- Check 1: Is it even an OAuth URL? ----
    if result.is_oauth_url:
        result.findings.append(Finding(
            "INFO", "OAUTH_URL_DETECTED",
            "URL matches an OAuth authorization endpoint pattern.",
            parsed.netloc + parsed.path
        ))
        score += 10

    # ---- Check 2: Silent-flow abuse via prompt=none ----
    for param, bad_values in SILENT_FLOW_ABUSE_PARAMS.items():
        val = params.get(param, "").lower()
        if val in bad_values:
            result.findings.append(Finding(
                "HIGH", "SILENT_FLOW_ABUSE",
                f"Parameter '{param}={val}' forces silent authentication. "
                "In the 2026 campaign, this triggers an error+redirect to redirect_uri "
                "without user interaction.",
                f"{param}={val}"
            ))
            score += 35

    # ---- Check 3: Suspicious redirect_uri ----
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri:
        decoded_redir = urllib.parse.unquote_plus(redirect_uri)
        for pattern in SUSPICIOUS_REDIRECT_URI_PATTERNS:
            if re.search(pattern, decoded_redir, re.IGNORECASE):
                result.findings.append(Finding(
                    "CRITICAL", "SUSPICIOUS_REDIRECT_URI",
                    f"redirect_uri matches suspicious pattern '{pattern}'. "
                    "Attackers register redirect URIs pointing to infrastructure "
                    "serving malware ZIPs or AitM phishing proxies.",
                    f"redirect_uri={decoded_redir}"
                ))
                score += 40
                break

        # Check for /download/XXXX path specifically (campaign signature)
        for pattern in AITM_PATH_PATTERNS:
            if re.search(pattern, decoded_redir, re.IGNORECASE):
                result.findings.append(Finding(
                    "CRITICAL", "AITM_DOWNLOAD_PATH",
                    f"redirect_uri contains an AitM/malware-delivery path pattern "
                    f"('{pattern}'). The March 2026 campaign used /download/XXXX paths "
                    "to auto-deliver malicious ZIP archives.",
                    f"redirect_uri={decoded_redir}"
                ))
                score += 30

    # ---- Check 4: PII / email address in state or login_hint ----
    for pii_param in PII_BEARING_PARAMS:
        val = params.get(pii_param, "")
        if not val:
            continue
        email = extract_email_from_value(val)
        if email:
            decoded_val = try_decode(val)
            result.email_in_state = email
            result.decoded_state = decoded_val
            result.findings.append(Finding(
                "HIGH", "PII_IN_OAUTH_PARAM",
                f"Parameter '{pii_param}' contains or encodes an email address ('{email}'). "
                "In the 2026 campaign, actors pre-populated victim email addresses "
                "in the state parameter to auto-fill phishing page forms.",
                f"{pii_param} decoded value: {decoded_val[:200]}"
            ))
            score += 30

    # ---- Check 5: State parameter is not a random nonce ----
    state_val = params.get("state", "")
    if state_val and len(state_val) > 8:
        # A legitimate state should look random; structured/readable content is suspicious
        decoded_state = try_decode(state_val)
        result.decoded_state = decoded_state
        # Check for structured data (JSON, delimiters, long readable strings)
        if re.search(r"[{}\[\]\"'=&|;,]", decoded_state) or re.search(r"[a-z]{5,}", decoded_state):
            # Only flag if it wasn't already flagged as PII
            if not result.email_in_state:
                result.findings.append(Finding(
                    "MEDIUM", "STRUCTURED_STATE_PARAM",
                    "The 'state' parameter decodes to structured/readable content rather "
                    "than a random nonce. Legitimate OAuth state values are random tokens; "
                    "structured content may encode victim identity or campaign metadata.",
                    f"decoded state (first 200 chars): {decoded_state[:200]}"
                ))
                score += 15

    # ---- Check 6: Missing or blank client_id / scope (broken OAuth = forced error redirect) ----
    client_id = params.get("client_id", "")
    scope = params.get("scope", "")
    response_type = params.get("response_type", "")
    if result.is_oauth_url:
        if not client_id:
            result.findings.append(Finding(
                "MEDIUM", "MISSING_CLIENT_ID",
                "OAuth URL is missing 'client_id'. Intentionally omitting required parameters "
                "is one technique to force Entra ID into an error-redirect flow.",
                "client_id absent"
            ))
            score += 15
        if not scope and not response_type:
            result.findings.append(Finding(
                "LOW", "MISSING_SCOPE_RESPONSE_TYPE",
                "Both 'scope' and 'response_type' are absent. Malformed requests can "
                "be used to trigger predictable error redirects.",
                "scope and response_type absent"
            ))
            score += 5

    # ---- Check 7: URL not from expected OAuth domain but mimics one ----
    netloc = parsed.netloc.lower()
    legit_domains = ["login.microsoftonline.com", "login.live.com",
                     "accounts.google.com", "github.com", "login.okta.com"]
    looks_like_oauth = any(
        re.search(r"/oauth", parsed.path, re.IGNORECASE) or "authorize" in parsed.path.lower()
        for _ in [1]
    )
    if looks_like_oauth and not any(netloc.endswith(d) for d in legit_domains):
        # Check for homograph / typosquatting
        for legit in legit_domains:
            legit_base = legit.split(".")[0]
            if legit_base in netloc and netloc != legit:
                result.findings.append(Finding(
                    "HIGH", "OAUTH_DOMAIN_SPOOFING",
                    f"URL path looks like an OAuth endpoint but the domain '{netloc}' "
                    f"resembles '{legit}' — possible typosquatting or homograph attack.",
                    f"domain={netloc}, path={parsed.path}"
                ))
                score += 40

    # ---- Compute final risk label ----
    score = min(score, 100)
    result.risk_score = score
    if score == 0:
        result.risk_label = "CLEAN"
    elif score < 20:
        result.risk_label = "LOW"
    elif score < 45:
        result.risk_label = "MEDIUM"
    elif score < 70:
        result.risk_label = "HIGH"
    else:
        result.risk_label = "CRITICAL"

    return result


# ---------------------------------------------------------------------------
# Email (.eml) analysis
# ---------------------------------------------------------------------------

def extract_urls_from_eml(eml_path: str) -> List[str]:
    """Extract all URLs from a raw .eml file (plain-text parsing, no external deps)."""
    urls = []
    try:
        with open(eml_path, "r", errors="replace") as f:
            content = f.read()
    except OSError as e:
        print(f"[ERROR] Cannot read {eml_path}: {e}", file=sys.stderr)
        return urls

    # Decode quoted-printable =XX sequences
    content = re.sub(r"=\r?\n", "", content)
    content = re.sub(r"=([0-9A-Fa-f]{2})",
                     lambda m: chr(int(m.group(1), 16)), content)

    # Extract all URLs
    url_pattern = re.compile(
        r"https?://[^\s\"'<>\]\)\\]+",
        re.IGNORECASE
    )
    urls = list(set(url_pattern.findall(content)))
    return urls


def check_lure_keywords(eml_path: str) -> List[str]:
    """Check email body for social-engineering lure keywords."""
    matched = []
    try:
        with open(eml_path, "r", errors="replace") as f:
            content = f.read().lower()
    except OSError:
        return matched
    for kw in LURE_KEYWORDS:
        if kw.lower() in content:
            matched.append(kw)
    return matched


def analyze_email(eml_path: str) -> Dict[str, Any]:
    print(f"\n[*] Analyzing email: {eml_path}")
    urls = extract_urls_from_eml(eml_path)
    lures = check_lure_keywords(eml_path)
    oauth_results = []
    for url in urls:
        res = analyze_url(url)
        if res.is_oauth_url or res.risk_score > 0:
            oauth_results.append(res.to_dict())

    return {
        "email_file": eml_path,
        "total_urls_found": len(urls),
        "lure_keywords_detected": lures,
        "suspicious_oauth_urls": len(oauth_results),
        "results": oauth_results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[96m",  # cyan
    "INFO":     "\033[97m",  # white
}
RESET = "\033[0m"

RISK_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "CLEAN":    "\033[92m",
}


def colored(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return text


def print_result(res: AnalysisResult, verbose: bool = False) -> None:
    risk_col = RISK_COLOR.get(res.risk_label, "")
    print(f"\n{'='*72}")
    print(f"  URL    : {res.url[:100]}")
    print(f"  OAuth  : {'Yes' if res.is_oauth_url else 'No'}")
    print(f"  Risk   : {colored(res.risk_label, risk_col)}  (score: {res.risk_score}/100)")

    if res.email_in_state:
        print(f"  !! Email in state param: {colored(res.email_in_state, SEVERITY_COLOR['HIGH'])}")

    if res.decoded_state and verbose:
        print(f"  Decoded state: {res.decoded_state[:120]}")

    if res.findings:
        print(f"  Findings ({len(res.findings)}):")
        for f in res.findings:
            col = SEVERITY_COLOR.get(f.severity, "")
            print(f"    [{colored(f.severity, col)}] {f.category}")
            print(f"         {f.description}")
            if f.evidence and verbose:
                print(f"         Evidence: {f.evidence[:120]}")

    if verbose and res.parsed_params:
        print(f"  Parsed params:")
        for k, v in res.parsed_params.items():
            print(f"    {k} = {v[:80]}")
    print(f"{'='*72}")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_url(args: argparse.Namespace) -> None:
    res = analyze_url(args.url)
    print_result(res, verbose=args.verbose)
    if args.json:
        print(json.dumps(res.to_dict(), indent=2))


def cmd_scan(args: argparse.Namespace) -> None:
    try:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {len(urls)} URLs from {args.file}")
    results = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for url in urls:
        res = analyze_url(url)
        results.append(res)
        counts[res.risk_label] = counts.get(res.risk_label, 0) + 1
        if res.risk_score > 0 or args.verbose:
            print_result(res, verbose=args.verbose)

    print(f"\n[SUMMARY] {len(urls)} URLs scanned")
    for label, count in counts.items():
        col = RISK_COLOR.get(label, "")
        if count:
            print(f"  {colored(label, col)}: {count}")

    if args.output:
        out = [r.to_dict() for r in results]
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[*] JSON report written to {args.output}")


def cmd_email(args: argparse.Namespace) -> None:
    result = analyze_email(args.file)
    print(f"\n[SUMMARY] Email analysis: {result['email_file']}")
    print(f"  Total URLs found          : {result['total_urls_found']}")
    print(f"  Suspicious OAuth URLs     : {result['suspicious_oauth_urls']}")
    if result["lure_keywords_detected"]:
        kws = ", ".join(result["lure_keywords_detected"])
        print(f"  Lure keywords detected    : {colored(kws, SEVERITY_COLOR['HIGH'])}")
    else:
        print(f"  Lure keywords detected    : none")

    for r_dict in result["results"]:
        # Re-hydrate for pretty printing
        findings = [Finding(**f) for f in r_dict.pop("findings", [])]
        r_dict.pop("timestamp", None)
        r_dict.pop("parsed_params", None)
        obj = AnalysisResult(findings=findings, **r_dict)
        print_result(obj, verbose=args.verbose)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[*] JSON report written to {args.output}")


def cmd_decode_state(args: argparse.Namespace) -> None:
    value = args.value
    decoded = try_decode(value)
    email = extract_email_from_value(value)
    print(f"\n[*] Input    : {value}")
    print(f"[*] Decoded  : {decoded}")
    if email:
        print(colored(f"[!] Email address found in state: {email}", SEVERITY_COLOR["HIGH"]))
    else:
        print("[*] No email address detected in decoded value.")


def cmd_report(args: argparse.Namespace) -> None:
    """Scan a file of URLs and produce a structured JSON report."""
    try:
        with open(args.input) as f:
            urls = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Generating report for {len(urls)} URLs ...")
    results = [analyze_url(u).to_dict() for u in urls]
    critical = [r for r in results if r["risk_label"] == "CRITICAL"]
    high = [r for r in results if r["risk_label"] == "HIGH"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "oauth_redirect_phish_hunter",
        "version": "1.0.0",
        "threat": "OAuth Redirection Abuse (March 2026 Campaign)",
        "source": "https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/",
        "total_urls": len(urls),
        "summary": {
            "critical": len(critical),
            "high": len(high),
            "medium": len([r for r in results if r["risk_label"] == "MEDIUM"]),
            "low": len([r for r in results if r["risk_label"] == "LOW"]),
            "clean": len([r for r in results if r["risk_label"] == "CLEAN"]),
        },
        "results": results,
    }
    output_path = args.output or "oauth_phish_report.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report written to: {output_path}")
    print(f"[*] CRITICAL: {len(critical)}  HIGH: {len(high)}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="oauth_redirect_phish_hunter",
        description=(
            "Detect and analyze OAuth redirection abuse phishing URLs.\n"
            "Based on the active March 2026 campaign documented by Microsoft Defender.\n"
            "Threat actors abuse OAuth authorization endpoints (Entra ID / Azure AD)\n"
            "to silently redirect victims to malware delivery or AitM phishing pages."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- url subcommand --
    p_url = sub.add_parser("url", help="Analyze a single OAuth URL")
    p_url.add_argument("url", help="The URL to analyze")
    p_url.add_argument("-v", "--verbose", action="store_true", help="Show evidence and decoded params")
    p_url.add_argument("--json", action="store_true", help="Also print full JSON output")
    p_url.set_defaults(func=cmd_url)

    # -- scan subcommand --
    p_scan = sub.add_parser("scan", help="Scan a file containing one URL per line")
    p_scan.add_argument("file", help="Path to file with URLs (one per line)")
    p_scan.add_argument("-v", "--verbose", action="store_true")
    p_scan.add_argument("-o", "--output", help="Write JSON results to this file")
    p_scan.set_defaults(func=cmd_scan)

    # -- email subcommand --
    p_email = sub.add_parser("email", help="Extract and analyze OAuth URLs from a .eml file")
    p_email.add_argument("file", help="Path to .eml file")
    p_email.add_argument("-v", "--verbose", action="store_true")
    p_email.add_argument("-o", "--output", help="Write JSON results to this file")
    p_email.set_defaults(func=cmd_email)

    # -- decode-state subcommand --
    p_ds = sub.add_parser(
        "decode-state",
        help="Decode an OAuth state parameter value and check for embedded email addresses"
    )
    p_ds.add_argument("value", help="Raw or encoded state parameter value")
    p_ds.set_defaults(func=cmd_decode_state)

    # -- report subcommand --
    p_report = sub.add_parser("report", help="Scan URLs and generate a structured JSON report")
    p_report.add_argument("--input", required=True, help="File with URLs (one per line)")
    p_report.add_argument("--output", help="Output JSON file (default: oauth_phish_report.json)")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
