#!/usr/bin/env python3
"""
oauth_phish_hunter.py — Detect OAuth redirection abuse phishing campaigns.

Targets the active campaign documented by Microsoft (March 2026) where threat
actors abuse OAuth authorization flows and the Entra ID error-redirect
mechanism (error 65001 / interaction_required) to bypass phishing defenses and
deliver malware to government and enterprise targets.

Detects:
  - Emails (.eml / mbox) containing OAuth URLs with prompt=none
  - state parameter values that decode to a victim email address
  - Invalid / attacker-planted OAuth scope parameters
  - Entra ID sign-in log entries with resultType=65001 from unknown app IDs
  - URL lists with suspicious OAuth redirect patterns

Usage:
  python3 oauth_phish_hunter.py emails  --input /path/to/inbox.mbox
  python3 oauth_phish_hunter.py emails  --input /path/to/msg.eml
  python3 oauth_phish_hunter.py urls    --input /path/to/urls.txt
  python3 oauth_phish_hunter.py logs    --input /path/to/signin_logs.json
  python3 oauth_phish_hunter.py logs    --input /path/to/signin_logs.csv
  python3 oauth_phish_hunter.py url     --url "https://login.microsoftonline.com/..."
"""

import argparse
import base64
import binascii
import csv
import email
import json
import mailbox
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
SCORE_PROMPT_NONE = 30          # prompt=none in OAuth URL in email context
SCORE_STATE_IS_EMAIL = 40       # state param decodes to an email address
SCORE_INVALID_SCOPE = 20        # scope contains obviously invalid/garbage value
SCORE_ERROR_65001 = 35          # Entra ID resultType 65001 + unknown app
SCORE_REDIRECT_MISMATCH = 25    # redirect_uri points to non-Microsoft domain
SCORE_PHISH_SUBJECT = 15        # email subject matches common phishing themes

PHISH_SUBJECT_PATTERNS = [
    r"password\s*reset",
    r"storage\s*(full|quota|limit)",
    r"shared?\s*(document|file|folder)",
    r"hr\s*(update|notice|action|policy)",
    r"invoice",
    r"review\s+required",
    r"verify\s+(your\s+)?(account|identity|email)",
    r"unusual\s+(sign.?in|activity|login)",
    r"action\s+required",
    r"confirm\s+your",
    r"suspended?\s+(account|access)",
]

KNOWN_MICROSOFT_DOMAINS = {
    "login.microsoftonline.com",
    "login.microsoft.com",
    "account.microsoft.com",
    "graph.microsoft.com",
    "microsoftonline.com",
    "microsoft.com",
    "live.com",
    "outlook.com",
}

EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# State encodings seen in the wild per Microsoft's March 2026 report
def _try_decode_state(value: str) -> Optional[str]:
    """Return decoded content of a state param value, or None if not decodable."""
    # Already plain text
    if EMAIL_RE.match(value):
        return value
    # URL-decoded first
    try:
        decoded = urllib.parse.unquote_plus(value)
        if EMAIL_RE.match(decoded):
            return decoded
    except Exception:
        pass
    # Base64
    for pad in range(4):
        try:
            b64 = value + "=" * pad
            decoded = base64.b64decode(b64).decode("utf-8", errors="ignore").strip()
            if EMAIL_RE.match(decoded):
                return decoded
        except Exception:
            pass
    # Hex
    try:
        decoded = bytes.fromhex(value).decode("utf-8", errors="ignore").strip()
        if EMAIL_RE.match(decoded):
            return decoded
    except Exception:
        pass
    # Hex URL-encoded (%xx chains)
    try:
        decoded = urllib.parse.unquote(value)
        hex_stripped = re.sub(r"[^0-9a-fA-F]", "", decoded)
        if len(hex_stripped) % 2 == 0:
            decoded2 = bytes.fromhex(hex_stripped).decode("utf-8", errors="ignore").strip()
            if EMAIL_RE.match(decoded2):
                return decoded2
    except Exception:
        pass
    return None


@dataclass
class Finding:
    source: str                     # file path or "cli"
    indicator: str                  # short label
    detail: str                     # human-readable explanation
    score: int
    evidence: str = ""              # raw snippet that triggered the finding
    decoded_email: Optional[str] = None   # victim email recovered from state param


@dataclass
class AnalysisResult:
    findings: list = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def verdict(self) -> str:
        s = self.total_score
        if s >= 80:
            return "HIGH CONFIDENCE — PHISHING"
        if s >= 40:
            return "MEDIUM CONFIDENCE — SUSPICIOUS"
        if s >= 15:
            return "LOW CONFIDENCE — WORTH REVIEWING"
        return "CLEAN / NO INDICATORS"

    def report(self, verbose: bool = False) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append(f"  VERDICT : {self.verdict}")
        lines.append(f"  SCORE   : {self.total_score}")
        lines.append(f"  FINDINGS: {len(self.findings)}")
        lines.append("=" * 70)
        for f in self.findings:
            lines.append(f"\n[+{f.score:>3}]  {f.indicator}")
            lines.append(f"       Source  : {f.source}")
            lines.append(f"       Detail  : {f.detail}")
            if f.decoded_email:
                lines.append(f"       Victim  : {f.decoded_email}")
            if verbose and f.evidence:
                snippet = f.evidence[:300].replace("\n", " ")
                lines.append(f"       Evidence: {snippet}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core URL analyser
# ---------------------------------------------------------------------------

def analyse_oauth_url(url: str, source: str = "cli") -> list:
    """Return a list of Finding objects for a single URL."""
    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return findings

    # Only care about OAuth / OIDC endpoints
    oauth_paths = {
        "/oauth2/authorize", "/oauth2/v2.0/authorize",
        "/common/oauth2/authorize", "/common/oauth2/v2.0/authorize",
        "/organizations/oauth2/v2.0/authorize",
    }
    if not any(parsed.path.endswith(p) or parsed.path.startswith(p) for p in oauth_paths):
        # Looser check — if it has client_id AND response_type it's OAuth-like
        if not ("client_id" in qs and "response_type" in qs):
            return findings

    # 1. prompt=none
    prompt_vals = qs.get("prompt", [])
    if any(v.lower() == "none" for v in prompt_vals):
        findings.append(Finding(
            source=source,
            indicator="prompt=none in OAuth URL",
            detail=(
                "Attackers use prompt=none to attempt silent authentication. "
                "When it fails, Entra ID issues error 65001 and redirects to "
                "the registered redirect_uri — which may be attacker-controlled."
            ),
            score=SCORE_PROMPT_NONE,
            evidence=url,
        ))

    # 2. state param decodes to victim email
    state_vals = qs.get("state", [])
    for sv in state_vals:
        decoded = _try_decode_state(sv)
        if decoded:
            findings.append(Finding(
                source=source,
                indicator="state parameter encodes victim email",
                detail=(
                    f"The OAuth state parameter decodes to an email address. "
                    "Microsoft's March 2026 report identifies this as a high-confidence "
                    "indicator: attackers pre-populate the phishing page with the "
                    "victim's address via the state param."
                ),
                score=SCORE_STATE_IS_EMAIL,
                evidence=f"state={sv}",
                decoded_email=decoded,
            ))
            break

    # 3. redirect_uri points outside Microsoft
    redirect_vals = qs.get("redirect_uri", [])
    for rv in redirect_vals:
        try:
            r_parsed = urllib.parse.urlparse(rv)
            r_host = r_parsed.netloc.lower().lstrip("www.")
            if not any(r_host == d or r_host.endswith("." + d) for d in KNOWN_MICROSOFT_DOMAINS):
                findings.append(Finding(
                    source=source,
                    indicator="redirect_uri points to non-Microsoft domain",
                    detail=(
                        f"redirect_uri resolves to '{r_host}', which is outside "
                        "known Microsoft domains. This is the attacker's malware-serving "
                        "endpoint that receives the browser after the 65001 error redirect."
                    ),
                    score=SCORE_REDIRECT_MISMATCH,
                    evidence=f"redirect_uri={rv}",
                ))
        except Exception:
            pass

    # 4. Scope sanity check — known-valid scopes
    valid_scope_keywords = {
        "openid", "profile", "email", "offline_access",
        "user.read", "mail.read", "calendars.read", "files.read",
        "https://graph.microsoft.com/",
    }
    scope_vals = qs.get("scope", [])
    for sv in scope_vals:
        parts = re.split(r"[\s+]", sv)
        clearly_invalid = [
            p for p in parts
            if p and not any(
                p.lower().startswith(k) or p.lower() == k
                for k in valid_scope_keywords
            )
        ]
        if len(clearly_invalid) > 0 and len(parts) <= 3:
            findings.append(Finding(
                source=source,
                indicator="Unusual / invalid OAuth scope",
                detail=(
                    "The scope parameter contains values that do not match standard "
                    "Microsoft OAuth scopes. Attackers deliberately use invalid scopes "
                    "to trigger the error-redirect flow."
                ),
                score=SCORE_INVALID_SCOPE,
                evidence=f"scope={sv}",
            ))

    return findings


# ---------------------------------------------------------------------------
# Email / mbox scanner
# ---------------------------------------------------------------------------

URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)

def _extract_text_from_message(msg: email.message.Message) -> str:
    """Recursively extract all text/plain and text/html payload from a message."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode("utf-8", errors="replace"))
        except Exception:
            pass
    return "\n".join(parts)


def scan_email_file(path: str) -> AnalysisResult:
    result = AnalysisResult()
    p = Path(path)

    if not p.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return result

    messages = []
    suffix = p.suffix.lower()

    if suffix == ".mbox":
        try:
            mb = mailbox.mbox(str(p))
            messages = list(mb)
        except Exception as e:
            print(f"[ERROR] Could not read mbox: {e}", file=sys.stderr)
            return result
    else:
        # Treat as single .eml
        try:
            with open(str(p), "rb") as fh:
                messages = [email.message_from_binary_file(fh)]
        except Exception as e:
            print(f"[ERROR] Could not read .eml: {e}", file=sys.stderr)
            return result

    for idx, msg in enumerate(messages, 1):
        src_label = f"{path}::msg#{idx}"

        # Subject check
        subject = str(msg.get("subject", ""))
        for pat in PHISH_SUBJECT_PATTERNS:
            if re.search(pat, subject, re.IGNORECASE):
                result.findings.append(Finding(
                    source=src_label,
                    indicator="Phishing-themed subject line",
                    detail=f"Subject matches known phishing theme pattern '{pat}': {subject!r}",
                    score=SCORE_PHISH_SUBJECT,
                    evidence=f"Subject: {subject}",
                ))
                break  # one subject hit per message is enough

        # URL extraction from body
        body = _extract_text_from_message(msg)
        urls = URL_RE.findall(body)
        for url in urls:
            url = url.rstrip(").,;'\"")
            for finding in analyse_oauth_url(url, source=src_label):
                result.findings.append(finding)

        # Also scan raw headers for OAuth URLs (some mailers hide links in headers)
        for header_val in [msg.get("x-original-url", ""), msg.get("list-unsubscribe", "")]:
            for url in URL_RE.findall(header_val):
                for finding in analyse_oauth_url(url, source=f"{src_label}::header"):
                    result.findings.append(finding)

    return result


# ---------------------------------------------------------------------------
# URL list scanner
# ---------------------------------------------------------------------------

def scan_url_file(path: str) -> AnalysisResult:
    result = AnalysisResult()
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return result
    with open(str(p), "r", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            for finding in analyse_oauth_url(url, source=f"{path}:line{lineno}"):
                result.findings.append(finding)
    return result


# ---------------------------------------------------------------------------
# Entra ID sign-in log scanner
# ---------------------------------------------------------------------------

def scan_signin_logs(path: str) -> AnalysisResult:
    """
    Scan Entra ID / Azure AD sign-in logs exported as JSON or CSV.
    Exported from: Azure portal > Microsoft Entra ID > Sign-in logs > Download.
    """
    result = AnalysisResult()
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        return result

    records = []
    suffix = p.suffix.lower()

    if suffix == ".json":
        try:
            with open(str(p), "r", errors="replace") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict) and "value" in data:
                records = data["value"]
        except Exception as e:
            print(f"[ERROR] JSON parse error: {e}", file=sys.stderr)
            return result
    elif suffix == ".csv":
        try:
            with open(str(p), newline="", errors="replace") as fh:
                reader = csv.DictReader(fh)
                records = list(reader)
        except Exception as e:
            print(f"[ERROR] CSV parse error: {e}", file=sys.stderr)
            return result
    else:
        print(f"[ERROR] Unsupported log format (use .json or .csv): {suffix}", file=sys.stderr)
        return result

    # Field name normalisation: Azure exports use camelCase in JSON and
    # "Result type" / "Application" etc. in CSV.
    def _get(rec: dict, *keys) -> str:
        for k in keys:
            if k in rec and rec[k] is not None:
                return str(rec[k])
        return ""

    for idx, rec in enumerate(records, 1):
        src = f"{path}::record#{idx}"

        result_type = _get(rec, "resultType", "Result type", "errorCode", "Error code")
        app_id      = _get(rec, "appId", "App ID", "clientAppUsed", "Client app")
        app_name    = _get(rec, "appDisplayName", "Application", "App display name")
        user_upn    = _get(rec, "userPrincipalName", "User", "Sign-in name")
        resource    = _get(rec, "resourceDisplayName", "Resource", "Resource display name")
        timestamp   = _get(rec, "createdDateTime", "Date (UTC)", "Date")

        # Primary signal: error code 65001 (interaction_required)
        try:
            code = int(result_type)
        except (ValueError, TypeError):
            code = -1

        if code == 65001:
            # Try to judge if the app is "unknown" (short UUID-like appId, no display name)
            is_unknown_app = (
                not app_name
                or app_name.lower() in {"unknown", "n/a", ""}
                or re.fullmatch(r"[0-9a-f\-]{36}", app_id.lower())
            )
            score = SCORE_ERROR_65001 if is_unknown_app else SCORE_ERROR_65001 // 2
            result.findings.append(Finding(
                source=src,
                indicator="Entra ID error 65001 (interaction_required)",
                detail=(
                    f"Sign-in attempt returned error 65001, consistent with the OAuth "
                    "redirection abuse technique. Attacker uses prompt=none; when silent "
                    f"auth fails the browser is redirected to the app's redirect_uri. "
                    f"App: '{app_name}' (ID: {app_id}), User: {user_upn}, Time: {timestamp}"
                ),
                score=score,
                evidence=json.dumps({k: rec[k] for k in list(rec.keys())[:10]}, default=str),
                decoded_email=user_upn if user_upn else None,
            ))

        # Secondary: look for OAuth URLs in any field values
        for v in rec.values():
            if isinstance(v, str) and "oauth2" in v.lower():
                for url in URL_RE.findall(v):
                    for finding in analyse_oauth_url(url, source=src):
                        result.findings.append(finding)

    return result


# ---------------------------------------------------------------------------
# Single URL mode
# ---------------------------------------------------------------------------

def scan_single_url(url: str) -> AnalysisResult:
    result = AnalysisResult()
    for finding in analyse_oauth_url(url, source="cli"):
        result.findings.append(finding)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oauth_phish_hunter",
        description=(
            "Detect OAuth redirection abuse phishing (CVE-adjacent — March 2026 campaign).\n"
            "Scans emails, URL lists, and Entra ID sign-in logs for indicators of the\n"
            "Microsoft-documented OAuth prompt=none / error-65001 attack pattern."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # emails subcommand
    p_emails = sub.add_parser("emails", help="Scan a .eml file or .mbox mailbox")
    p_emails.add_argument("--input", "-i", required=True, help="Path to .eml or .mbox file")
    p_emails.add_argument("--verbose", "-v", action="store_true", help="Show raw evidence snippets")
    p_emails.add_argument("--json", "-j", action="store_true", dest="out_json", help="Output JSON")

    # urls subcommand
    p_urls = sub.add_parser("urls", help="Scan a plain-text file of URLs (one per line)")
    p_urls.add_argument("--input", "-i", required=True, help="Path to URL list file")
    p_urls.add_argument("--verbose", "-v", action="store_true")
    p_urls.add_argument("--json", "-j", action="store_true", dest="out_json")

    # logs subcommand
    p_logs = sub.add_parser("logs", help="Scan Entra ID sign-in log export (.json or .csv)")
    p_logs.add_argument("--input", "-i", required=True, help="Path to sign-in log file")
    p_logs.add_argument("--verbose", "-v", action="store_true")
    p_logs.add_argument("--json", "-j", action="store_true", dest="out_json")

    # url subcommand (single URL)
    p_url = sub.add_parser("url", help="Analyse a single OAuth URL")
    p_url.add_argument("--url", "-u", required=True, help="The URL to analyse")
    p_url.add_argument("--verbose", "-v", action="store_true")
    p_url.add_argument("--json", "-j", action="store_true", dest="out_json")

    return parser


def _emit(result: AnalysisResult, out_json: bool, verbose: bool) -> None:
    if out_json:
        data = {
            "verdict": result.verdict,
            "total_score": result.total_score,
            "findings": [
                {
                    "indicator": f.indicator,
                    "source": f.source,
                    "detail": f.detail,
                    "score": f.score,
                    "decoded_email": f.decoded_email,
                    "evidence": f.evidence if verbose else "",
                }
                for f in result.findings
            ],
        }
        print(json.dumps(data, indent=2))
    else:
        print(result.report(verbose=verbose))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.mode == "emails":
        result = scan_email_file(args.input)
    elif args.mode == "urls":
        result = scan_url_file(args.input)
    elif args.mode == "logs":
        result = scan_signin_logs(args.input)
    elif args.mode == "url":
        result = scan_single_url(args.url)
    else:
        parser.print_help()
        sys.exit(1)

    _emit(result, out_json=args.out_json, verbose=args.verbose)

    # Exit code: 0 = clean, 1 = findings present
    sys.exit(0 if not result.findings else 1)


if __name__ == "__main__":
    main()
