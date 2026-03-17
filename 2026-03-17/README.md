# Next.js CVE-2025-29927 — Middleware Authentication Bypass Scanner

Scans Next.js applications for the critical middleware authentication bypass
vulnerability **CVE-2025-29927** (CVSS 9.1).

## Vulnerability Summary

Next.js uses an internal HTTP header, `x-middleware-subrequest`, to prevent
infinite loops when middleware calls itself recursively. When this header is
present and its colon-separated value reaches the recursion depth limit,
Next.js skips middleware execution entirely and forwards the request directly
to the application handler.

An unauthenticated attacker can forge this header with the value:

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

This causes the server to bypass **all** middleware logic on any route —
authentication checks, authorization gates, redirects, rate limiting, bot
protection, IP allowlists — without any credentials.

| Attribute       | Value                               |
|-----------------|-------------------------------------|
| CVE             | CVE-2025-29927                      |
| CVSS Score      | 9.1 (Critical)                      |
| Affected        | Next.js < 14.2.25 and < 15.2.3      |
| Fixed versions  | 14.2.25, 15.2.3                     |
| Attack vector   | Network, unauthenticated            |
| Exploitation    | Single HTTP header, trivial         |

## Requirements

```
pip install httpx
```

Python 3.11+ recommended (uses `tuple[...] | None` union type hints).

## Usage

```bash
# Scan a single target
python nextjs_middleware_bypass.py --target https://app.example.com

# Scan a list of targets and save JSON output
python nextjs_middleware_bypass.py --list targets.txt --output findings.json

# Safe mode — fingerprint and version-check only, no active bypass probe
python nextjs_middleware_bypass.py --target https://app.example.com --safe

# High-throughput scan with custom concurrency and self-signed cert support
python nextjs_middleware_bypass.py \
    --list hosts.txt \
    --concurrency 50 \
    --no-verify \
    --output results.json
```

### Arguments

| Flag              | Description                                                  |
|-------------------|--------------------------------------------------------------|
| `--target URL`    | Single URL to scan                                           |
| `--list FILE`     | File containing one URL per line (# lines ignored)          |
| `--output FILE`   | Write full JSON results to this file                         |
| `--safe`          | Detection only — do not send the bypass header               |
| `--concurrency N` | Max concurrent requests (default: 30)                        |
| `--no-verify`     | Disable TLS certificate verification                         |

## How It Works

### 1. Fingerprinting

The scanner identifies Next.js applications by checking:

- `x-powered-by: Next.js` response header
- `x-nextjs-cache`, `x-vercel-cache` headers
- `__NEXT_DATA__`, `_next/static/`, `__NEXT_F` markers in HTML bodies
- Presence of `/_next/static/` path

### 2. Version Extraction

The Next.js version is extracted from:

- `x-powered-by` header value (e.g., `Next.js 14.2.20`)
- `__NEXT_DATA__` JSON blob embedded in HTML
- Build chunk JS files (`/_next/static/chunks/main.js`, etc.)
- Version patterns across response bodies

### 3. Vulnerability Assessment

| Version known?  | Vulnerable?          | Risk     |
|-----------------|----------------------|----------|
| Yes, < fix      | Confirmed            | CRITICAL |
| Yes, >= fix     | Patched              | LOW      |
| Unknown         | Cannot determine     | HIGH     |

### 4. Active Bypass Probe (disabled in `--safe` mode)

For each target, the scanner probes a list of commonly-protected paths
(`/admin`, `/dashboard`, `/api/user`, etc.) with and without the bypass header.
A bypass is flagged when:

- A baseline redirect (3xx) or auth error (401/403) becomes a 200 response
- The `Location` header disappears in the bypass response
- The bypass response body is substantially larger than the baseline

## Output

**Terminal output** is color-coded:

- `CRITICAL` — red, version is below the patched release or bypass confirmed
- `HIGH` — yellow, version could not be determined
- `INFO` / `LOW` — green, patched or informational

**JSON output** (`--output`) includes scan metadata and per-target findings:

```json
{
  "scan_meta": {
    "tool": "nextjs-middleware-bypass-scanner",
    "cve": "CVE-2025-29927",
    "cvss": "9.1 (Critical)",
    "timestamp": "2026-03-17T12:00:00Z",
    "targets": 10,
    "safe_mode": false
  },
  "findings": [
    {
      "url": "https://app.example.com",
      "timestamp": "2026-03-17T12:00:01Z",
      "cve": "CVE-2025-29927",
      "nextjs_detected": true,
      "version": "14.2.20",
      "risk": "CRITICAL",
      "findings": [ ... ],
      "bypass_probe": { ... }
    }
  ]
}
```

## Remediation

Upgrade to:

- **Next.js 14.x** → upgrade to **14.2.25** or later
- **Next.js 15.x** → upgrade to **15.2.3** or later
- **Next.js ≤ 13** → upgrade to a supported branch

If an immediate upgrade is not possible, block the `x-middleware-subrequest`
header at your reverse proxy / WAF / CDN layer before it reaches the Next.js
process.

## References

- [NVD — CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [Next.js Security Advisory (GitHub)](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [Next.js Blog Post](https://nextjs.org/blog/cve-2025-29927)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Next.js 14.2.25 Release](https://github.com/vercel/next.js/releases/tag/v14.2.25)
- [Next.js 15.2.3 Release](https://github.com/vercel/next.js/releases/tag/v15.2.3)

## Disclaimer

This tool is intended for authorized security testing and research only.
Only scan systems you own or have explicit written permission to test.
The bypass probe sends a single additional HTTP request per candidate path —
it does not exploit, modify, or persist anything on the target system.
