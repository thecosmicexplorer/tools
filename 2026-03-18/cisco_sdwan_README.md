# Cisco SD-WAN Manager Scanner — CVE-2026-20122 / CVE-2026-20128

Security scanner for Cisco Catalyst SD-WAN Manager (vManage) targeting two
actively exploited vulnerabilities confirmed by Cisco PSIRT on **March 5, 2026**.
Nation-state group **UAT-8616** has been observed exploiting these issues to
deploy webshells and move laterally across SD-WAN management infrastructure.

---

## Vulnerabilities

### CVE-2026-20122 — Arbitrary File Overwrite (CVSS 5.4)

| Field        | Detail |
|--------------|--------|
| Product      | Cisco Catalyst SD-WAN Manager (vManage) |
| Auth needed  | Yes — read-only API credentials are sufficient |
| Impact       | Write arbitrary files via REST API path-traversal → privilege escalation to `vmanage` OS user |
| In-the-wild  | UAT-8616 used this to write JSP webshells under the Tomcat webapp root |

The vManage REST API fails to sanitise file paths in its upload-handling code.
An attacker with any authenticated API access (even a read-only service account)
can overwrite arbitrary files on the underlying OS.  UAT-8616 exploited this to
plant persistent JSP webshells, achieving persistent remote code execution on
SD-WAN controllers.

### CVE-2026-20128 — DCA Credential Exposure (CVSS 7.5)

| Field        | Detail |
|--------------|--------|
| Product      | Cisco Catalyst SD-WAN Manager < 20.18 |
| Auth needed  | Any local OS user (gained via CVE-2026-20122 or another vector) |
| Impact       | Read the Data Collection Agent (DCA) password from a world-readable config file; use it to authenticate against other vManage nodes |
| Not affected | vManage 20.18+ |

After gaining an OS-level foothold via CVE-2026-20122, the DCA credential file
is world-readable on affected versions.  The recovered password enables direct
authentication to other vManage deployments in the same organisation, making
lateral movement across the SD-WAN management plane trivial.

---

## Requirements

```
Python 3.10+
httpx>=0.27
```

Install dependencies:

```bash
pip install httpx
```

---

## Usage

### Single target

```bash
python cisco_sdwan_scanner.py --target https://vmanage.corp.example
```

### Bulk scan from a host list

```bash
python cisco_sdwan_scanner.py --list vmanage_hosts.txt --output sdwan_findings.json
```

### Safe mode — fingerprint and version check only, no credential attempts or webshell probes

```bash
python cisco_sdwan_scanner.py --list hosts.txt --safe --output safe_scan.json
```

### Authenticated scan (enables CVE-2026-20128 DCA check)

```bash
python cisco_sdwan_scanner.py --target https://vmanage.corp.example \
    --username admin --password Admin1234!
```

### Ignore TLS errors (self-signed certs are common in SD-WAN deployments)

```bash
python cisco_sdwan_scanner.py --list hosts.txt --no-verify --output findings.json
```

### Tune concurrency for large subnet scans

```bash
python cisco_sdwan_scanner.py --list big_list.txt --concurrency 40 --output findings.json
```

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--target URL` | Single target URL or IP |
| `--list FILE` | File with one URL/IP per line |
| `--output FILE` | Write JSON findings to file |
| `--safe` | Skip credential probes and webshell checks |
| `--username USER` | Username for authenticated checks |
| `--password PASS` | Password for authenticated checks |
| `--concurrency N` | Max concurrent requests (default: 20) |
| `--no-verify` | Disable TLS certificate verification |

---

## Detection Capabilities

| Check | Requires Auth | Skipped by `--safe` |
|-------|:---:|:---:|
| vManage fingerprinting (API, login page, headers, index.html) | No | No |
| Version extraction (`/dataservice/client/server`, `/about`) | No | No |
| Unauthenticated API endpoint exposure | No | No |
| Default credential check | No (tests against target) | **Yes** |
| Webshell path probing (UAT-8616 paths + common Tomcat names) | No | **Yes** |
| CVE-2026-20128 DCA config endpoint check | **Yes** | No |

---

## Output

### Console (ANSI colours)

- **CRITICAL** — red: default credentials accepted, confirmed webshell
- **HIGH** — yellow: version-based CVE-2026-20128 exposure, unauthenticated API, suspicious webshell path
- **MEDIUM** — dim yellow: version unknown, DCA endpoint accessible but no credentials returned
- **INFO** — green: patched version detected

### JSON (`--output`)

Each entry in the output array corresponds to one detected vManage instance:

```json
{
  "url": "https://vmanage.corp.example",
  "timestamp": "2026-03-18T12:00:00+00:00",
  "vmanage": true,
  "version": "20.12.1",
  "server_info": {
    "server_version": "20.12.1",
    "tenant_id": "default",
    "config_db_ver": "20.12.1"
  },
  "csrf_present": true,
  "cves": ["CVE-2026-20122", "CVE-2026-20128"],
  "risk": "CRITICAL",
  "findings": [
    {
      "type": "default_credentials",
      "severity": "CRITICAL",
      "cve": "CVE-2026-20122",
      "detail": "Default credentials accepted: admin:Admin1234! via j_security_check",
      "credential": "admin:Admin1234!",
      "method": "j_security_check"
    },
    {
      "type": "cve_2026_20128_version",
      "severity": "HIGH",
      "cve": "CVE-2026-20128",
      "detail": "Version 20.12.1 is below 20.18 — affected by CVE-2026-20128 DCA credential exposure"
    }
  ]
}
```

---

## Operational Notes

- **TLS**: vManage commonly ships with self-signed certificates.  Use `--no-verify` when scanning internal deployments and suppress urllib3 warnings (the scanner does this automatically).
- **Rate limiting**: The default concurrency of 20 is conservative.  Cisco devices may rate-limit or block IPs that send too many requests too quickly.
- **Authentication**: Even read-only credentials are sufficient to trigger CVE-2026-20122.  If you have service-account credentials for a vManage cluster, supply them with `--username`/`--password` to enable the DCA check.
- **False positives (webshells)**: The scanner flags HTTP 200 responses on known webshell paths.  A hit with two or more content markers (exec/Runtime/cmd/etc.) is marked `suspicious: true`.  All hits should be manually verified.
- **False positives (default creds)**: Some deployments front vManage with an SSO proxy that returns 200 + JSESSIONID for any POST.  Verify CRITICAL credential findings manually before acting.

---

## Remediation

1. **Patch immediately**: Apply the Cisco security advisory patch for CVE-2026-20122 and CVE-2026-20128.
2. **Upgrade to 20.18+** to eliminate CVE-2026-20128 (DCA credential exposure).
3. **Change default credentials**: Ensure all vManage instances use strong, unique passwords.
4. **Restrict API access**: Place vManage behind a VPN or firewall; do not expose it directly to the internet.
5. **Rotate DCA credentials**: If any vManage deployment was running a vulnerable version, treat DCA credentials as compromised and rotate them across all nodes.
6. **Hunt for webshells**: Inspect the Tomcat webapp directory (`/opt/cisco/viptela/web/`) for unexpected `.jsp` files, especially on controllers that were reachable from untrusted networks.
7. **Review access logs**: Look for unusual POST requests to `/dataservice/` endpoints with file-path parameters from low-privileged service accounts.

---

## References

- [Cisco Security Advisory — cisco-sa-sdwan-mgr-2026-Q1](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-mgr-2026-Q1)
- [Talos Blog — UAT-8616 SD-WAN Exploitation Campaign](https://blog.talosintelligence.com/uat-8616-sdwan-exploitation-2026/)
- [NVD — CVE-2026-20122](https://nvd.nist.gov/vuln/detail/CVE-2026-20122)
- [NVD — CVE-2026-20128](https://nvd.nist.gov/vuln/detail/CVE-2026-20128)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
