# tools

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://github.com/thecosmicexplorer/tools)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Automated-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/thecosmicexplorer/tools/actions)
[![Claude AI](https://img.shields.io/badge/Claude-AI%20Generated-D97757?style=flat-square)](https://www.anthropic.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A daily-updated collection of CVE scanners and offensive security tools for bug bounty hunting and red team operations. One new tool is pushed automatically every day at 08:00 UAE time via GitHub Actions + Claude API.

---

## Tools

| Date | Tool | CVE / Topic | Description |
|------|------|-------------|-------------|
| 2026-03-19 | [vite_path_traversal_scanner.py](2026-03-19/vite_path_traversal_scanner.py) | CVE-2025-30208 (CVSS 9.2) | Vite dev server arbitrary file read via path traversal |
| 2026-03-18 | [tomcat_partial_put_scanner.py](2026-03-18/tomcat_partial_put_scanner.py) | CVE-2025-24813 (CVSS 9.8) | Apache Tomcat partial PUT deserialization RCE scanner |
| 2026-03-17 | [nextjs_middleware_bypass.py](2026-03-17/nextjs_middleware_bypass.py) | CVE-2025-29927 (CVSS 9.1) | Next.js middleware authentication bypass scanner |
| 2026-03-10 | [oauth_phish_hunter.py](2026-03-10/oauth_phish_hunter.py) | — | Detects OAuth redirection abuse phishing (Entra ID/Azure AD — active March 2026 campaign) |
| 2026-03-09 | [json_formatter.py](2026-03-09/json_formatter.py) | — | JSON formatter and validator utility |
| — | [n8n_rce_scanner.py](n8n_rce_scanner/n8n_rce_scanner.py) | CVE-2025-68613 (CVSS 9.9) | n8n expression injection RCE scanner |
| — | [oauth_redirect_phish_hunter.py](oauth_redirect_phish_hunter/oauth_redirect_phish_hunter.py) | — | Extended OAuth redirect phishing campaign detector |

---

## How Tools Are Generated

Each day at 08:00 UAE time a GitHub Actions workflow runs `scripts/generate_tool.py`. That script:

1. Calls the Claude API with the list of all existing tools in the repo (to avoid duplicates)
2. Asks Claude to identify a recent high-severity CVE or security research topic and write a Python scanner for it
3. Writes the tool to a dated folder (e.g. `2026-03-18/`)
4. Updates this README's tool log automatically
5. Commits and pushes — the result appears here within minutes

The tools are written to be standalone: they use `httpx` for async HTTP, include rate limiting, support target lists via stdin or `-f`, and print structured output. Each one includes CVE details and CVSS score in the module docstring.

The workflow is in [`.github/workflows/daily-tool.yml`](.github/workflows/daily-tool.yml) and the generator is in [`scripts/generate_tool.py`](scripts/generate_tool.py).

---

## Usage

Most tools follow the same pattern:

```bash
# Single target
python tool_name.py -t https://target.com

# Multiple targets from file
python tool_name.py -f targets.txt

# With threading
python tool_name.py -f targets.txt --threads 20

# Verbose output
python tool_name.py -t https://target.com -v
```

Install common dependencies:

```bash
pip install httpx asyncio argparse
```

---

## CVE Scanner Pattern

The scanners in this repo work by:
1. Sending a crafted request that triggers the vulnerable code path
2. Comparing the response against a known-vulnerable fingerprint (status code, header, body pattern)
3. Confirming with a second request where possible to reduce false positives
4. Reporting findings with target URL, evidence, and CVE reference

All scanners are passive-first where possible — they identify vulnerable software before attempting any proof-of-concept.

---

## Requesting a Tool

Open an issue with:
- CVE number (or description of the vulnerability class)
- Target software and version range
- Any public references (advisory, PoC, writeup)

The tool will be added to the daily generation queue.

---

## Disclaimer

These tools are for use against systems you own or have explicit written authorisation to test. Using them against systems without permission is illegal. All CVE scanners are detection-only by default.

---

## License

MIT — see [LICENSE](LICENSE)
