# Apache HTTP Server Log4Shell Scanner (CVE-2021-44228)

This Python tool detects and optionally exploits Apache servers running vulnerable versions of the Log4j library, specifically those affected by the critical Log4Shell vulnerability (CVE-2021-44228). The vulnerability has a CVSS score of 10.0 and allows remote attackers to execute arbitrary code through maliciously crafted log messages that exploit JNDI lookups.

## CVE Details

- **CVE ID**: CVE-2021-44228
- **CVSS Base Score**: 10.0 (Critical)
- **Affected Software**:
  - Apache Log4j 2.x <= 2.14.1
- [Official Log4j Advisory](https://logging.apache.org/log4j/2.x/security.html)
- [NVD Details](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

## Features

- Detects vulnerable instances of Apache HTTP servers using fingerprinting techniques.
- Actively probes servers for Log4Shell vulnerability using JNDI payloads (optional).
- Supports bulk scanning with adjustable concurrency.
- Provides detailed results in JSON format (optional).

## Requirements

- Python 3.10 or newer
- `httpx`, install with `pip install httpx`

## Usage

