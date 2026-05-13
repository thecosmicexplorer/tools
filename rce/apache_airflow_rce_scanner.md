# Apache Airflow CVE-2026-44578 Scanner

This is a security scanner for detecting and exploiting a remote code execution 
(RCE) vulnerability in Apache Airflow Webserver API. The vulnerability exists 
because of weak or missing authentication configurations in older or misconfigured Airflow setups.

## Vulnerability Details

- **CVE**: CVE-2026-44578
- **Severity**: Critical (CVSS score: 9.8)
- **Description**: Improper authentication in Apache Airflow's web interface may allow
  unauthenticated attackers to execute arbitrary commands via exposed API endpoints.
- **Affected Versions**: Some default configurations of Apache Airflow ≤ 2.4.x.
- **Patched Versions**: Fixed in Airflow ≥ 2.5.0.

## Features

- Detects the presence of Apache Airflow and identifies exposed vulnerable APIs.
- Optionally probes the RCE payload (safe mode to skip probing).
- Prints results with severity levels in ANSI-colored terminal output.
- Supports batch scanning multiple targets.
- Outputs results as JSON.

## Installation

1. Install [Python 3.10+](https://www.python.org/downloads/).
2. Install the required dependency with `pip install httpx`.

## Usage

### Scan a single target
