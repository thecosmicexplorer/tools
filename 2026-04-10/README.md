# Apache Spark JobServer CVE-2026-52201 RCE Scanner

This tool scans for instances of [Apache Spark JobServer](https://github.com/spark-jobserver/spark-jobserver) that are vulnerable to a Remote Code Execution (RCE) flaw tracked as **CVE-2026-52201**.

## CVE Details

- **CVE:** CVE-2026-52201
- **CVSS Score:** 9.8 (Critical)
- **Description:** Unauthenticated code execution via the `/jobs` endpoint allows attackers to execute arbitrary OS commands by submitting malicious Python scripts due to unsafe input handling.
- **Affected versions:** Apache Spark JobServer <= 0.11.1
- **Fixed in version:** 0.12.0

## Features

- Detects running instances of Apache Spark JobServer
- Extracts software version and determines if it is vulnerable
- Optionally probes for RCE by submitting harmless payloads
- Outputs findings in JSON format for easy integration into pipelines

## Requirements

- Python 3.10+
- `httpx` and `colorama` libraries installed (`pip install httpx colorama`)

## Usage

### Scan a single target

To scan a single Apache Spark JobServer instance for CVE-2026-52201:

