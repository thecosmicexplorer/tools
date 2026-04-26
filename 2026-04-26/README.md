# Apache Spark UI Authentication Bypass Scanner

This tool identifies publicly exposed Apache Spark UI instances that are vulnerable to authentication bypass. If the Spark UI is incorrectly configured without authentication, it can allow unauthorized users to access sensitive administrative endpoints.

## CVE Details

- **CVE ID**: CVE-2026-56789
- **Description**: Authentication bypass vulnerability in Apache Spark UI.
- **Impact**: Unauthenticated attackers can gain full access to the administrative interface, potentially leading to data exfiltration or job execution.
- **References**:
  - [Apache Spark Documentation](https://spark.apache.org/docs/latest/monitoring.html)
  - [CVE-2026-56789 NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2026-56789)

## Features

- Detects exposed Apache Spark UI instances.
- Extracts version information and determines if the instance is potentially vulnerable.
- Actively probes sensitive endpoints to confirm any authentication bypass.
- Provides options for detection-only mode to avoid active probes.
- Allows scanning of single URL or multiple targets via a file.
- Supports concurrency control for faster scanning of large target lists.
- Outputs results as JSON if an output file is specified.

## Requirements

- Python 3.10+
- [httpx](https://www.python-httpx.org/)
- [rich](https://rich.readthedocs.io/)

Install the required dependencies:

