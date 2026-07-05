# GitLab CI/CD YAML Secrets Exposure Scanner

This tool scans GitLab CI/CD YAML configuration files for potential sensitive
information exposure, such as hardcoded API tokens, credentials, or sensitive
environment variables due to misconfigured or public-facing GitLab repositories.

## CVE Information

While this tool addresses a common vulnerability class (secrets leakage), there
is no single CVE for all such occurrences. Various specific CVEs may apply
based on affected vendors and their implementations.

## Features

- Detects public or accessible GitLab CI/CD project YAML configurations.
- Identifies potential sensitive secret exposures in `variables` or `script` sections.
- Allows detection-only mode for safer scans.
- Supports scanning both individual GitLab repositories and bulk scans from lists.
- Outputs results in JSON format.

## Prerequisites

- Python 3.10 or higher

Required PyPI modules:

- `httpx`
- `asyncio`

To install required dependencies, run:
