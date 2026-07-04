# GitLab CI/CD Runner Misconfigurations Scanner

## Overview

This tool scans for misconfigured GitLab CI/CD runners that allow unauthorized remote code execution (RCE) by checking for:
1. Exposed and misconfigured shared runners.
2. Risky `script` usage in pipeline definitions.
3. Specific CVE vulnerabilities in GitLab CI/CD configurations.

### Some Relevant CVEs:
- **CVE-2021-22205:** Improper validation of user-provided image filepaths led to arbitrary code execution.
- **Multi-CVE Context:** The tool also includes generic checks for pervasive runner-related configuration flaws.

## Usage

- **Scan a single target (active probing, full scan):**
  