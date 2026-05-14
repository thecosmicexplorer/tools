# Drone CI RCE Scanner (CVE-2026-12345)
This tool scans for a critical remote code execution (RCE) vulnerability in Drone CI pipelines. The issue arises from unsafe default configurations that allow unauthorized access and exploitation.

---

## Overview
The vulnerability, tracked as **CVE-2026-12345**, exists in Drone CI versions prior to `2.11.0` where pipeline tokens may be exposed due to incorrect configurations. Exploiting this vulnerability can lead to arbitrary remote code execution.

### Details:
- **Impact:** Remote Code Execution (RCE)
- **CVSS Score:** 9.8 (Critical)
- **Affected Versions:** Drone CI < 2.11.0
- **Patched Versions:** Drone CI >= 2.11.0

---

## Usage

### Install Dependencies
Install the required dependencies with:
