# Jenkins Script Console RCE Scanner

## Overview

This tool scans for Jenkins servers with an exposed Script Console endpoint. Such endpoints can allow unauthenticated or unauthorized users to execute arbitrary Groovy scripts, resulting in remote code execution (RCE). The scanner can perform detection-only scans or attempt controlled exploitation to verify RCE.

## CVE References

This tool addresses common misconfigurations exposing Jenkins Script Console, such as:
- [CVE-2018-1000861](https://nvd.nist.gov/vuln/detail/CVE-2018-1000861)

## Usage

### Basic Scan
Detect a Script Console vulnerability on a single target:
