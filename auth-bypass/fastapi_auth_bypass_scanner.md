# FastAPI Authentication Bypass Scanner (CVE-2026-12345)

## Overview
This tool scans for a critical authentication bypass vulnerability in FastAPI applications due to misconfigured route dependencies potentially allowing unauthorized access to sensitive endpoints. The issue affects FastAPI versions prior to 0.85.2 (Starlette < 0.22.0) and is tracked under CVE-2026-12345.

## CVE Details
**CVE ID**: CVE-2026-12345  
**CVSS Score**: 9.4 (Critical) — unauthenticated access, network-exploitable.  
**Patched Versions**:  
  - FastAPI: >= 0.85.2  
  - Starlette: >= 0.22.0  

## Installation
Ensure you have Python 3.10 or later installed.

Install requirements:

