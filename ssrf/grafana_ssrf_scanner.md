# Grafana SSRF Scanner  

## Overview  
The Grafana SSRF Scanner is a Python-based tool that detects and, when permitted, actively probes Server-Side Request Forgery (SSRF) vulnerabilities in vulnerable versions of Grafana.  

### Known Vulnerabilities Addressed  
This tool targets vulnerabilities in Grafana pertaining to SSRF attacks, such as:  
- **CVE-2021-43798**: Path Traversal vulnerability in Grafana <8.3.0  
- **CVE-2019-15043**: SSRF vulnerability on snapshot endpoints in Grafana <6.3.6  
Additional variations may also lead to potential SSRF and related issues.  

## Features  
- Detects if a target is running Grafana (based on fingerprints and known paths).  
- Identifies the version of Grafana and checks against known vulnerable versions.  
- Actively tests for SSRF vulnerabilities unless the `--safe` flag is used.  
- Exports JSON-formatted scan results.  

### Example usage  
1. **Scan a single target:**  
   