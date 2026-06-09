# WordPress Project Management Plugin RCE Scanner (CVE-2026-33124)

## Overview
This tool scans WordPress websites for remote code execution (RCE) vulnerabilities impacting the Project Management Plugin (CVE-2026-33124). The vulnerability allows an attacker to execute arbitrary PHP code via crafted payloads submitted to AJAX endpoints.

The tool performs both detection and exploitation attempts (optional) to validate the presence of the vulnerability. Use it responsibly within authorized engagements such as bug bounty programs or enterprise security assessments.

---

## CVE Details
**ID:** CVE-2026-33124  
**Affected Software:** WordPress Project Management Plugin (versions 2.3.0 and below)  
**Impact:** Remote Code Execution (RCE)  
**CVSS:** 9.8 (Critical)  
**Description:** This high-severity vulnerability is caused by improper validation of input to the `/wp-admin/admin-ajax.php` endpoint, where attackers can craft payloads to execute arbitrary PHP code. The issue is resolved in version 2.3.1.  

**References:**
- [CVE-2026-33124](https://nvd.nist.gov/vuln/detail/CVE-2026-33124)  
- [WordPress Plugin Info](https://wordpress.org/plugins/project-management/)  

---

## Usage

### Example Commands
- Scan a single target:
    