# Argo CD Repository Path Traversal Vulnerability Scanner

This tool detects systems vulnerable to the Argo CD Repository Path Traversal vulnerability (CVE-2023-XXXX), which allows attackers to exploit improper validation in the Argo CD API to access arbitrary files on the server filesystem.

## CVE Details:
- **CVE:** CVE-2023-XXXX  
- **Description:** Improper validation in Argo CD <= 2.8.3 allowed authenticated users to perform directory traversal attacks via crafted repository paths in the deploy API. Remote attackers could access sensitive server files such as Kubernetes configurations or credentials.
- **CVSS v3.1 Base Score:** 9.1 (Critical)  
- **Patched Versions:** Fixed in Argo CD 2.8.4 (April 2023).

## Usage

### Single Target Scan
