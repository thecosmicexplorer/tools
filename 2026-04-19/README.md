# Apache Cassandra CVE-2022-46781 Unauthenticated Read Access Scanner

This tool scans for Apache Cassandra database instances that are vulnerable to CVE-2022-46781, 
a high-impact flaw in which unauthenticated users can perform data read operations and potentially access sensitive information.

## CVE Details

- **CVE:** CVE-2022-46781
- **Vulnerability:** Unauthenticated Remote Data Read Access
- **Versions Affected:** Apache Cassandra <= 3.0.26, 3.11.12, 4.0.6
- **Fixed Version:** 3.0.27, 3.11.13, 4.0.7
- **CVSS Score:** 9.1 (Critical)
- **Attack Vector:** Network
- **Exploit:** Lack of authentication on specific HTTP endpoints can lead to unauthorized access to sensitive database information.
  
## Usage Examples

### Scan a single target
