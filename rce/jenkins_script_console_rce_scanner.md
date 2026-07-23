# Jenkins Script Console RCE Scanner (CVE-2017-1000353)

This security scanner identifies and exploits a Remote Code Execution (RCE) vulnerability in improperly secured Jenkins Script Console endpoints. The tool helps detect outdated or misconfigured Jenkins instances that are vulnerable to CVE-2017-1000353.

## CVE Details
- **CVE ID**: CVE-2017-1000353
- **Risk**: Critical (CVSS 9.8)
- **Vulnerable Jenkins versions**: 
  - Jenkins < 2.54 (weekly)
  - Jenkins LTS < 2.46.2
- **Exploit**: Unauthenticated or improperly secured Script Console allows execution of arbitrary Groovy scripts.

## Usage

### Scan a single target
