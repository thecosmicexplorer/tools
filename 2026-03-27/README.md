# Apache Struts2 CVE-2018-11776 Scanner

This tool scans for Apache Struts2 instances vulnerable to CVE-2018-11776, a critical remote code execution (RCE) vulnerability caused by improper namespace handling in the Struts2 REST plugin.

## CVE Details

- **CVE**: [CVE-2018-11776](https://nvd.nist.gov/vuln/detail/CVE-2018-11776)
- **CVSS Score**: 9.8 (Critical)
- **Description**: The vulnerability allows unauthenticated remote attackers to execute arbitrary commands on vulnerable Struts2 installations. The issue lies in the REST plugin's incorrect handling of namespaces and OGNL expressions.
- **Affected Versions**: Struts2 versions prior to 2.3.35 and 2.5.17
- **Fixed Versions**: 2.3.35+ and 2.5.17+

## Usage

### Scan a Single Target
