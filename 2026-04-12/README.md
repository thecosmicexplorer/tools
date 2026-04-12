# Jenkins Plugin RCE Scanner

This tool scans Jenkins instances for plugins that may be vulnerable to remote code execution (RCE) through unsafe Groovy script execution. The tool fingerprints Jenkins installations, identifies their versions, and, when not in `--safe` mode, attempts to trigger RCE using a non-destructive probe.

## CVE Details

Several Jenkins plugins suffer from remote code execution vulnerabilities due to insufficient input sanitization when executing Groovy scripts. Exploiting these vulnerabilities could result in a complete compromise of the Jenkins server.

### Key Features
- Detects whether a target is a Jenkins instance.
- Extracts Jenkins version information from various sources.
- Option to actively probe for RCE vulnerabilities or passively detect Jenkins without probing (`--safe` mode).
- Supports scanning a single target or bulk scanning a list of targets.
- Outputs results to the console and optionally to a JSON file.

### Usage

